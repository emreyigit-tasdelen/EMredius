# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Aktif Cihazlar: IP aralıkları + keşif (ICMP/ARP -> SNMP -> SSH banner) ve cihaz envanteri.
Tablolar NMS veritabanında (SQLite); her satırda tenant_id (çok kiracılı yapı). Salt okunur ağ erişimi."""
import asyncio
import csv
import io
import ipaddress
import logging
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import ipscan
from ..core import get_nms_db
from ..core.tenant import resolve_tenant

log = logging.getLogger(__name__)

DEFAULT_TENANT = 1
SSH_TIMEOUT_S = 1.5
PROBE_WORKERS = 32
_schema_ok = set()
_run_lock = threading.Lock()
_running = {}  # range_id -> True

SCHEMA = """
CREATE TABLE IF NOT EXISTS inv_ranges (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL DEFAULT '',
  cidr TEXT NOT NULL, communities TEXT NOT NULL DEFAULT 'public', interval_min INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1, last_run TEXT DEFAULT '', last_result TEXT DEFAULT '',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(tenant_id, cidr));
CREATE TABLE IF NOT EXISTS inv_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, range_id INTEGER,
  ip TEXT NOT NULL, mac TEXT DEFAULT '', hostname TEXT DEFAULT '', mac_vendor TEXT DEFAULT '',
  vendor TEXT DEFAULT '', model TEXT DEFAULT '', os_version TEXT DEFAULT '', sys_name TEXT DEFAULT '',
  sys_descr TEXT DEFAULT '', sys_object_id TEXT DEFAULT '', device_type TEXT DEFAULT 'Bilinmiyor',
  snmp_ok INTEGER DEFAULT 0, ssh_ok INTEGER DEFAULT 0, ssh_banner TEXT DEFAULT '', snmp_community TEXT DEFAULT '',
  status TEXT DEFAULT 'ONLINE', first_seen TEXT DEFAULT '', last_seen TEXT DEFAULT '', UNIQUE(tenant_id, ip));
"""


def _db():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(snmp_devices)")}
        if cols and "tenant_id" not in cols:  # NMS tablosu varsa kiracı sütunu ekle
            conn.execute("ALTER TABLE snmp_devices ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1")
        conn.commit()
        _schema_ok.add(key)
    return conn


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ---------- ranges ----------
def add_range(cidr, name="", communities="public", interval_min=0, tenant_id=None):
    """None = eklendi, aksi halde hata metni."""
    tenant_id = resolve_tenant(tenant_id)
    net, err = ipscan.parse_target(cidr)
    if err:
        return err
    comm = ",".join(c.strip() for c in (communities or "public").split(",") if c.strip())[:200] or "public"
    if not re.fullmatch(r"[\w.,@!#%^*+=:-]+", comm):
        return "Geçersiz community."
    try:
        interval = max(0, min(int(interval_min or 0), 10080))
    except (TypeError, ValueError):
        interval = 0
    conn = _db()
    try:
        cur = conn.execute("INSERT OR IGNORE INTO inv_ranges (tenant_id,name,cidr,communities,interval_min) VALUES (?,?,?,?,?)",
                           (tenant_id, (name or "")[:64], str(net), comm, interval))
        conn.commit()
        return None if cur.rowcount else "Bu aralık zaten kayıtlı."
    finally:
        conn.close()


def delete_range(range_id, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        cur = conn.execute("DELETE FROM inv_ranges WHERE id=? AND tenant_id=?", (range_id, tenant_id))
        conn.commit()
        return bool(cur.rowcount)
    finally:
        conn.close()


def list_ranges(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        rows = [dict(r) for r in conn.execute("SELECT * FROM inv_ranges WHERE tenant_id=? ORDER BY id", (tenant_id,))]
    finally:
        conn.close()
    for r in rows:
        r["running"] = r["id"] in _running
    return rows


# ---------- probing ----------
SSH_HINTS = [(re.compile(r"ROSSSH", re.I), "MikroTik"), (re.compile(r"Cisco", re.I), "Cisco"),
             (re.compile(r"HUAWEI|VRP", re.I), "Huawei"), (re.compile(r"Juniper|JUNOS", re.I), "Juniper"),
             (re.compile(r"Comware|HPE|Aruba", re.I), "HP / Aruba"), (re.compile(r"FortiSSH|Fortinet", re.I), "Fortinet"),
             (re.compile(r"Ruijie", re.I), "Ruijie"), (re.compile(r"OpenSSH.*(Ubuntu|Debian|el\d)", re.I), "Linux/Unix")]


def ssh_banner(ip, port=22, timeout=SSH_TIMEOUT_S):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(255)
        text = data.decode("latin-1", "replace").strip().splitlines()[0][:120]
        return text if text.startswith("SSH-") else ""
    except Exception:  # noqa: BLE001
        return ""


def ssh_vendor(banner):
    for rx, vendor in SSH_HINTS:
        if rx.search(banner or ""):
            return vendor
    return ""


_MODEL_RX = [re.compile(p, re.I) for p in (
    r"\b(CCR\w+|CRS\w+|RB\w+|hEX\w*|CHR)\b", r"\b(C\d{4}\w*|WS-C\w+|N\dK-\w+|ISR\w+|ASR\w+)\b",
    r"\b(S\d{4}\w*-\w+|CE\d{4}\w*|AR\d{4}\w*|USG\w+)\b", r"\b((?:EX|QFX|MX|SRX|ACX)\d{2,4}\w*)\b",
    r"\b(FortiGate-?\w+|FG\w+)\b")]
_VER_RX = re.compile(r"(?:Version|ver\.?|RouterOS|JUNOS|Release)\s*[:\s]?\s*v?(\d[\w.()-]*)", re.I)


def parse_model_version(sys_descr):
    """sysDescr'den model ve yazılım sürümü tahmini (en iyi çaba)."""
    text = sys_descr or ""
    model = ""
    for rx in _MODEL_RX:
        m = rx.search(text)
        if m:
            model = m.group(1)
            break
    ver = _VER_RX.search(text)
    return model, (ver.group(1).rstrip(".,") if ver else "")


def classify(vendor, sys_descr, snmp_ok, ssh_ok, ssh_vendor_name=""):
    d = (sys_descr or "").lower()
    if re.search(r"ip phone|voip|yealink|polycom|grandstream|\bsnom\b|fanvil|\bspa\d{3}|\bcp-\d{4}|sip-t\d|telefon|\bphone\b", d):
        return "IP Telefon"
    if re.search(r"fortigate|firewall|\bsrx|\busg|\basa\b", d):
        return "Firewall"
    if re.search(r"switch|catalyst|\bws-c|\bcrs\d|\bex\d{4}|\bs\d{4}", d):
        return "Switch"
    if re.search(r"router|\bccr|\bisr|\basr|\bmx\d|\bar\d{4}|routeros", d):
        return "Router"
    if re.search(r"access point|wlan|\bap\d", d):
        return "Access Point"
    if re.search(r"linux|ubuntu|debian|windows|freebsd", d):
        return "Sunucu"
    if vendor and vendor != "Generic":
        return "Ağ Cihazı"
    if ssh_vendor_name == "Linux/Unix":
        return "Sunucu"
    return "Ağ Cihazı" if (snmp_ok or ssh_ok) else "Bilinmiyor"


def _snmp_probe(ip, communities):
    """nms/snmp motorunu yeniden kullanır; DiscoveredDevice veya None."""
    try:
        from nms.snmp import discovery as nd
        from nms.snmp.engine import SnmpClient
        cfg = nd.DiscoveryScanConfig(targets=ip, v2c_communities=communities, walk_interfaces=False, persist_db=False,
                                     timeout=1.0, retries=1, allow_loopback=True)
        return asyncio.run(nd.discover_single_device(ip, cfg, SnmpClient()))
    except Exception as e:  # noqa: BLE001
        log.debug("snmp %s: %s", ip, e)
        return None


def probe_host(ip, communities, mac="", hostname=""):
    """Tek host için tam tanıma: SNMP + SSH banner + MAC üreticisi."""
    info = {"ip": ip, "mac": mac, "hostname": hostname, "snmp_ok": 0, "ssh_ok": 0, "vendor": "", "model": "",
            "os_version": "", "sys_name": "", "sys_descr": "", "sys_object_id": "", "snmp_community": "",
            "ssh_banner": "", "mac_vendor": ""}
    try:
        from ..core.validators import lookup_mac_vendor
        info["mac_vendor"] = (lookup_mac_vendor(mac) or "") if mac else ""
    except Exception:  # noqa: BLE001
        pass
    dev = _snmp_probe(ip, communities)
    if dev:
        info.update(snmp_ok=1, vendor=dev.vendor, sys_name=dev.sys_name, sys_descr=(dev.sys_descr or "")[:1000],
                    sys_object_id=dev.sys_object_id, snmp_community=dev.community)
        info["model"], info["os_version"] = parse_model_version(dev.sys_descr)
    banner = ssh_banner(ip)
    sv = ""
    if banner:
        info["ssh_ok"], info["ssh_banner"] = 1, banner
        sv = ssh_vendor(banner)
        if not info["vendor"] or info["vendor"] == "Generic":
            info["vendor"] = sv
        if not info["os_version"]:
            m = re.search(r"SSH-[\d.]+-(\S+)", banner)
            info["os_version"] = m.group(1)[:60] if m else ""
    if not info["vendor"]:
        info["vendor"] = info["mac_vendor"] or ""
    info["device_type"] = classify(info["vendor"], info["sys_descr"], info["snmp_ok"], info["ssh_ok"], sv)
    return info


_COLS = ("mac", "hostname", "mac_vendor", "vendor", "model", "os_version", "sys_name", "sys_descr",
         "sys_object_id", "device_type", "snmp_ok", "ssh_ok", "ssh_banner", "snmp_community")


def save_device(conn, info, range_id=None, tenant_id=None):
    """Yeni bilgi boş değilse eskinin üstüne yazar (boş tarama sonucu önceki tanımayı silmez)."""
    tenant_id = resolve_tenant(tenant_id)
    now = _now()
    is_new = conn.execute("SELECT 1 FROM inv_devices WHERE tenant_id=? AND ip=?", (tenant_id, info["ip"])).fetchone() is None
    conn.execute(
        f"INSERT INTO inv_devices (tenant_id,range_id,ip,{','.join(_COLS)},status,first_seen,last_seen) "
        f"VALUES (?,?,?,{','.join('?' * len(_COLS))},'ONLINE',?,?) "
        "ON CONFLICT(tenant_id,ip) DO UPDATE SET range_id=excluded.range_id, status='ONLINE', last_seen=excluded.last_seen, "
        + ", ".join(f"{c}=CASE WHEN excluded.{c} IN ('',0) THEN inv_devices.{c} ELSE excluded.{c} END" for c in _COLS),
        (tenant_id, range_id, info["ip"], *[info.get(c, "") for c in _COLS], now, now))
    if is_new:
        try:
            from . import notifications
            notifications.publish("inventory", "Yeni cihaz bulundu",
                                  f"{info['ip']} {info.get('hostname') or info.get('sys_name') or ''}".strip(),
                                  "/inventory", ntype="new_device", severity="warning",
                                  dedupe_key=f"inv:{tenant_id}:{info['ip']}", tenant_id=tenant_id)
        except Exception:  # noqa: BLE001
            pass


def scan_range(range_id, tenant_id=None, history_path=""):
    """Aralığı tarar (ping/ARP + tanıma), envantere yazar; yanıt vermeyen eski kayıtlar OFFLINE olur."""
    tenant_id = resolve_tenant(tenant_id)
    with _run_lock:
        if range_id in _running:
            return {"error": "Bu aralık zaten taranıyor."}
        _running[range_id] = True
    try:
        conn = _db()
        try:
            r = conn.execute("SELECT * FROM inv_ranges WHERE id=? AND tenant_id=?", (range_id, tenant_id)).fetchone()
        finally:
            conn.close()
        if not r:
            return {"error": "Aralık bulunamadı."}
        net, err = ipscan.parse_target(r["cidr"])
        if err:
            return {"error": err}
        comms = [c for c in r["communities"].split(",") if c]
        started = time.time()
        job_id = ipscan.start_scan(net, user="__inventory__", resolve_names=True, max_concurrent=64,
                                   history_path=history_path)
        ipscan.wait(job_id, timeout=3600)
        alive = (ipscan.get_job(job_id, "__inventory__", True) or {}).get("alive", [])
        with ThreadPoolExecutor(PROBE_WORKERS) as ex:
            infos = list(ex.map(lambda h: probe_host(h["ip"], comms, h.get("mac", ""), h.get("hostname", "")), alive))
        conn = _db()
        try:
            for info in infos:
                save_device(conn, info, range_id, tenant_id)
            seen = {i["ip"] for i in infos}
            for row in conn.execute("SELECT ip FROM inv_devices WHERE tenant_id=? AND range_id=?", (tenant_id, range_id)).fetchall():
                if row["ip"] not in seen:
                    conn.execute("UPDATE inv_devices SET status='OFFLINE' WHERE tenant_id=? AND ip=?", (tenant_id, row["ip"]))
            summary = (f"{len(infos)} cihaz, {sum(i['snmp_ok'] for i in infos)} SNMP, "
                       f"{sum(i['ssh_ok'] for i in infos)} SSH, {round(time.time() - started)} sn")
            conn.execute("UPDATE inv_ranges SET last_run=?, last_result=? WHERE id=?", (_now(), summary, range_id))
            conn.commit()
        finally:
            conn.close()
        return {"found": len(infos), "summary": summary}
    except ipscan.ScanError as e:
        return {"error": str(e)}
    finally:
        with _run_lock:
            _running.pop(range_id, None)


def scan_range_async(range_id, tenant_id=None, history_path=""):
    tenant_id = resolve_tenant(tenant_id)
    if range_id in _running:
        return False
    threading.Thread(target=scan_range, args=(range_id, tenant_id, history_path), daemon=True,
                     name=f"inv-{range_id}").start()
    return True


def due_ranges(now=None):
    """Zamanlanmış taraması gelen aralıkların (id, tenant_id) listesi."""
    now = now or time.time()
    out = []
    conn = _db()
    try:
        for r in conn.execute("SELECT id,tenant_id,interval_min,last_run FROM inv_ranges WHERE enabled=1 AND interval_min>0"):
            try:
                last = time.mktime(time.strptime(r["last_run"], "%Y-%m-%d %H:%M:%S")) if r["last_run"] else 0
            except ValueError:
                last = 0
            if now - last >= r["interval_min"] * 60 and r["id"] not in _running:
                out.append((r["id"], r["tenant_id"]))
    finally:
        conn.close()
    return out


def start_scheduler(history_path=""):
    def loop():
        while True:
            time.sleep(60)
            try:
                for rid, tid in due_ranges():
                    scan_range_async(rid, tid, history_path)
            except Exception as e:  # noqa: BLE001
                log.warning("inventory scheduler: %s", e)
    threading.Thread(target=loop, daemon=True, name="inventory-scheduler").start()


# ---------- devices ----------
def _ipkey(ip):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, 0)


def list_devices(tenant_id=None, q="", vendor="", dtype="", status="", limit=5000):
    tenant_id = resolve_tenant(tenant_id)
    sql, args = "SELECT * FROM inv_devices WHERE tenant_id=?", [tenant_id]
    if q:
        sql += " AND (ip LIKE ? OR mac LIKE ? OR hostname LIKE ? OR sys_name LIKE ? OR model LIKE ? OR vendor LIKE ?)"
        args += [f"%{q}%"] * 6
    for col, val in (("vendor", vendor), ("device_type", dtype), ("status", status)):
        if val:
            sql += f" AND {col}=?"
            args.append(val)
    sql += " LIMIT ?"
    args.append(max(1, min(int(limit), 20000)))
    conn = _db()
    try:
        rows = [dict(r) for r in conn.execute(sql, args)]
    finally:
        conn.close()
    rows.sort(key=lambda d: (d["status"] != "ONLINE", _ipkey(d["ip"])))
    return rows


def device_filters(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        return {c: [r[0] for r in conn.execute(
            f"SELECT DISTINCT {c} FROM inv_devices WHERE tenant_id=? AND {c}!='' ORDER BY 1", (tenant_id,))]
            for c in ("vendor", "device_type")}
    finally:
        conn.close()


CSV_COLS = ["ip", "hostname", "mac", "mac_vendor", "vendor", "model", "os_version", "device_type", "snmp_ok", "ssh_ok",
            "status", "first_seen", "last_seen"]


def devices_csv(devices):
    """CSV; formül enjeksiyonuna karşı =,+,-,@ ile başlayan hücreler kaçışlanır."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLS)
    for d in devices:
        w.writerow([("'" + str(d[c]) if str(d[c])[:1] in ("=", "+", "-", "@") else d[c]) for c in CSV_COLS])
    return buf.getvalue()


def overview(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    devs = list_devices(tenant_id)
    return {"total": len(devs), "online": sum(d["status"] == "ONLINE" for d in devs),
            "snmp": sum(d["snmp_ok"] for d in devs), "ssh": sum(d["ssh_ok"] for d in devs)}
