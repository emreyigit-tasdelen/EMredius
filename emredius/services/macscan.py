# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""MAC Tarama: cihaz -> port -> MAC -> üretici/IP/kullanıcı -> PoE tek tabloda. MAC/port verisi Ekipman servisinden (Q-BRIDGE/BRIDGE),
bu modül ek olarak PoE (POWER-ETHERNET-MIB, Cisco cpeExt) ve ARP (ipNetToMedia/ipNetToPhysical) toplar; LLDP komşusu topo_links'ten,
RADIUS oturumu radacct'tan gelir. Tablolar NMS veritabanında, her satırda tenant_id. Salt okunur ağ erişimi; PoE yoksa sessizce atlanır."""
import asyncio
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import equipment, inventory, topology
from ..core import get_nms_db, oui
from ..core.tenant import all_tenant_ids, resolve_tenant

log = logging.getLogger(__name__)

STALE_DAYS = 7
_schema_ok = set()
_running = threading.Event()
_last = {"at": "", "result": ""}

SCHEMA = """
CREATE TABLE IF NOT EXISTS ms_poe (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, device_ip TEXT NOT NULL,
  grp INTEGER NOT NULL DEFAULT 1, pport INTEGER NOT NULL DEFAULT 0, if_index INTEGER NOT NULL DEFAULT 0, port TEXT DEFAULT '',
  admin TEXT DEFAULT '', detection TEXT DEFAULT '', power_class TEXT DEFAULT '', power_mw INTEGER DEFAULT 0,
  last_seen TEXT DEFAULT '', UNIQUE(tenant_id, device_ip, grp, pport));
CREATE TABLE IF NOT EXISTS ms_poe_main (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, device_ip TEXT NOT NULL,
  grp INTEGER NOT NULL DEFAULT 1, budget_w INTEGER DEFAULT 0, used_w INTEGER DEFAULT 0, oper TEXT DEFAULT '',
  last_seen TEXT DEFAULT '', UNIQUE(tenant_id, device_ip, grp));
CREATE TABLE IF NOT EXISTS ms_arp (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, device_ip TEXT NOT NULL,
  ip TEXT NOT NULL, mac TEXT NOT NULL, if_index INTEGER DEFAULT 0, last_seen TEXT DEFAULT '',
  UNIQUE(tenant_id, device_ip, ip, mac));
CREATE INDEX IF NOT EXISTS ms_arp_mac ON ms_arp(tenant_id, mac);
"""

OID_POE_PORT = "1.3.6.1.2.1.105.1.1.1"      # .3 admin(1 açık,2 kapalı) .6 detection .10 class
OID_POE_MAIN = "1.3.6.1.2.1.105.1.3.1.1"    # .2 güç bütçesi W .3 durum .4 tüketim W
OID_CPE_PORT = "1.3.6.1.4.1.9.9.402.1.2.1"  # Cisco cpeExtPsePortEntry: .7 tüketim mW (varsa)
OID_ARP = "1.3.6.1.2.1.4.22.1.2"            # ipNetToMediaPhysAddress: ifIndex.a.b.c.d
OID_ARP6 = "1.3.6.1.2.1.4.35.1.4"           # ipNetToPhysicalPhysAddress: ifIndex.1.4.a.b.c.d

DETECT = {1: "disabled", 2: "searching", 3: "delivering", 4: "fault", 5: "test", 6: "otherFault"}
MAIN_OPER = {1: "on", 2: "off", 3: "faulty"}
POE_CLASS = {1: "0", 2: "1", 3: "2", 4: "3", 5: "4"}
PHONE_RE = re.compile(r"yealink|polycom|grandstream|snom|fanvil|avaya|mitel|panasonic|cisco.*phone|ip.?phone|\bspa\d", re.I)
AP_RE = re.compile(r"ubiquiti|ruckus|aruba|meraki|tp-?link.*(eap|omada)|cambium|engenius", re.I)
CAM_RE = re.compile(r"hikvision|dahua|axis comm|vivotek|uniview", re.I)


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _db():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        conn.commit()
        equipment._db().close()  # eq_* tabloları da hazır olsun
        _schema_ok.add(key)
    return conn


def _int(v, default=0):
    return equipment._int(v, default)


def _split(vbs, base):
    """[(oid, value)] -> {suffix: value}"""
    d = {}
    for oid, val in vbs:
        s = topology._suffix(oid, base)
        if s is not None:
            d[s] = val
    return d


def guess_kind(vendor="", lldp_name="", poe_class=""):
    """Üretici adı / LLDP komşu adından uç cihaz türü tahmini (en iyi çaba)."""
    s = f"{vendor} {lldp_name}"
    if PHONE_RE.search(s):
        return "IP Telefon"
    if CAM_RE.search(s):
        return "Kamera"
    if AP_RE.search(s):
        return "Access Point"
    return ""


def parse_poe(t, ports):
    """t: {'port':{col:{'grp.port':val}}, 'main':{col:{grp:val}}, 'cpe':{'ifidx':mW}}, ports: eq_ports satırları.
    -> (poe_rows, main_rows). PoE tablosu boşsa ([], [])."""
    t = t if isinstance(t, dict) else {}
    ports = [p for p in (ports or []) if isinstance(p, dict)]
    pt = {c: v for c, v in (t.get("port") or {}).items() if isinstance(v, dict)}
    mt = {c: v for c, v in (t.get("main") or {}).items() if isinstance(v, dict)}
    cpe = t.get("cpe") if isinstance(t.get("cpe"), dict) else {}
    rows, mains, used_if = [], [], set()
    names = {p["if_index"]: p.get("name") or "" for p in ports}
    phys = sorted((p for p in ports if p.get("if_index") and p.get("if_type") in (6, 62, 69, 117, 0) and
                   not re.match(r"(vl|lo|po|tu|nu|null|mgmt)", p.get("name") or "", re.I)), key=lambda p: p["if_index"])
    by_name = {p["name"]: p["if_index"] for p in phys if p.get("name")}
    keys = set(pt.get(3, {})) | set(pt.get(6, {})) | set(pt.get(10, {}))
    groups = {k.split(".")[0] for k in keys}
    for key in sorted(keys, key=lambda k: [_int(x) for x in k.split(".")]):
        g, _, p = key.partition(".")
        grp, pp = _int(g, 1), _int(p)
        ifi = 0
        for pat in (rf"(?:^|\D){grp}/\d+/{pp}$", rf"(?:^|\D){grp}/{pp}$"):
            hit = [n for n in by_name if re.search(pat, n)]
            if len(hit) == 1:
                ifi = by_name[hit[0]]
                break
        if not ifi and len(groups) == 1 and 0 < pp <= len(phys):
            ifi = phys[pp - 1]["if_index"]
        if ifi in used_if:  # iki PoE satırı aynı ifIndex'e düşerse belirsiz eşleme yerine boş bırak
            ifi = 0
        if ifi:
            used_if.add(ifi)
        admin = {1: "on", 2: "off"}.get(_int(pt.get(3, {}).get(key)), "")
        # Cisco CISCO-POWER-ETHERNET-EXT-MIB: önce grp.port, yoksa ifIndex dizini; standart MIB'de tüketim yok
        mw = _int(cpe.get(key), 0) or (_int(cpe.get(str(ifi)), 0) if ifi else 0)
        mw = mw if 0 <= mw <= 200000 else 0
        rows.append({"grp": grp, "pport": pp, "if_index": ifi, "port": names.get(ifi, ""), "admin": admin,
                     "detection": DETECT.get(_int(pt.get(6, {}).get(key)), ""),
                     "power_class": POE_CLASS.get(_int(pt.get(10, {}).get(key)), ""), "power_mw": mw})
    for g in sorted(set(mt.get(2, {})) | set(mt.get(4, {})) | set(mt.get(3, {})), key=lambda x: _int(x)):
        mains.append({"grp": _int(g, 1), "budget_w": _int(mt.get(2, {}).get(g)), "used_w": _int(mt.get(4, {}).get(g)),
                      "oper": MAIN_OPER.get(_int(mt.get(3, {}).get(g)), "")})
    return rows, mains


def parse_arp(t):
    """t: {'arp':{'ifidx.a.b.c.d': macbytes}, 'arp6':{'ifidx.1.4.a.b.c.d': macbytes}} -> [{ip, mac, if_index}]"""
    out, seen = [], set()
    items = [(k.split("."), v, 1) for k, v in t.get("arp", {}).items()]
    items += [(k.split("."), v, 3) for k, v in t.get("arp6", {}).items()]
    for parts, val, skip in items:
        if len(parts) != 4 + skip:
            continue
        octets = parts[skip:]
        if skip == 3 and parts[1:3] != ["1", "4"]:
            continue
        try:
            ip = ".".join(str(int(o)) for o in octets)
            if any(not 0 <= int(o) <= 255 for o in octets):
                continue
        except ValueError:
            continue
        mac = equipment._mac_bytes(val)
        if not mac or mac == "00:00:00:00:00:00" or (ip, mac) in seen:
            continue
        seen.add((ip, mac))
        out.append({"ip": ip, "mac": mac, "if_index": _int(parts[0])})
    return out


async def _walk_all(ip, community):
    from nms.snmp.engine import SnmpClient
    c = SnmpClient()

    async def walk(root, to=40):
        try:
            vbs = await asyncio.wait_for(c.walk(target=ip, root_oid=root, community=community, version="v2c",
                                                timeout=2, retries=1), to)
            return [(vb.oid, vb.value) for vb in vbs]
        except Exception as e:  # noqa: BLE001
            log.debug("macscan walk %s %s: %s", ip, root, e)
            return []

    def cols(vbs, base):
        out = {}
        for k, v in _split(vbs, base).items():
            col, _, idx = k.partition(".")
            if col.isdigit() and idx:
                out.setdefault(int(col), {})[idx] = v
        return out

    port = cols(await walk(OID_POE_PORT), OID_POE_PORT)
    main = cols(await walk(OID_POE_MAIN), OID_POE_MAIN)
    cpe = {}
    if port:  # Cisco tüketim değeri yalnızca PoE'li cihazda denenir; dizin olduğu gibi tutulur (grp.port veya ifIndex)
        cpe = dict(cols(await walk(OID_CPE_PORT), OID_CPE_PORT).get(7, {}))
    arp = _split(await walk(OID_ARP), OID_ARP)
    arp6 = {} if arp else _split(await walk(OID_ARP6), OID_ARP6)
    return {"port": port, "main": main, "cpe": cpe, "arp": arp, "arp6": arp6}


def poll_device(ip, community, ports):
    try:
        t = asyncio.run(_walk_all(ip, community))
        poe, main = parse_poe(t, ports)
        return poe, main, parse_arp(t)
    except Exception as e:  # noqa: BLE001
        log.debug("macscan %s: %s", ip, e)
        return [], [], []


def save_device(conn, ip, poe, main, arp, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    now = _now()
    for r in poe:
        conn.execute(
            "INSERT INTO ms_poe (tenant_id,device_ip,grp,pport,if_index,port,admin,detection,power_class,power_mw,last_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,device_ip,grp,pport) DO UPDATE SET if_index=excluded.if_index,"
            "port=excluded.port,admin=excluded.admin,detection=excluded.detection,power_class=excluded.power_class,"
            "power_mw=excluded.power_mw,last_seen=excluded.last_seen",
            (tenant_id, ip, r["grp"], r["pport"], r["if_index"], r["port"], r["admin"], r["detection"], r["power_class"],
             r["power_mw"], now))
    for r in main:
        conn.execute(
            "INSERT INTO ms_poe_main (tenant_id,device_ip,grp,budget_w,used_w,oper,last_seen) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(tenant_id,device_ip,grp) DO UPDATE SET budget_w=excluded.budget_w,used_w=excluded.used_w,"
            "oper=excluded.oper,last_seen=excluded.last_seen", (tenant_id, ip, r["grp"], r["budget_w"], r["used_w"], r["oper"], now))
    for r in arp:
        conn.execute(
            "INSERT INTO ms_arp (tenant_id,device_ip,ip,mac,if_index,last_seen) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(tenant_id,device_ip,ip,mac) DO UPDATE SET if_index=excluded.if_index,last_seen=excluded.last_seen",
            (tenant_id, ip, r["ip"], r["mac"], r["if_index"], now))


def scan(tenant_id=None, with_equipment=True):
    tenant_id = resolve_tenant(tenant_id)
    if _running.is_set():
        return {"error": "MAC taraması zaten çalışıyor."}
    _running.set()
    try:
        if with_equipment:
            equipment.discover(tenant_id)  # port/MAC tablosu (çalışıyorsa hata döner, mevcut veri kullanılır)
        devs = [d for d in inventory.list_devices(tenant_id, status="ONLINE") if d["snmp_ok"] and d["snmp_community"]]
        ports = {d["ip"]: equipment.list_ports(tenant_id, d["ip"]) for d in devs}
        with ThreadPoolExecutor(6) as ex:
            res = list(ex.map(lambda d: (d["ip"], poll_device(d["ip"], d["snmp_community"], ports[d["ip"]])), devs))
        conn = _db()
        try:
            npoe = narp = 0
            for ip, (poe, main, arp) in res:
                save_device(conn, ip, poe, main, arp, tenant_id)
                npoe += len(poe)
                narp += len(arp)
            cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - STALE_DAYS * 86400))
            for tb in ("ms_poe", "ms_poe_main", "ms_arp"):
                conn.execute(f"DELETE FROM {tb} WHERE tenant_id=? AND last_seen<?", (tenant_id, cutoff))
            conn.commit()
        finally:
            conn.close()
        _last.update(at=_now(), result=f"{len(devs)} cihaz, {npoe} PoE port, {narp} ARP")
        return {"devices": len(devs), "poe_ports": npoe, "arp": narp}
    finally:
        _running.clear()


def scan_async(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    if _running.is_set():
        return False
    threading.Thread(target=scan, args=(tenant_id,), daemon=True, name="macscan").start()
    return True


def start_scheduler(interval_s=1800):
    def loop():
        while True:
            time.sleep(interval_s)
            try:
                for t in all_tenant_ids():
                    scan(t, with_equipment=False)  # port/MAC'i Ekipman zamanlayıcısı yeniler
            except Exception as e:  # noqa: BLE001
                log.warning("macscan scheduler: %s", e)
    threading.Thread(target=loop, daemon=True, name="macscan-scheduler").start()


def _rows(conn, sql, args):
    return [dict(r) for r in conn.execute(sql, args)]


def list_rows(tenant_id=None, device_ip="", q="", vlan="", access_only=False, poe_only=False, limit=2000):
    """Tek tablo: cihaz, port, MAC, üretici, IP (ARP/envanter/RADIUS), kullanıcı, LLDP komşusu, PoE."""
    tenant_id = resolve_tenant(tenant_id)
    macs = equipment.list_macs(tenant_id, device_ip=device_ip, q=q, vlan=vlan, limit=50000, enrich=True)
    conn = _db()
    try:
        arp = {}
        for r in conn.execute("SELECT mac, ip FROM ms_arp WHERE tenant_id=? ORDER BY last_seen", (tenant_id,)):
            arp[r[0]] = r[1]
        poe = {(r["device_ip"], r["if_index"]): r for r in _rows(
            conn, "SELECT * FROM ms_poe WHERE tenant_id=? AND if_index>0", (tenant_id,))}
        ports = {(r["device_ip"], r["if_index"]): r for r in _rows(
            conn, "SELECT device_ip, if_index, oper_status, speed_mbps, alias FROM eq_ports WHERE tenant_id=?", (tenant_id,))}
        nb = {}
        if equipment._has_topo(conn):
            for r in conn.execute("SELECT local_ip, local_port, remote_name, remote_port, remote_ip FROM topo_links WHERE tenant_id=?",
                                  (tenant_id,)):
                nb[(r[0], r[1])] = r
    finally:
        conn.close()
    out = []
    for m in macs:
        n = nb.get((m["device_ip"], m["port"]))
        m["uplink"] = m.get("uplink") or bool(n)
        if access_only and m["uplink"]:
            continue
        pe = poe.get((m["device_ip"], m["if_index"]))
        if poe_only and not (pe and pe["detection"] == "delivering"):
            continue
        po = ports.get((m["device_ip"], m["if_index"]), {})
        m["ip"] = arp.get(m["mac"]) or m.get("inv_ip") or m.get("radius_ip") or ""
        m["neighbor"] = f"{n[2]} {n[3]}".strip() if n else ""
        m["kind"] = guess_kind(m.get("vendor", ""), n[2] if n else "")
        m["port_state"], m["speed_mbps"], m["alias"] = po.get("oper_status", ""), po.get("speed_mbps", 0), po.get("alias", "")
        m["poe_admin"] = pe["admin"] if pe else ""
        m["poe_state"] = pe["detection"] if pe else ""
        m["poe_class"] = pe["power_class"] if pe else ""
        m["poe_w"] = round(pe["power_mw"] / 1000, 1) if pe and pe["power_mw"] else ""
        out.append(m)
        if len(out) >= max(1, min(int(limit), 50000)):
            break
    return out


def list_poe(tenant_id=None, device_ip=""):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        sql, args = "SELECT * FROM ms_poe_main WHERE tenant_id=?", [tenant_id]
        if device_ip:
            sql += " AND device_ip=?"
            args.append(device_ip)
        return _rows(conn, sql + " ORDER BY device_ip, grp", args)
    finally:
        conn.close()


def overview(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        g = lambda sql: conn.execute(sql, (tenant_id,)).fetchone()[0] or 0  # noqa: E731
        return {"macs": g("SELECT COUNT(*) FROM eq_macs WHERE tenant_id=?"),
                "arp": g("SELECT COUNT(*) FROM ms_arp WHERE tenant_id=?"),
                "poe_ports": g("SELECT COUNT(*) FROM ms_poe WHERE tenant_id=?"),
                "poe_on": g("SELECT COUNT(*) FROM ms_poe WHERE tenant_id=? AND detection='delivering'"),
                "poe_budget_w": g("SELECT SUM(budget_w) FROM ms_poe_main WHERE tenant_id=?"),
                "poe_used_w": g("SELECT SUM(used_w) FROM ms_poe_main WHERE tenant_id=?"),
                "running": _running.is_set(), "last": dict(_last)}
    finally:
        conn.close()


COLS = ["device_ip", "port", "vlan", "mac", "vendor", "kind", "ip", "radius_user", "neighbor", "port_state", "speed_mbps",
        "poe_state", "poe_class", "poe_w", "last_seen"]


def to_csv(rows):
    return equipment._csv(rows, COLS)
