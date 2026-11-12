# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Ağ Topolojisi: LLDP (IEEE 802.1AB) ve CDP komşuluklarını SNMP ile toplar, envanterle eşleyip grafiğe çevirir.
Tablo topo_links NMS veritabanında, her satırda tenant_id. Salt okunur ağ erişimi."""
import asyncio
import csv
import io
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import inventory
from ..core import get_nms_db
from ..core.tenant import all_tenant_ids, resolve_tenant

log = logging.getLogger(__name__)

DEFAULT_TENANT = inventory.DEFAULT_TENANT
STALE_DAYS = 7
_schema_ok = set()
_running = threading.Event()
_last = {"at": "", "result": ""}

SCHEMA = """
CREATE TABLE IF NOT EXISTS topo_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, local_ip TEXT NOT NULL,
  local_port TEXT NOT NULL DEFAULT '', remote_name TEXT DEFAULT '', remote_port TEXT DEFAULT '',
  remote_ip TEXT DEFAULT '', remote_mac TEXT DEFAULT '', protocol TEXT DEFAULT 'LLDP',
  first_seen TEXT DEFAULT '', last_seen TEXT DEFAULT '',
  UNIQUE(tenant_id, local_ip, local_port, remote_name, remote_port, protocol));
CREATE TABLE IF NOT EXISTS topo_type_override (
  tenant_id INTEGER NOT NULL DEFAULT 1, node_key TEXT NOT NULL, device_type TEXT NOT NULL,
  updated_by TEXT DEFAULT '', updated_at TEXT DEFAULT '', PRIMARY KEY (tenant_id, node_key));
"""
DEVICE_TYPES = ("Router", "Switch", "IP Telefon", "Firewall", "Access Point", "Sunucu", "Ağ Cihazı", "Bilinmiyor")

OID_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IFDESCR = "1.3.6.1.2.1.2.2.1.2"
OID_LLDP_LOC_DESC = "1.0.8802.1.1.2.1.3.7.1.4"   # lldpLocPortDesc
OID_LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1.3"   # lldpLocPortId
OID_LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"          # .5 chassisId .7 portId .8 portDesc .9 sysName
OID_LLDP_REM_MAN = "1.0.8802.1.1.2.1.4.2.1.3"    # lldpRemManAddrIfSubtype; dizin sonu = adres
OID_CDP = "1.3.6.1.4.1.9.9.23.1.2.1.1"           # .4 address .6 deviceId .7 devicePort


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _db():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        conn.commit()
        _schema_ok.add(key)
    return conn


def _text(v):
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("utf-8", "replace").strip("\x00 ")[:120]
    return str(v if v is not None else "").strip()[:120]


def _mac(v):
    if isinstance(v, (bytes, bytearray)) and len(v) == 6:
        return ":".join(f"{b:02x}" for b in v)
    t = _text(v)
    return t.lower() if re.fullmatch(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", t) else ""


def _ip(v):
    if isinstance(v, (bytes, bytearray)) and len(v) == 4:
        return ".".join(str(b) for b in v)
    t = _text(v)
    return t if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", t) else ""


def _suffix(oid, base):
    o = oid.lstrip(".")
    return o[len(base) + 1:] if o.startswith(base + ".") else None


def parse_neighbors(tables):
    """tables: {'ifname':{idx:name}, 'lldp_loc':{portnum:name}, 'lldp':{col:{idx:val}}, 'lldp_man':{idx:ip}, 'cdp':{col:{idx:val}}}
    -> [{local_port, remote_name, remote_port, remote_ip, remote_mac, protocol}]"""
    out = []
    lldp = tables.get("lldp", {})
    keys = set()
    for col in (5, 7, 8, 9):
        keys |= set((lldp.get(col) or {}).keys())
    for idx in sorted(keys):
        parts = idx.split(".")  # timeMark.localPortNum.remIndex
        lport = parts[1] if len(parts) >= 3 else ""
        port = tables.get("lldp_loc", {}).get(lport) or tables.get("ifname", {}).get(lport) or f"port{lport}"
        rport = _text((lldp.get(8) or {}).get(idx)) or _text((lldp.get(7) or {}).get(idx))
        rname = _text((lldp.get(9) or {}).get(idx))
        mac = _mac((lldp.get(5) or {}).get(idx))
        if not (rname or mac or rport):
            continue
        out.append({"local_port": port, "remote_name": rname or mac, "remote_port": rport,
                    "remote_ip": tables.get("lldp_man", {}).get(".".join(parts[:3]), ""), "remote_mac": mac,
                    "protocol": "LLDP"})
    cdp = tables.get("cdp", {})
    for idx in sorted((cdp.get(6) or {}).keys()):
        ifidx = idx.split(".")[0]
        name = _text(cdp[6][idx])
        if not name:
            continue
        short = name.split(".")[0] if re.search(r"[A-Za-z]", name) else name
        out.append({"local_port": tables.get("ifname", {}).get(ifidx) or f"if{ifidx}", "remote_name": short,
                    "remote_port": _text((cdp.get(7) or {}).get(idx)), "remote_ip": _ip((cdp.get(4) or {}).get(idx)),
                    "remote_mac": "", "protocol": "CDP"})
    return out


async def _walk_all(ip, community):
    from nms.snmp.engine import SnmpClient
    c = SnmpClient()

    async def walk(root):
        try:
            return await asyncio.wait_for(c.walk(target=ip, root_oid=root, community=community, version="v2c",
                                                 timeout=1.5, retries=1), 20)
        except Exception as e:  # noqa: BLE001
            log.debug("walk %s %s: %s", ip, root, e)
            return []

    def tab(vbs, base):
        d = {}
        for vb in vbs:
            s = _suffix(vb.oid, base)
            if s is not None:
                d[s] = vb.value
        return d

    def cols(vbs, base):
        d = {}
        for vb in vbs:
            s = _suffix(vb.oid, base)
            if s:
                col, _, idx = s.partition(".")
                if col.isdigit():
                    d.setdefault(int(col), {})[idx] = vb.value
        return d

    ifn = tab(await walk(OID_IFNAME), OID_IFNAME) or tab(await walk(OID_IFDESCR), OID_IFDESCR)
    loc = tab(await walk(OID_LLDP_LOC_DESC), OID_LLDP_LOC_DESC) or tab(await walk(OID_LLDP_LOC_PORT), OID_LLDP_LOC_PORT)
    man = {}
    for vb in await walk(OID_LLDP_REM_MAN):
        p = (_suffix(vb.oid, OID_LLDP_REM_MAN) or "").split(".")
        if len(p) >= 9 and p[3] == "1" and p[4] == "4":  # alt tür 1 = IPv4, sonda 4 sekizli
            man[".".join(p[:3])] = ".".join(p[-4:])
    return {"ifname": {k: _text(v) for k, v in ifn.items()}, "lldp_loc": {k: _text(v) for k, v in loc.items()},
            "lldp": cols(await walk(OID_LLDP_REM), OID_LLDP_REM), "lldp_man": man,
            "cdp": cols(await walk(OID_CDP), OID_CDP)}


def poll_device(ip, community):
    try:
        return parse_neighbors(asyncio.run(_walk_all(ip, community)))
    except Exception as e:  # noqa: BLE001
        log.debug("topo %s: %s", ip, e)
        return []


def save_links(conn, local_ip, links, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    now = _now()
    for l in links:
        conn.execute(
            "INSERT INTO topo_links (tenant_id,local_ip,local_port,remote_name,remote_port,remote_ip,remote_mac,protocol,first_seen,last_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,local_ip,local_port,remote_name,remote_port,protocol) "
            "DO UPDATE SET last_seen=excluded.last_seen, "
            "remote_ip=CASE WHEN excluded.remote_ip='' THEN topo_links.remote_ip ELSE excluded.remote_ip END, "
            "remote_mac=CASE WHEN excluded.remote_mac='' THEN topo_links.remote_mac ELSE excluded.remote_mac END",
            (tenant_id, local_ip, l["local_port"][:64], l["remote_name"][:120], l["remote_port"][:64], l["remote_ip"],
             l["remote_mac"], l["protocol"], now, now))


def discover(tenant_id=None):
    """SNMP erişimi olan envanter cihazlarının komşularını toplar."""
    tenant_id = resolve_tenant(tenant_id)
    if _running.is_set():
        return {"error": "Topoloji taraması zaten çalışıyor."}
    _running.set()
    try:
        devs = [d for d in inventory.list_devices(tenant_id, status="ONLINE") if d["snmp_ok"] and d["snmp_community"]]
        with ThreadPoolExecutor(8) as ex:
            res = list(ex.map(lambda d: (d["ip"], poll_device(d["ip"], d["snmp_community"])), devs))
        conn = _db()
        try:
            n = 0
            for ip, links in res:
                save_links(conn, ip, links, tenant_id)
                n += len(links)
            cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - STALE_DAYS * 86400))
            conn.execute("DELETE FROM topo_links WHERE tenant_id=? AND last_seen<?", (tenant_id, cutoff))
            conn.commit()
        finally:
            conn.close()
        _last.update(at=_now(), result=f"{len(devs)} cihaz tarandı, {n} komşuluk")
        return {"devices": len(devs), "links": n}
    finally:
        _running.clear()


def discover_async(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    if _running.is_set():
        return False
    threading.Thread(target=discover, args=(tenant_id,), daemon=True, name="topo-discover").start()
    return True


def start_scheduler(interval_s=600):
    def loop():
        while True:
            time.sleep(interval_s)
            try:
                for t in all_tenant_ids():
                    discover(t)
            except Exception as e:  # noqa: BLE001
                log.warning("topology scheduler: %s", e)
    threading.Thread(target=loop, daemon=True, name="topology-scheduler").start()


def list_links(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM topo_links WHERE tenant_id=? ORDER BY local_ip, local_port", (tenant_id,))]
    finally:
        conn.close()


def list_overrides(tenant_id=None):
    """{node_key: device_type} — elle atanan türler; otomatik tespit bunların üzerine yazmaz."""
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        return {r["node_key"]: r["device_type"] for r in conn.execute(
            "SELECT node_key, device_type FROM topo_type_override WHERE tenant_id=?", (tenant_id,))}
    finally:
        conn.close()


def set_override(node_key, device_type, user="", tenant_id=None):
    """device_type boş/'auto' ise elle atama kaldırılır. -> (ok, hata)"""
    tenant_id = resolve_tenant(tenant_id)
    node_key = (node_key or "").strip()[:200]
    if not node_key:
        return False, "Düğüm belirtilmedi."
    conn = _db()
    try:
        if device_type in ("", "auto", None):
            conn.execute("DELETE FROM topo_type_override WHERE tenant_id=? AND node_key=?", (tenant_id, node_key))
        elif device_type not in DEVICE_TYPES:
            return False, "Geçersiz cihaz türü."
        else:
            conn.execute(
                "INSERT INTO topo_type_override (tenant_id,node_key,device_type,updated_by,updated_at) VALUES (?,?,?,?,?) "
                "ON CONFLICT(tenant_id,node_key) DO UPDATE SET device_type=excluded.device_type,"
                "updated_by=excluded.updated_by,updated_at=excluded.updated_at",
                (tenant_id, node_key, device_type, (user or "")[:64], _now()))
        conn.commit()
        return True, ""
    finally:
        conn.close()


def build_graph(devices, links, q="", overrides=None):
    """Envanter + komşuluklar -> {nodes, edges}. Envanterde olmayan komşu 'bilinmeyen' düğüm olur;
    aynı bağlantının iki yönü tek kenara indirgenir."""
    by_ip = {d["ip"]: d for d in devices}
    by_name = {}
    for d in devices:
        for k in (d.get("sys_name"), d.get("hostname")):
            if k:
                by_name.setdefault(k.lower().split(".")[0], d["ip"])
    by_mac = {d["mac"].lower(): d["ip"] for d in devices if d.get("mac")}
    nodes, edges = {}, {}

    def node(key, **kw):
        if key not in nodes:
            nodes[key] = {"id": key, "label": key, "type": "Bilinmiyor", "vendor": "", "model": "", "ip": "",
                          "mac": "", "status": "UNKNOWN", "known": False}
        nodes[key].update({k: v for k, v in kw.items() if v})
        return key

    def from_dev(d):
        return node(d["ip"], label=d.get("sys_name") or d.get("hostname") or d["ip"], type=d["device_type"],
                    vendor=d["vendor"], model=d["model"], ip=d["ip"], status=d["status"], known=True, mac=d.get("mac", ""))

    for l in links:
        if l["local_ip"] not in by_ip:
            continue
        a = from_dev(by_ip[l["local_ip"]])
        rip = (l["remote_ip"] if l["remote_ip"] in by_ip else
               by_name.get((l["remote_name"] or "").lower().split(".")[0]) or
               by_mac.get((l["remote_mac"] or l["remote_name"] or "").lower()))
        b = from_dev(by_ip[rip]) if rip else node(l["remote_name"] or l["remote_ip"] or l["remote_mac"],
                                                 ip=l["remote_ip"], mac=l["remote_mac"])
        if a == b:
            continue
        k = tuple(sorted([(a, l["local_port"]), (b, l["remote_port"])]))
        e = edges.setdefault(k, {"source": a, "target": b, "source_port": l["local_port"], "target_port": l["remote_port"],
                                 "protocols": set(), "last_seen": ""})
        e["protocols"].add(l["protocol"])
        e["last_seen"] = max(e["last_seen"], l["last_seen"])
    el = [dict(e, protocols=sorted(e["protocols"])) for e in edges.values()]
    deg = {}
    for e in el:
        deg[e["source"]] = deg.get(e["source"], 0) + 1
        deg[e["target"]] = deg.get(e["target"], 0) + 1
    nl = list(nodes.values())
    ql = (q or "").lower()
    ov = overrides or {}
    for n in nl:
        n["auto_type"] = n["type"]
        n["manual"] = n["id"] in ov
        if n["manual"]:
            n["type"] = ov[n["id"]]
        n["degree"] = deg.get(n["id"], 0)
        if ql:
            n["match"] = ql in " ".join(str(n.get(k, "")) for k in ("label", "ip", "mac", "vendor", "model", "type")).lower()
    return {"nodes": nl, "edges": el}


def graph(tenant_id=None, q=""):
    tenant_id = resolve_tenant(tenant_id)
    g = build_graph(inventory.list_devices(tenant_id), list_links(tenant_id), q, list_overrides(tenant_id))
    g["stats"] = {"nodes": len(g["nodes"]), "edges": len(g["edges"]), "unknown": sum(not n["known"] for n in g["nodes"]),
                  "running": _running.is_set(), "last": dict(_last)}
    return g


CSV_COLS = ["local_ip", "local_port", "remote_name", "remote_port", "remote_ip", "remote_mac", "protocol", "last_seen"]


def links_csv(links):
    """CSV; formül enjeksiyonuna karşı =,+,-,@ ile başlayan hücreler kaçışlanır."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLS)
    for l in links:
        w.writerow([("'" + str(l[c]) if str(l[c])[:1] in ("=", "+", "-", "@") else l[c]) for c in CSV_COLS])
    return buf.getvalue()
