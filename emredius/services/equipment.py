# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Ekipman & MAC Tabloları: SNMP ile port envanteri (IF-MIB), MAC adres tabloları (Q-BRIDGE/BRIDGE-MIB) ve
şasi/modül envanteri (ENTITY-MIB). Tablolar NMS veritabanında, her satırda tenant_id. Salt okunur ağ erişimi."""
import asyncio
import csv
import io
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import inventory, topology
from ..core import get_db, get_nms_db, oui
from ..core.tenant import all_tenant_ids, resolve_tenant

log = logging.getLogger(__name__)

DEFAULT_TENANT = inventory.DEFAULT_TENANT
STALE_DAYS = 7
MAX_MACS_PER_DEVICE = 20000
_schema_ok = set()
_running = threading.Event()
_last = {"at": "", "result": ""}

SCHEMA = """
CREATE TABLE IF NOT EXISTS eq_ports (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, device_ip TEXT NOT NULL,
  if_index INTEGER NOT NULL, name TEXT DEFAULT '', descr TEXT DEFAULT '', alias TEXT DEFAULT '',
  if_type INTEGER DEFAULT 0, speed_mbps INTEGER DEFAULT 0, admin_status TEXT DEFAULT '', oper_status TEXT DEFAULT '',
  mac TEXT DEFAULT '', last_seen TEXT DEFAULT '', UNIQUE(tenant_id, device_ip, if_index));
CREATE TABLE IF NOT EXISTS eq_macs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, device_ip TEXT NOT NULL,
  mac TEXT NOT NULL, vlan INTEGER NOT NULL DEFAULT 0, if_index INTEGER NOT NULL DEFAULT 0, port TEXT DEFAULT '',
  first_seen TEXT DEFAULT '', last_seen TEXT DEFAULT '', UNIQUE(tenant_id, device_ip, mac, vlan));
CREATE INDEX IF NOT EXISTS eq_macs_mac ON eq_macs(tenant_id, mac);
CREATE TABLE IF NOT EXISTS eq_chassis (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, device_ip TEXT NOT NULL,
  ent_index INTEGER NOT NULL, parent INTEGER DEFAULT 0, ent_class TEXT DEFAULT '', position INTEGER DEFAULT 0,
  name TEXT DEFAULT '', descr TEXT DEFAULT '', model TEXT DEFAULT '', serial TEXT DEFAULT '', mfg TEXT DEFAULT '',
  hw_rev TEXT DEFAULT '', fw_rev TEXT DEFAULT '', sw_rev TEXT DEFAULT '', last_seen TEXT DEFAULT '',
  UNIQUE(tenant_id, device_ip, ent_index));
"""

OID_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IFALIAS = "1.3.6.1.2.1.31.1.1.1.18"
OID_IFHIGHSPEED = "1.3.6.1.2.1.31.1.1.1.15"
OID_IFDESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IFTYPE = "1.3.6.1.2.1.2.2.1.3"
OID_IFPHYS = "1.3.6.1.2.1.2.2.1.6"
OID_IFADMIN = "1.3.6.1.2.1.2.2.1.7"
OID_IFOPER = "1.3.6.1.2.1.2.2.1.8"
OID_QFDB = "1.3.6.1.2.1.17.7.1.2.2.1.2"   # dot1qTpFdbPort: vlan.mac(6) -> bridge port
OID_DFDB = "1.3.6.1.2.1.17.4.3.1.2"       # dot1dTpFdbPort: mac(6) -> bridge port
OID_BPORT = "1.3.6.1.2.1.17.1.4.1.2"      # dot1dBasePortIfIndex
OID_ENT = "1.3.6.1.2.1.47.1.1.1.1"        # .2 descr .4 parent .5 class .6 pos .7 name .8 hw .9 fw .10 sw .11 serial .12 mfg .13 model

PORT_TYPES = {6, 62, 69, 71, 117, 161}    # ethernet, fast/gig/FE-FX, wifi, LAG
STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}
ENT_CLASS = {1: "other", 2: "unknown", 3: "chassis", 4: "backplane", 5: "container", 6: "powerSupply", 7: "fan",
             8: "sensor", 9: "module", 10: "port", 11: "stack", 12: "cpu"}


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


def _text(v, n=120):
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("utf-8", "replace").strip("\x00 ")[:n]
    return str(v if v is not None else "").strip()[:n]


def _int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _mac_from_octets(parts):
    try:
        if len(parts) == 6 and all(0 <= int(p) <= 255 for p in parts):
            return ":".join(f"{int(p):02x}" for p in parts)
    except ValueError:
        pass
    return ""


def _mac_bytes(v):
    if isinstance(v, (bytes, bytearray)) and len(v) == 6:
        return ":".join(f"{b:02x}" for b in v)
    return ""


def norm_mac(s):
    """aa:bb:cc:dd:ee:ff biçimine çevirir; geçersizse ''."""
    h = re.sub(r"[^0-9a-f]", "", (s or "").lower())
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else ""


def parse_device(t):
    """t: {'ifname','ifdescr','ifalias','ifspeed','iftype','ifphys','ifadmin','ifoper':{idx:val},
           'qfdb':{'vlan.m1..m6':bport}, 'dfdb':{'m1..m6':bport}, 'bport':{bport:ifindex}, 'ent':{col:{idx:val}}}
    -> (ports, macs, chassis)"""
    ports = []
    idxs = set()
    for k in ("ifname", "ifdescr", "iftype"):
        idxs |= set(t.get(k, {}).keys())
    for idx in sorted(idxs, key=lambda x: _int(x)):
        ityp = _int(t.get("iftype", {}).get(idx))
        if ityp and ityp not in PORT_TYPES:
            continue
        name = _text(t.get("ifname", {}).get(idx)) or _text(t.get("ifdescr", {}).get(idx)) or f"if{idx}"
        ports.append({"if_index": _int(idx), "name": name, "descr": _text(t.get("ifdescr", {}).get(idx)),
                      "alias": _text(t.get("ifalias", {}).get(idx)), "if_type": ityp,
                      "speed_mbps": _int(t.get("ifspeed", {}).get(idx)),
                      "admin_status": STATUS.get(_int(t.get("ifadmin", {}).get(idx)), ""),
                      "oper_status": STATUS.get(_int(t.get("ifoper", {}).get(idx)), ""),
                      "mac": _mac_bytes(t.get("ifphys", {}).get(idx))})
    names = {p["if_index"]: p["name"] for p in ports}
    macs, seen = [], set()
    entries = [(p.split("."), v) for p, v in t.get("qfdb", {}).items()]
    if not entries:
        entries = [(["0"] + p.split("."), v) for p, v in t.get("dfdb", {}).items()]
    for parts, bport in entries:
        mac = _mac_from_octets(parts[1:]) if len(parts) == 7 else ""
        vlan = _int(parts[0])
        if not mac or (mac, vlan) in seen:
            continue
        ifi = _int(t.get("bport", {}).get(str(_int(bport))), _int(bport))
        if not ifi:
            continue
        seen.add((mac, vlan))
        macs.append({"mac": mac, "vlan": vlan, "if_index": ifi, "port": names.get(ifi, f"if{ifi}")})
        if len(macs) >= MAX_MACS_PER_DEVICE:
            break
    ent = t.get("ent", {})
    chassis = []
    for idx in sorted(set(ent.get(2, {})) | set(ent.get(5, {})), key=lambda x: _int(x)):
        cls = ENT_CLASS.get(_int(ent.get(5, {}).get(idx)), "other")
        row = {"ent_index": _int(idx), "parent": _int(ent.get(4, {}).get(idx)), "ent_class": cls,
               "position": _int(ent.get(6, {}).get(idx)), "name": _text(ent.get(7, {}).get(idx)),
               "descr": _text(ent.get(2, {}).get(idx)), "model": _text(ent.get(13, {}).get(idx)),
               "serial": _text(ent.get(11, {}).get(idx)), "mfg": _text(ent.get(12, {}).get(idx)),
               "hw_rev": _text(ent.get(8, {}).get(idx)), "fw_rev": _text(ent.get(9, {}).get(idx)),
               "sw_rev": _text(ent.get(10, {}).get(idx))}
        if cls in ("other", "unknown") and not (row["model"] or row["serial"] or row["name"]):
            continue
        chassis.append(row)
    return ports, macs, chassis


async def _walk_all(ip, community):
    from nms.snmp.engine import SnmpClient
    c = SnmpClient()

    async def walk(root, to=30):
        try:
            return await asyncio.wait_for(c.walk(target=ip, root_oid=root, community=community, version="v2c",
                                                 timeout=2, retries=1), to)
        except Exception as e:  # noqa: BLE001
            log.debug("walk %s %s: %s", ip, root, e)
            return []

    def tab(vbs, base):
        d = {}
        for vb in vbs:
            s = topology._suffix(vb.oid, base)
            if s is not None:
                d[s] = vb.value
        return d

    ent = {}
    for vb in await walk(OID_ENT, 40):
        s = topology._suffix(vb.oid, OID_ENT) or ""
        col, _, idx = s.partition(".")
        if col.isdigit() and idx:
            ent.setdefault(int(col), {})[idx] = vb.value
    return {"ifname": tab(await walk(OID_IFNAME), OID_IFNAME), "ifdescr": tab(await walk(OID_IFDESCR), OID_IFDESCR),
            "ifalias": tab(await walk(OID_IFALIAS), OID_IFALIAS), "ifspeed": tab(await walk(OID_IFHIGHSPEED), OID_IFHIGHSPEED),
            "iftype": tab(await walk(OID_IFTYPE), OID_IFTYPE), "ifphys": tab(await walk(OID_IFPHYS), OID_IFPHYS),
            "ifadmin": tab(await walk(OID_IFADMIN), OID_IFADMIN), "ifoper": tab(await walk(OID_IFOPER), OID_IFOPER),
            "qfdb": tab(await walk(OID_QFDB, 60), OID_QFDB), "dfdb": tab(await walk(OID_DFDB, 60), OID_DFDB),
            "bport": tab(await walk(OID_BPORT), OID_BPORT), "ent": ent}


def poll_device(ip, community):
    try:
        return parse_device(asyncio.run(_walk_all(ip, community)))
    except Exception as e:  # noqa: BLE001
        log.debug("equipment %s: %s", ip, e)
        return [], [], []


def save_device_data(conn, ip, ports, macs, chassis, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    now = _now()
    for p in ports:
        conn.execute(
            "INSERT INTO eq_ports (tenant_id,device_ip,if_index,name,descr,alias,if_type,speed_mbps,admin_status,oper_status,mac,last_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,device_ip,if_index) DO UPDATE SET name=excluded.name,"
            "descr=excluded.descr,alias=excluded.alias,if_type=excluded.if_type,speed_mbps=excluded.speed_mbps,"
            "admin_status=excluded.admin_status,oper_status=excluded.oper_status,mac=excluded.mac,last_seen=excluded.last_seen",
            (tenant_id, ip, p["if_index"], p["name"], p["descr"], p["alias"], p["if_type"], p["speed_mbps"],
             p["admin_status"], p["oper_status"], p["mac"], now))
    for m in macs:
        conn.execute(
            "INSERT INTO eq_macs (tenant_id,device_ip,mac,vlan,if_index,port,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(tenant_id,device_ip,mac,vlan) DO UPDATE SET if_index=excluded.if_index,port=excluded.port,"
            "last_seen=excluded.last_seen", (tenant_id, ip, m["mac"], m["vlan"], m["if_index"], m["port"], now, now))
    if chassis:
        conn.execute("DELETE FROM eq_chassis WHERE tenant_id=? AND device_ip=?", (tenant_id, ip))
    for c in chassis:
        conn.execute(
            "INSERT OR REPLACE INTO eq_chassis (tenant_id,device_ip,ent_index,parent,ent_class,position,name,descr,model,serial,"
            "mfg,hw_rev,fw_rev,sw_rev,last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tenant_id, ip, c["ent_index"], c["parent"], c["ent_class"], c["position"], c["name"], c["descr"], c["model"],
             c["serial"], c["mfg"], c["hw_rev"], c["fw_rev"], c["sw_rev"], now))


def discover(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    if _running.is_set():
        return {"error": "Ekipman taraması zaten çalışıyor."}
    _running.set()
    try:
        devs = [d for d in inventory.list_devices(tenant_id, status="ONLINE") if d["snmp_ok"] and d["snmp_community"]]
        with ThreadPoolExecutor(6) as ex:
            res = list(ex.map(lambda d: (d["ip"], poll_device(d["ip"], d["snmp_community"])), devs))
        conn = _db()
        try:
            np_ = nm = 0
            for ip, (ports, macs, chassis) in res:
                save_device_data(conn, ip, ports, macs, chassis, tenant_id)
                np_ += len(ports)
                nm += len(macs)
            cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - STALE_DAYS * 86400))
            conn.execute("DELETE FROM eq_macs WHERE tenant_id=? AND last_seen<?", (tenant_id, cutoff))
            conn.execute("DELETE FROM eq_ports WHERE tenant_id=? AND last_seen<?", (tenant_id, cutoff))
            conn.commit()
        finally:
            conn.close()
        _last.update(at=_now(), result=f"{len(devs)} cihaz, {np_} port, {nm} MAC")
        return {"devices": len(devs), "ports": np_, "macs": nm}
    finally:
        _running.clear()


def discover_async(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    if _running.is_set():
        return False
    threading.Thread(target=discover, args=(tenant_id,), daemon=True, name="equipment-discover").start()
    return True


def start_scheduler(interval_s=900):
    def loop():
        while True:
            time.sleep(interval_s)
            try:
                for t in all_tenant_ids():
                    discover(t)
            except Exception as e:  # noqa: BLE001
                log.warning("equipment scheduler: %s", e)
    threading.Thread(target=loop, daemon=True, name="equipment-scheduler").start()


def radius_users(macs):
    """MAC -> {user, ip, active} (en son RADIUS oturumu). RADIUS veritabanı yoksa boş sözlük."""
    keys = {re.sub(r"[^0-9a-f]", "", m.lower()): m for m in macs if norm_mac(m)}
    if not keys:
        return {}
    out = {}
    try:
        conn = get_db()
    except Exception:  # noqa: BLE001
        return {}
    try:
        with conn.cursor() as cur:
            ks = list(keys)[:500]
            cur.execute(
                "SELECT username, framedipaddress, callingstationid, (acctstoptime IS NULL) AS active, radacctid FROM radacct "
                "WHERE REPLACE(REPLACE(REPLACE(LOWER(callingstationid), ':', ''), '-', ''), '.', '') IN (%s) "
                "ORDER BY radacctid" % ",".join(["%s"] * len(ks)), ks)
            for r in cur.fetchall():
                k = re.sub(r"[^0-9a-f]", "", (r["callingstationid"] or "").lower())
                if k in keys:
                    out[keys[k]] = {"user": r["username"], "ip": r["framedipaddress"] or "", "active": bool(r["active"])}
    except Exception as e:  # noqa: BLE001
        log.debug("equipment radius lookup: %s", e)
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
    return out


def list_ports(tenant_id=None, device_ip="", q="", state="", limit=20000):
    tenant_id = resolve_tenant(tenant_id)
    sql, args = "SELECT * FROM eq_ports WHERE tenant_id=?", [tenant_id]
    if device_ip:
        sql += " AND device_ip=?"
        args.append(device_ip)
    if state in ("up", "down"):
        sql += " AND oper_status=?"
        args.append(state)
    if q:
        sql += " AND (name LIKE ? OR alias LIKE ? OR descr LIKE ? OR mac LIKE ? OR device_ip LIKE ?)"
        args += [f"%{q}%"] * 5
    sql += " ORDER BY device_ip, if_index LIMIT ?"
    args.append(max(1, min(int(limit), 50000)))
    conn = _db()
    try:
        return [dict(r) for r in conn.execute(sql, args)]
    finally:
        conn.close()


def list_macs(tenant_id=None, device_ip="", port="", q="", vlan="", limit=2000, enrich=True):
    tenant_id = resolve_tenant(tenant_id)
    sql, args = "SELECT * FROM eq_macs WHERE tenant_id=?", [tenant_id]
    if device_ip:
        sql += " AND device_ip=?"
        args.append(device_ip)
    if port:
        sql += " AND port=?"
        args.append(port)
    if vlan not in ("", None) and str(vlan).isdigit():
        sql += " AND vlan=?"
        args.append(int(vlan))
    qm = re.sub(r"[^0-9a-f]", "", (q or "").lower())
    if q:
        sql += " AND (mac LIKE ? OR port LIKE ? OR device_ip LIKE ?)" if not qm else " AND (REPLACE(mac,':','') LIKE ? OR port LIKE ? OR device_ip LIKE ?)"
        args += [f"%{qm if qm else q}%", f"%{q}%", f"%{q}%"]
    sql += " ORDER BY device_ip, port, mac LIMIT ?"
    args.append(max(1, min(int(limit), 50000)))
    conn = _db()
    try:
        rows = [dict(r) for r in conn.execute(sql, args)]
        uplink = {(l["local_ip"], l["local_port"]) for l in conn.execute(
            "SELECT local_ip, local_port FROM topo_links WHERE tenant_id=?", (tenant_id,))} if _has_topo(conn) else set()
    finally:
        conn.close()
    if enrich:
        by_mac = {d["mac"].lower(): d for d in inventory.list_devices(tenant_id) if d.get("mac")}
        users = radius_users([r["mac"] for r in rows])
        for r in rows:
            d = by_mac.get(r["mac"])
            r["vendor"] = oui.lookup(r["mac"]) or ""
            r["inv_ip"] = d["ip"] if d else ""
            r["inv_name"] = (d.get("sys_name") or d.get("hostname")) if d else ""
            u = users.get(r["mac"], {})
            r["radius_user"], r["radius_ip"], r["radius_active"] = u.get("user", ""), u.get("ip", ""), u.get("active", False)
            r["uplink"] = (r["device_ip"], r["port"]) in uplink
    return rows


def _has_topo(conn):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE name='topo_links'").fetchone() is not None


def list_chassis(tenant_id=None, device_ip=""):
    tenant_id = resolve_tenant(tenant_id)
    sql, args = "SELECT * FROM eq_chassis WHERE tenant_id=?", [tenant_id]
    if device_ip:
        sql += " AND device_ip=?"
        args.append(device_ip)
    conn = _db()
    try:
        return [dict(r) for r in conn.execute(sql + " ORDER BY device_ip, ent_index", args)]
    finally:
        conn.close()


def device_summary(tenant_id=None):
    """Cihaz başına port/MAC/modül sayıları (envanterle birleşik)."""
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        pc = {r[0]: (r[1], r[2]) for r in conn.execute(
            "SELECT device_ip, COUNT(*), SUM(oper_status='up') FROM eq_ports WHERE tenant_id=? GROUP BY device_ip", (tenant_id,))}
        mc = {r[0]: r[1] for r in conn.execute(
            "SELECT device_ip, COUNT(*) FROM eq_macs WHERE tenant_id=? GROUP BY device_ip", (tenant_id,))}
        cc = {r[0]: r[1] for r in conn.execute(
            "SELECT device_ip, COUNT(*) FROM eq_chassis WHERE tenant_id=? GROUP BY device_ip", (tenant_id,))}
    finally:
        conn.close()
    out = []
    for d in inventory.list_devices(tenant_id):
        if d["ip"] in pc or d["snmp_ok"]:
            n, up = pc.get(d["ip"], (0, 0))
            out.append({"ip": d["ip"], "name": d.get("sys_name") or d.get("hostname") or d["ip"], "vendor": d["vendor"],
                        "model": d["model"], "type": d["device_type"], "status": d["status"],
                        "ports": n, "ports_up": up or 0, "macs": mc.get(d["ip"], 0), "modules": cc.get(d["ip"], 0)})
    return out


def panel(device_ip, tenant_id=None):
    """Ön panel: portlar + her porttaki MAC sayısı + karşı uç (LLDP/CDP komşusu)."""
    tenant_id = resolve_tenant(tenant_id)
    ports = list_ports(tenant_id, device_ip)
    conn = _db()
    try:
        cnt = {r[0]: r[1] for r in conn.execute(
            "SELECT port, COUNT(*) FROM eq_macs WHERE tenant_id=? AND device_ip=? GROUP BY port", (tenant_id, device_ip))}
        nb = {}
        if _has_topo(conn):
            for r in conn.execute("SELECT local_port, remote_name, remote_port FROM topo_links WHERE tenant_id=? AND local_ip=?",
                                  (tenant_id, device_ip)):
                nb[r[0]] = f"{r[1]} {r[2]}".strip()
    finally:
        conn.close()
    for p in ports:
        p["mac_count"] = cnt.get(p["name"], 0)
        p["neighbor"] = nb.get(p["name"], "")
    return ports


def overview(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        g = lambda sql: conn.execute(sql, (tenant_id,)).fetchone()[0] or 0  # noqa: E731
        return {"ports": g("SELECT COUNT(*) FROM eq_ports WHERE tenant_id=?"),
                "ports_up": g("SELECT SUM(oper_status='up') FROM eq_ports WHERE tenant_id=?"),
                "macs": g("SELECT COUNT(*) FROM eq_macs WHERE tenant_id=?"),
                "modules": g("SELECT COUNT(*) FROM eq_chassis WHERE tenant_id=?"),
                "running": _running.is_set(), "last": dict(_last)}
    finally:
        conn.close()


def _csv(rows, cols):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([("'" + str(r.get(c, "")) if str(r.get(c, ""))[:1] in ("=", "+", "-", "@") else r.get(c, "")) for c in cols])
    return buf.getvalue()


PORT_COLS = ["device_ip", "if_index", "name", "alias", "speed_mbps", "admin_status", "oper_status", "mac", "last_seen"]
MAC_COLS = ["device_ip", "port", "vlan", "mac", "vendor", "inv_ip", "radius_user", "radius_ip", "last_seen"]
CHASSIS_COLS = ["device_ip", "ent_index", "parent", "ent_class", "name", "descr", "model", "serial", "mfg", "hw_rev", "fw_rev", "sw_rev"]
KINDS = {"ports": PORT_COLS, "macs": MAC_COLS, "chassis": CHASSIS_COLS}


def to_csv(kind, rows):
    return _csv(rows, KINDS[kind])
