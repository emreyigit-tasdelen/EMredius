# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""MAC Geçmişi: eq_macs anlık görüntüsünden (kullanıcı/MAC başına) hangi cihaz-portlardan ne zaman bağlandığını biriktirir.
mh_hist = (MAC, cihaz, port, VLAN) başına ilk/son görülme; mh_changes = MAC taşınması / yeni MAC olayları (alarm modülü okur).
RADIUS oturumlarıyla radacct üzerinden çapraz bağlanır. Tablolar NMS veritabanında, her satırda tenant_id."""
import logging
import re
import threading
import time

from . import equipment
from ..core import get_db, get_nms_db
from ..core.tenant import all_tenant_ids, resolve_tenant

log = logging.getLogger(__name__)

RETENTION_DAYS = 365
_schema_ok = set()
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS mh_hist (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, mac TEXT NOT NULL, device_ip TEXT NOT NULL,
  port TEXT DEFAULT '', vlan INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  seen_count INTEGER NOT NULL DEFAULT 1, UNIQUE(tenant_id, mac, device_ip, port, vlan));
CREATE INDEX IF NOT EXISTS mh_hist_mac ON mh_hist(tenant_id, mac, last_seen);
CREATE TABLE IF NOT EXISTS mh_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, kind TEXT NOT NULL, mac TEXT NOT NULL,
  device_ip TEXT DEFAULT '', port TEXT DEFAULT '', prev_device_ip TEXT DEFAULT '', prev_port TEXT DEFAULT '',
  at TEXT NOT NULL, handled INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS mh_changes_h ON mh_changes(tenant_id, handled);
"""


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _db():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        conn.commit()
        equipment._db().close()
        _schema_ok.add(key)
    return conn


def record(tenant_id=None, rows=None):
    """Anlık MAC tablosunu (uplink olmayan portlar) geçmişe işler. Taşınma / yeni MAC olaylarını mh_changes'e yazar.
    İlk çalışmada (geçmiş boşken) 'yeni MAC' olayı üretmez. -> {"seen", "moves", "new"}"""
    tenant_id = resolve_tenant(tenant_id)
    if rows is None:
        rows = equipment.list_macs(tenant_id, limit=50000, enrich=True)
    cur = {}
    for m in rows:
        if m.get("uplink") or not m.get("mac"):
            continue
        cur.setdefault(m["mac"], set()).add((m["device_ip"], m.get("port") or "", int(m.get("vlan") or 0)))
    now = _now()
    moves = new = 0
    with _lock:
        conn = _db()
        try:
            baseline = conn.execute("SELECT 1 FROM mh_hist WHERE tenant_id=? LIMIT 1", (tenant_id,)).fetchone() is not None
            last = {}
            for r in conn.execute("SELECT mac, device_ip, port, last_seen FROM mh_hist WHERE tenant_id=? ORDER BY last_seen",
                                  (tenant_id,)):
                last[r[0]] = (r[1], r[2])
            for mac, locs in cur.items():
                prev = last.get(mac)
                here = {(d, p) for d, p, _ in locs}
                d, p, _v = sorted(locs)[0]
                if prev is None:
                    if baseline:
                        conn.execute("INSERT INTO mh_changes (tenant_id,kind,mac,device_ip,port,at) VALUES (?,?,?,?,?,?)",
                                     (tenant_id, "new", mac, d, p, now))
                        new += 1
                elif prev not in here:
                    conn.execute("INSERT INTO mh_changes (tenant_id,kind,mac,device_ip,port,prev_device_ip,prev_port,at) "
                                 "VALUES (?,?,?,?,?,?,?,?)", (tenant_id, "move", mac, d, p, prev[0], prev[1], now))
                    moves += 1
                for dd, pp, vv in locs:
                    conn.execute(
                        "INSERT INTO mh_hist (tenant_id,mac,device_ip,port,vlan,first_seen,last_seen) VALUES (?,?,?,?,?,?,?) "
                        "ON CONFLICT(tenant_id,mac,device_ip,port,vlan) DO UPDATE SET last_seen=excluded.last_seen, "
                        "seen_count=seen_count+1", (tenant_id, mac, dd, pp, vv, now, now))
            cut = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - RETENTION_DAYS * 86400))
            conn.execute("DELETE FROM mh_hist WHERE tenant_id=? AND last_seen<?", (tenant_id, cut))
            conn.execute("DELETE FROM mh_changes WHERE tenant_id=? AND handled=1 AND at<?", (tenant_id, cut))
            conn.commit()
        finally:
            conn.close()
    return {"seen": len(cur), "moves": moves, "new": new}


def start_scheduler(interval_s=300):
    def loop():
        while True:
            time.sleep(interval_s)
            try:
                for t in all_tenant_ids():
                    record(t)
            except Exception as e:  # noqa: BLE001
                log.warning("machist scheduler: %s", e)
    threading.Thread(target=loop, daemon=True, name="machist-scheduler").start()


def _mac_key(s):
    return re.sub(r"[^0-9a-f]", "", (s or "").lower())


def _close(conn):
    try:
        conn.close()
    except Exception:  # noqa: BLE001
        pass


def user_macs(username):
    """RADIUS kullanıcısının cihaz MAC'leri (radacct.callingstationid) -> [norm_mac]."""
    try:
        conn = get_db()
    except Exception:  # noqa: BLE001
        return []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT callingstationid FROM radacct WHERE username=%s AND callingstationid<>'' LIMIT 200",
                        (username,))
            return sorted({equipment.norm_mac(r["callingstationid"]) for r in cur.fetchall()} - {""})
    except Exception as e:  # noqa: BLE001
        log.debug("machist user_macs: %s", e)
        return []
    finally:
        _close(conn)


def radius_sessions(macs=(), username="", days=30, limit=500):
    """Son N günün RADIUS oturumları (kullanıcı adı ve/veya MAC listesi ile)."""
    keys = [k for k in (_mac_key(m) for m in macs) if k][:200]
    if not username and not keys:
        return []
    conds, args = [], []
    if username:
        conds.append("username=%s")
        args.append(username)
    if keys:
        conds.append("REPLACE(REPLACE(REPLACE(LOWER(callingstationid), ':', ''), '-', ''), '.', '') IN (%s)"
                     % ",".join(["%s"] * len(keys)))
        args += keys
    try:
        conn = get_db()
    except Exception:  # noqa: BLE001
        return []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username, callingstationid, nasipaddress, nasportid, framedipaddress, acctstarttime, acctstoptime "
                        "FROM radacct WHERE (" + " OR ".join(conds) + ") AND acctstarttime >= DATE_SUB(NOW(), INTERVAL %s DAY) "
                        "ORDER BY acctstarttime DESC LIMIT %s", args + [int(days), int(limit)])
            return [{"user": r["username"], "mac": equipment.norm_mac(r["callingstationid"] or ""), "nas": r["nasipaddress"],
                     "nas_port": r["nasportid"] or "", "ip": r["framedipaddress"] or "",
                     "start": str(r["acctstarttime"] or ""), "stop": str(r["acctstoptime"] or "")} for r in cur.fetchall()]
    except Exception as e:  # noqa: BLE001
        log.debug("machist radius_sessions: %s", e)
        return []
    finally:
        _close(conn)


def history(tenant_id=None, q="", days=30, limit=2000):
    """q: MAC (herhangi biçim), RADIUS kullanıcı adı, cihaz IP'si veya port. -> {"macs", "ports", "sessions", "user"}"""
    tenant_id = resolve_tenant(tenant_id)
    q = (q or "").strip()[:64]
    days = max(1, min(int(days or 30), 365))
    empty = {"macs": [], "ports": [], "sessions": [], "user": ""}
    if not q:
        return empty
    macs, user = [], ""
    if len(_mac_key(q)) == 12:
        macs = [equipment.norm_mac(q)]
    else:
        macs = user_macs(q)
        user = q if macs else ""
    cut = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - days * 86400))
    if macs:
        sql = "SELECT * FROM mh_hist WHERE tenant_id=? AND last_seen>=? AND mac IN (%s)" % ",".join("?" * len(macs))
        args = [tenant_id, cut] + macs
    else:
        sql, args = ("SELECT * FROM mh_hist WHERE tenant_id=? AND last_seen>=? AND (device_ip=? OR port LIKE ?)",
                     [tenant_id, cut, q, "%" + q + "%"])
    conn = _db()
    try:
        ports = [dict(r) for r in conn.execute(sql + " ORDER BY last_seen DESC LIMIT ?",
                                               args + [max(1, min(int(limit), 10000))])]
    finally:
        conn.close()
    shown = macs or sorted({p["mac"] for p in ports})
    users = equipment.radius_users(shown) if shown else {}
    for p in ports:
        p["radius_user"] = (users.get(p["mac"]) or {}).get("user", "")
    sessions = radius_sessions(shown, user, days) if shown else []
    return {"macs": shown, "ports": ports, "sessions": sessions, "user": user}


def pending_changes(tenant_id=None):
    """İşlenmemiş taşınma/yeni MAC olayları (alarm modülü okur)."""
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM mh_changes WHERE tenant_id=? AND handled=0 ORDER BY id LIMIT 500",
                                              (tenant_id,))]
    finally:
        conn.close()


def mark_handled(ids):
    if not ids:
        return
    conn = _db()
    try:
        conn.execute("UPDATE mh_changes SET handled=1 WHERE id IN (%s)" % ",".join("?" * len(ids)), list(ids))
        conn.commit()
    finally:
        conn.close()


COLS = ["mac", "radius_user", "device_ip", "port", "vlan", "first_seen", "last_seen", "seen_count"]


def to_csv(rows):
    return equipment._csv(rows, COLS)
