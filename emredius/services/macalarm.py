# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""MAC Alarmları: port flap, PoE bütçe aşımı, MAC taşınması, yeni/bilinmeyen MAC kuralları. Olaylar Alarmlar panelindeki
alm_events tablosuna (kaynak "mac") yazılır; e-posta ancak kuralda adres VE alarm_smtp_enabled=1 ise gider (varsayılan kapalı).
Veri: eq_ports (flap), ms_poe_main (PoE), mh_changes (taşınma / yeni MAC; machist doldurur)."""
import logging
import threading
import time

from . import alarms, machist, macscan
from ..core import get_nms_db
from ..core.tenant import all_tenant_ids, resolve_tenant

log = logging.getLogger(__name__)

FLAP_WINDOW_S = 600
_schema_ok = set()
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS mxa_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, rtype TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1, param INTEGER NOT NULL DEFAULT 0, severity TEXT NOT NULL DEFAULT 'WARNING',
  email_to TEXT NOT NULL DEFAULT '', UNIQUE(tenant_id, rtype));
CREATE TABLE IF NOT EXISTS mxa_ports (
  tenant_id INTEGER NOT NULL DEFAULT 1, device_ip TEXT NOT NULL, if_index INTEGER NOT NULL, name TEXT DEFAULT '',
  oper TEXT DEFAULT '', PRIMARY KEY (tenant_id, device_ip, if_index));
CREATE TABLE IF NOT EXISTS mxa_flaps (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, device_ip TEXT NOT NULL,
  if_index INTEGER NOT NULL, name TEXT DEFAULT '', at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS mxa_flaps_p ON mxa_flaps(tenant_id, device_ip, if_index, at);
"""

# rtype -> (başlık, açıklama, parametre etiketi, varsayılan parametre, varsayılan önem)
RULES = {
    "port_flap": ("Port flap", "Bir port 10 dk içinde N kez durum değiştirirse", "Değişim sayısı", 4, "WARNING"),
    "poe_over": ("PoE aşımı", "Cihazın PoE tüketimi bütçenin %N'ini aşarsa", "Yüzde", 90, "WARNING"),
    "mac_move": ("MAC taşınması", "Bir MAC başka cihaz/porta geçerse (uplink hariç)", "", 0, "WARNING"),
    "new_mac": ("Yeni / bilinmeyen MAC", "Geçmişte hiç görülmemiş bir MAC erişim portunda belirirse", "", 0, "INFO"),
}


def _db():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        conn.commit()
        for m in (alarms, machist, macscan):
            m._db().close()
        _schema_ok.add(key)
    return conn


def list_rules(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        for rt, (_t, _d, _l, param, sev) in RULES.items():
            conn.execute("INSERT OR IGNORE INTO mxa_rules (tenant_id,rtype,param,severity) VALUES (?,?,?,?)",
                         (tenant_id, rt, param, sev))
        conn.commit()
        rows = [dict(r) for r in conn.execute("SELECT * FROM mxa_rules WHERE tenant_id=?", (tenant_id,))]
    finally:
        conn.close()
    order = list(RULES)
    rows.sort(key=lambda r: order.index(r["rtype"]) if r["rtype"] in order else 99)
    for r in rows:
        r["title"], r["desc"], r["param_label"] = RULES.get(r["rtype"], (r["rtype"], "", ""))[:3]
    return [r for r in rows if r["rtype"] in RULES]


def set_rule(rtype, enabled=None, param=None, severity=None, email_to=None, tenant_id=None):
    """Hata metni döndürür (boşsa başarılı)."""
    if rtype not in RULES:
        return "Bilinmeyen kural."
    tenant_id = resolve_tenant(tenant_id)
    list_rules(tenant_id)
    sets, args = [], []
    if enabled is not None:
        sets.append("enabled=?")
        args.append(1 if enabled else 0)
    if param is not None:
        try:
            p = int(param)
        except (TypeError, ValueError):
            return "Parametre sayı olmalı."
        if not 0 <= p <= 100000 or (rtype == "poe_over" and not 1 <= p <= 100) or (rtype == "port_flap" and p < 2):
            return "Parametre aralık dışı."
        sets.append("param=?")
        args.append(p)
    if severity is not None:
        if severity not in ("INFO", "WARNING", "CRITICAL"):
            return "Önem INFO, WARNING veya CRITICAL olmalı."
        sets.append("severity=?")
        args.append(severity)
    if email_to is not None:
        email_to = (email_to or "").strip()[:120]
        if email_to and ("@" not in email_to or any(c in email_to for c in "\r\n ")):
            return "Geçersiz e-posta."
        sets.append("email_to=?")
        args.append(email_to)
    if not sets:
        return ""
    conn = _db()
    try:
        conn.execute("UPDATE mxa_rules SET " + ",".join(sets) + " WHERE tenant_id=? AND rtype=?", args + [tenant_id, rtype])
        conn.commit()
    finally:
        conn.close()
    return ""


def track_ports(conn, tenant_id, now):
    """eq_ports oper durumunu önceki görüntüyle karşılaştırır; değişimleri mxa_flaps'e yazar. -> flap sayıları {(dev,if):n}"""
    prev = {(r[0], r[1]): r[2] for r in conn.execute("SELECT device_ip, if_index, oper FROM mxa_ports WHERE tenant_id=?", (tenant_id,))}
    for r in conn.execute("SELECT device_ip, if_index, name, oper_status FROM eq_ports WHERE tenant_id=?", (tenant_id,)).fetchall():
        k = (r[0], r[1])
        oper = r[3] or ""
        if k in prev and prev[k] != oper and oper in ("up", "down") and prev[k] in ("up", "down"):
            conn.execute("INSERT INTO mxa_flaps (tenant_id,device_ip,if_index,name,at) VALUES (?,?,?,?,?)",
                         (tenant_id, r[0], r[1], r[2] or "", now))
        conn.execute("INSERT INTO mxa_ports (tenant_id,device_ip,if_index,name,oper) VALUES (?,?,?,?,?) "
                     "ON CONFLICT(tenant_id,device_ip,if_index) DO UPDATE SET name=excluded.name, oper=excluded.oper",
                     (tenant_id, r[0], r[1], r[2] or "", oper))
    conn.execute("DELETE FROM mxa_flaps WHERE tenant_id=? AND at<?", (tenant_id, now - 7 * 86400))
    return {(r[0], r[1]): (r[2], r[3]) for r in conn.execute(
        "SELECT device_ip, if_index, name, COUNT(*) FROM mxa_flaps WHERE tenant_id=? AND at>=? GROUP BY device_ip, if_index",
        (tenant_id, now - FLAP_WINDOW_S))}


def evaluate(tenant_id=None, now=None):
    """Kuralları değerlendirir, alarm olayı açar/çözer. -> açılan yeni olay sayısı"""
    tenant_id = resolve_tenant(tenant_id)
    rules = {r["rtype"]: r for r in list_rules(tenant_id)}
    now = int(now or time.time())
    opened = 0
    with _lock:
        conn = _db()
        try:
            flaps = track_ports(conn, tenant_id, now)
            r = rules["port_flap"]
            if r["enabled"]:
                active = set()
                for (dev, ifi), (name, n) in flaps.items():
                    if n >= r["param"]:
                        key = f"mxa:flap:{dev}:{ifi}"
                        active.add(key)
                        opened += alarms.raise_event(conn, key, "mac", dev, r["severity"],
                                                     f"Port flap: {name or ifi} 10 dk'da {n} kez durum değiştirdi", tenant_id, r["email_to"])
                for (ev_key,) in conn.execute("SELECT ev_key FROM alm_events WHERE tenant_id=? AND source='mac' AND status!='resolved' "
                                              "AND ev_key LIKE 'mxa:flap:%'", (tenant_id,)).fetchall():
                    if ev_key not in active:
                        alarms.resolve_key(conn, ev_key, tenant_id)
            r = rules["poe_over"]
            if r["enabled"]:
                for m in conn.execute("SELECT device_ip, grp, budget_w, used_w FROM ms_poe_main WHERE tenant_id=? AND budget_w>0",
                                      (tenant_id,)).fetchall():
                    pct = round(100.0 * m[3] / m[2])
                    key = f"mxa:poe:{m[0]}:{m[1]}"
                    if pct >= r["param"]:
                        opened += alarms.raise_event(conn, key, "mac", m[0], r["severity"],
                                                     f"PoE aşımı: grup {m[1]} %{pct} ({m[3]}/{m[2]} W)", tenant_id, r["email_to"])
                    else:
                        alarms.resolve_key(conn, key, tenant_id)
            conn.commit()
        finally:
            conn.close()
    done = []
    conn = _db()
    try:
        for c in machist.pending_changes(tenant_id):
            done.append(c["id"])
            r = rules["mac_move" if c["kind"] == "move" else "new_mac"]
            if not r["enabled"]:
                continue
            if c["kind"] == "move":
                msg = f"MAC taşındı: {c['mac']} {c['prev_device_ip']} {c['prev_port']} → {c['device_ip']} {c['port']}"
            else:
                msg = f"Yeni MAC: {c['mac']} {c['device_ip']} {c['port']} portunda ilk kez görüldü"
            opened += alarms.raise_event(conn, f"mxa:{c['kind']}:{c['mac']}", "mac", c["device_ip"], r["severity"], msg,
                                         tenant_id, r["email_to"])
        conn.commit()
    finally:
        conn.close()
    machist.mark_handled(done)
    return opened


def list_events(tenant_id=None, limit=100):
    return alarms.list_events(tenant_id, source="mac", limit=limit)


def start_scheduler(interval_s=60):
    def loop():
        while True:
            time.sleep(interval_s)
            try:
                for t in all_tenant_ids():
                    evaluate(t)
            except Exception as e:  # noqa: BLE001
                log.warning("macalarm scheduler: %s", e)
    threading.Thread(target=loop, daemon=True, name="macalarm-scheduler").start()
