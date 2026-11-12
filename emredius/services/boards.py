# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Özel panolar: kullanıcının kendi panosunu hazır bileşenlerden (envanter, alarm, sağlık, izlenen IP, akış, ekipman, döngü) kurması.
Pano tanımı NMS veritabanında dash_boards (tenant_id'li); bileşen verisi her istekte ilgili servislerden canlı okunur."""
import json
import threading
import time

from . import alarms, equipment, flows, health, inventory, loops, watch
from ..core import get_nms_db
from ..core.tenant import resolve_tenant

DEFAULT_TENANT = inventory.DEFAULT_TENANT
MAX_BOARDS = 30
MAX_WIDGETS = 24
_schema_ok = set()
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS dash_boards (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL, owner TEXT DEFAULT '',
  widgets TEXT NOT NULL DEFAULT '[]', created TEXT DEFAULT '', updated TEXT DEFAULT '');
"""


def _stats(title, *rows):
    return {"kind": "stats", "title": title, "items": [{"label": a, "value": b, "href": h, "tone": t} for a, b, h, t in rows]}


def _list(title, rows, href):
    return {"kind": "list", "title": title, "href": href, "items": rows}


def w_inventory(t):
    o = inventory.overview(t)
    return _stats("Aktif cihazlar", ("Aktif", o.get("online", 0), "/inventory", ""), ("Toplam", o.get("total", 0), "/inventory", ""),
                  ("SNMP", o.get("snmp", 0), "/inventory", ""), ("SSH", o.get("ssh", 0), "/inventory", ""))


def w_alarms(t):
    o = alarms.overview(t)
    return _stats("Alarmlar", ("Aktif", o["active"], "/alarms", "bad" if o["active"] else "ok"),
                  ("Kritik", o["critical"], "/alarms", "bad" if o["critical"] else "ok"), ("Onaylı", o["ack"], "/alarms", ""))


def w_alarm_list(t):
    ev = alarms.list_events(t, status="active", limit=6)
    return _list("Son aktif alarmlar", [{"text": e["message"], "sub": f"{e['severity']} · {e['device_ip']}"} for e in ev], "/alarms")


def w_health(t):
    o = health.overview(t)
    return _stats("Ekipman sağlığı", ("Cihaz", o["devices"], "/health", ""), ("Uyarı", o["warn"], "/health", "bad" if o["warn"] else "ok"),
                  ("Veri yok", o["nodata"], "/health", ""))


def w_health_list(t):
    rows = [r for r in health.health_rows(t) if r["state"] == "warn"][:6]
    return _list("Yüksek yüklü cihazlar", [{"text": r["name"], "sub": f"CPU {r['cpu']} · Bellek {r['ram']} · {r['temp']}°C"} for r in rows], "/health")


def w_watch(t):
    o = watch.overview(t)
    return _stats("İzlenen IP'ler", ("Açık", o["up"], "/watch", "ok"), ("Kapalı", o["down"], "/watch", "bad" if o["down"] else "ok"),
                  ("Toplam", o["total"], "/watch", ""))


def w_equipment(t):
    o = equipment.overview(t)
    return _stats("Ekipman", ("Port (açık)", f"{o['ports_up']}/{o['ports']}", "/equipment", ""), ("MAC", o["macs"], "/equipment", ""),
                  ("Modül", o["modules"], "/equipment", ""))


def w_loops(t):
    o = loops.overview(t)
    return _stats("Döngü tespiti", ("Halka", o["rings"], "/loops", "bad" if o["rings"] else "ok"),
                  ("MAC taşınması", o["macs"], "/loops", "bad" if o["macs"] else "ok"))


def w_flows_src(t):
    return _list("En çok konuşanlar (1 sa)", [{"text": r["key"], "sub": f"{r['name'] or '-'} · {r['bytes']} bayt"} for r in flows.top("src", "1h", t, limit=6)], "/flows")


def w_flows_app(t):
    return _list("Uygulamalar (1 sa)", [{"text": r["name"], "sub": f"{r['bytes']} bayt"} for r in flows.top("app", "1h", t, limit=6)], "/flows")


CATALOG = {
    "inventory": ("Aktif cihazlar", w_inventory), "alarms": ("Alarm özeti", w_alarms), "alarm_list": ("Son aktif alarmlar", w_alarm_list),
    "health": ("Sağlık özeti", w_health), "health_list": ("Yüksek yüklü cihazlar", w_health_list), "watch": ("İzlenen IP'ler", w_watch),
    "equipment": ("Ekipman özeti", w_equipment), "loops": ("Döngü tespiti", w_loops),
    "flows_src": ("En çok konuşanlar", w_flows_src), "flows_app": ("Uygulamalar", w_flows_app),
}


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


def _clean(widgets):
    out = []
    for w in widgets if isinstance(widgets, list) else []:
        if isinstance(w, str) and w in CATALOG and w not in out:
            out.append(w)
    return out[:MAX_WIDGETS]


def create_board(name, owner="", widgets=None, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    name = (name or "").strip()[:64]
    if not name:
        return None, "Pano adı gerekli."
    conn = _db()
    try:
        if conn.execute("SELECT COUNT(*) FROM dash_boards WHERE tenant_id=?", (tenant_id,)).fetchone()[0] >= MAX_BOARDS:
            return None, f"En fazla {MAX_BOARDS} pano oluşturulabilir."
        cur = conn.execute("INSERT INTO dash_boards (tenant_id,name,owner,widgets,created,updated) VALUES (?,?,?,?,?,?)",
                           (tenant_id, name, (owner or "")[:64], json.dumps(_clean(widgets if widgets is not None else ["inventory", "alarms", "health", "watch"])),
                            _now(), _now()))
        conn.commit()
        return cur.lastrowid, ""
    finally:
        conn.close()


def get_board(board_id, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        r = conn.execute("SELECT * FROM dash_boards WHERE id=? AND tenant_id=?", (board_id, tenant_id)).fetchone()
    finally:
        conn.close()
    if not r:
        return None
    d = dict(r)
    d["widgets"] = _clean(json.loads(d["widgets"] or "[]"))
    return d


def list_boards(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        return [{"id": r["id"], "name": r["name"], "owner": r["owner"], "count": len(json.loads(r["widgets"] or "[]"))}
                for r in conn.execute("SELECT * FROM dash_boards WHERE tenant_id=? ORDER BY id", (tenant_id,))]
    finally:
        conn.close()


def set_widgets(board_id, widgets, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        n = conn.execute("UPDATE dash_boards SET widgets=?, updated=? WHERE id=? AND tenant_id=?",
                         (json.dumps(_clean(widgets)), _now(), board_id, tenant_id)).rowcount
        conn.commit()
        return n > 0
    finally:
        conn.close()


def rename_board(board_id, name, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    name = (name or "").strip()[:64]
    if not name:
        return False
    conn = _db()
    try:
        n = conn.execute("UPDATE dash_boards SET name=?, updated=? WHERE id=? AND tenant_id=?", (name, _now(), board_id, tenant_id)).rowcount
        conn.commit()
        return n > 0
    finally:
        conn.close()


def delete_board(board_id, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        n = conn.execute("DELETE FROM dash_boards WHERE id=? AND tenant_id=?", (board_id, tenant_id)).rowcount
        conn.commit()
        return n > 0
    finally:
        conn.close()


def render(board, tenant_id=None):
    """Pano bileşenlerini canlı veriyle üretir; tek bileşenin hatası panoyu bozmaz."""
    tenant_id = resolve_tenant(tenant_id)
    out = []
    for key in board["widgets"]:
        try:
            w = CATALOG[key][1](tenant_id)
        except Exception as e:  # noqa: BLE001
            w = {"kind": "list", "title": CATALOG[key][0], "items": [{"text": "Veri alınamadı", "sub": str(e)[:80]}]}
        w["key"] = key
        out.append(w)
    return out
