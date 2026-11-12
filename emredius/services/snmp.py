# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""SNMP NMS page data from the NMS SQLite database (device/alarm CRUD lives in the NMS /api/snmp/* blueprint).
Community strings and SNMPv3 keys never leave this module."""
import logging

from ..core import get_nms_db, safe_int
from .tacacs import daemon_state

log = logging.getLogger(__name__)

# Fields the page (tables + topology map) may see; everything else (community, v3 keys...) stays server-side.
DEVICE_PUBLIC_FIELDS = ("id", "ip", "port", "version", "vendor", "sys_name", "sys_descr", "location", "status",
                        "interface_count", "last_cpu", "last_ram", "last_uptime", "last_polled", "kind")


def _pct(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _device_view(d):
    v = {k: d.get(k) for k in DEVICE_PUBLIC_FIELDS if k in d}
    v["id"] = safe_int(d.get("id"), 0)
    v["status"] = d.get("status") or "ONLINE"
    v["version"] = str(d.get("version") or "").upper()
    v["vendor_label"] = (d.get("vendor") or "Generic").upper()
    v["interface_count"] = safe_int(d.get("interface_count"), 0)
    v["cpu"], v["ram"] = _pct(d.get("last_cpu")), _pct(d.get("last_ram"))
    from . import inventory
    v["kind"] = inventory.classify(d.get("vendor") if d.get("vendor") != "Generic" else "", d.get("sys_descr"), 1, 0)
    return v


def _alarm_view(a):
    sev = str(a.get("severity") or "").upper()
    return {"id": safe_int(a.get("id"), 0), "timestamp": a.get("timestamp") or "-",
            "device": a.get("sys_name") or a.get("device_ip") or "-", "type": a.get("alarm_type") or "",
            "severity": sev, "sev_color": "#dc2626" if sev == "CRITICAL" else ("#f59e0b" if sev == "WARNING" else "#3b82f6"),
            "message": a.get("message") or "", "resolved": bool(a.get("resolved")),
            "ai_comment": ""}  # NMS (g): yerel LLM yorumu için boş bağlantı noktası (services/llm.py explain_alarm)


_LIVE_CACHE = {"key": None, "ts": 0.0, "val": None}
_LIVE_TTL = 4.0


def topology_live(force=False):
    """Topology refresh: public device fields + live ICMP ping. `live_status`: ONLINE if SNMP up or ping ok (`snmp_ok` tells SNMP),
    else OFFLINE. DB status is never written here (the poller owns it)."""
    import time
    from concurrent.futures import ThreadPoolExecutor

    from ..core import db as _db

    from ..core.net import ping_host
    key, now = _db.NMS_DB_PATH, time.monotonic()
    c = _LIVE_CACHE
    if not force and c["val"] is not None and c["key"] == key and now - c["ts"] < _LIVE_TTL:
        return c["val"]
    data, error = page_data()
    devs = data["topology"]
    if devs:
        with ThreadPoolExecutor(max_workers=min(16, len(devs))) as ex:
            pings = list(ex.map(lambda d: bool(ping_host(d.get("ip"))), devs))
    else:
        pings = []
    for d, ok in zip(devs, pings):
        d["ping"] = ok
        d["snmp_ok"] = d["status"] == "ONLINE"
        d["live_status"] = "ONLINE" if (d["snmp_ok"] or ok) else "OFFLINE"
    out = {"devices": devs, "online_count": sum(1 for d in devs if d["live_status"] == "ONLINE"),
            "ping_only_count": sum(1 for d in devs if d["live_status"] == "ONLINE" and not d["snmp_ok"]),
           "total": len(devs), "error": error}
    c.update(key=key, ts=time.monotonic(), val=out)
    return out


def page_data():
    """Returns (data, error_message_or_None)."""
    status, devices, alarms, total_interfaces, error = None, [], [], 0, None
    try:
        conn = get_nms_db()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM daemon_status WHERE daemon_name IN ('snmp_daemon', 'snmp_poller') LIMIT 1")
            status = cur.fetchone()
            cur.execute("""
                SELECT d.*,
                       (SELECT count(*) FROM snmp_interfaces i WHERE i.device_id = d.id) AS interface_count,
                       (SELECT cpu_percent FROM snmp_health h WHERE h.device_id = d.id ORDER BY h.id DESC LIMIT 1) AS last_cpu,
                       (SELECT memory_percent FROM snmp_health h WHERE h.device_id = d.id ORDER BY h.id DESC LIMIT 1) AS last_ram,
                       (SELECT uptime_seconds FROM snmp_health h WHERE h.device_id = d.id ORDER BY h.id DESC LIMIT 1) AS last_uptime
                FROM snmp_devices d ORDER BY d.id DESC
            """)
            devices = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT count(*) FROM snmp_interfaces")
            total_interfaces = cur.fetchone()[0] or 0
            cur.execute("""
                SELECT a.*, d.ip AS device_ip, d.sys_name FROM alarms a LEFT JOIN snmp_devices d ON a.device_id = d.id
                ORDER BY a.resolved ASC, a.id DESC LIMIT 30
            """)
            alarms = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
    except Exception as e:
        log.error("snmp page NMS DB error: %s", e)
        error = f"SNMP NMS veritabanı okuma hatası: {e}"
        status, devices, alarms, total_interfaces = None, [], [], 0
    dev_views = [_device_view(d) for d in devices]
    alarm_views = [_alarm_view(a) for a in alarms]
    daemon = daemon_state(status, 161)
    return {
        "daemon": daemon,
        "daemon_pid": (status["pid"] if status and "pid" in status.keys() else "-") if status else "-",
        "devices": dev_views,
        "topology": [{k: v for k, v in d.items() if k in DEVICE_PUBLIC_FIELDS} for d in dev_views],
        "alarms": alarm_views,
        "total_interfaces": total_interfaces,
        "online_count": sum(1 for d in dev_views if d["status"] == "ONLINE"),
        "active_alarms": sum(1 for a in alarm_views if not a["resolved"]),
    }, error
