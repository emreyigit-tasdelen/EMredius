# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Ekipman Sağlığı & Trafik: NMS poller tarafından yazılan snmp_health / snmp_telemetry tablolarından son değerler,
geçmiş ve en yoğun arayüzler. Salt okunur; kiracı ayrımı envanter (inv_devices, tenant_id) ile IP üzerinden yapılır."""
import csv
import io
import time

from . import inventory
from ..core import get_nms_db
from ..core.tenant import resolve_tenant

DEFAULT_TENANT = inventory.DEFAULT_TENANT
WARN = {"cpu": 80, "ram": 85, "temp": 70}
KINDS = {"health": ["ip", "name", "vendor", "cpu", "ram", "temp", "uptime_s", "ts", "state"],
         "traffic": ["ip", "name", "if_index", "in_bps", "out_bps", "ts"]}


def _tenant_ips(tenant_id):
    return {d["ip"] for d in inventory.list_devices(tenant_id)}


def _state(cpu, ram, temp):
    if (cpu or 0) >= WARN["cpu"] or (ram or 0) >= WARN["ram"] or (temp or 0) >= WARN["temp"]:
        return "warn"
    return "ok"


def health_rows(tenant_id=None, q=""):
    tenant_id = resolve_tenant(tenant_id)
    conn = get_nms_db()
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT d.id, d.ip, d.sys_name, d.vendor, h.cpu_percent, h.memory_percent, h.temperature_c, h.uptime_seconds, h.timestamp "
            "FROM snmp_devices d LEFT JOIN snmp_health h ON h.id=(SELECT MAX(id) FROM snmp_health WHERE device_id=d.id)")]
    except Exception:  # noqa: BLE001
        return []
    finally:
        conn.close()
    ips, ql, out = _tenant_ips(tenant_id), (q or "").lower(), []
    for r in rows:
        if r["ip"] not in ips:
            continue
        name = r["sys_name"] or r["ip"]
        if ql and ql not in f"{r['ip']} {name} {r['vendor']}".lower():
            continue
        out.append({"id": r["id"], "ip": r["ip"], "name": name, "vendor": r["vendor"] or "", "cpu": r["cpu_percent"],
                    "ram": r["memory_percent"], "temp": r["temperature_c"], "uptime_s": r["uptime_seconds"],
                    "ts": r["timestamp"] or "",
                    "state": _state(r["cpu_percent"], r["memory_percent"], r["temperature_c"]) if r["timestamp"] else "nodata"})
    out.sort(key=lambda x: (x["state"] != "warn", -(x["cpu"] or 0)))
    return out


def history(device_id, hours=24):
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - max(1, min(int(hours), 168)) * 3600))
    conn = get_nms_db()
    try:
        return [dict(r) for r in conn.execute(
            "SELECT timestamp AS ts, cpu_percent AS cpu, memory_percent AS ram, temperature_c AS temp FROM snmp_health "
            "WHERE device_id=? AND timestamp>=? ORDER BY id LIMIT 2000", (int(device_id), since))]
    except Exception:  # noqa: BLE001
        return []
    finally:
        conn.close()


def traffic_rows(tenant_id=None, q="", limit=100):
    tenant_id = resolve_tenant(tenant_id)
    conn = get_nms_db()
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT d.ip, d.sys_name, t.if_index, t.in_bps, t.out_bps, t.timestamp FROM snmp_telemetry t "
            "JOIN snmp_devices d ON d.id=t.device_id "
            "WHERE t.id IN (SELECT MAX(id) FROM snmp_telemetry GROUP BY device_id, if_index) "
            "ORDER BY (t.in_bps+t.out_bps) DESC LIMIT 2000")]
    except Exception:  # noqa: BLE001
        return []
    finally:
        conn.close()
    ips, ql = _tenant_ips(tenant_id), (q or "").lower()
    out = [{"ip": r["ip"], "name": r["sys_name"] or r["ip"], "if_index": r["if_index"], "in_bps": r["in_bps"] or 0,
            "out_bps": r["out_bps"] or 0, "ts": r["timestamp"]} for r in rows if r["ip"] in ips]
    if ql:
        out = [r for r in out if ql in f"{r['ip']} {r['name']}".lower()]
    return out[:max(1, min(int(limit), 2000))]


def overview(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    h = health_rows(tenant_id)
    return {"devices": len(h), "warn": sum(x["state"] == "warn" for x in h), "nodata": sum(x["state"] == "nodata" for x in h)}


def to_csv(kind, rows):
    cols = KINDS[kind]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([("'" + str(r.get(c, "")) if str(r.get(c, ""))[:1] in ("=", "+", "-", "@") else r.get(c, "")) for c in cols])
    return buf.getvalue()
