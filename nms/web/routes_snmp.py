# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Multi-Vendor SNMP NMS Web Management Routes and REST APIs.

Provides comprehensive endpoints for:
- Device Inventory (Cisco, MikroTik, Huawei, Juniper, Fortinet, HP/Aruba, Generic)
- Dual SNMPv2c / SNMPv3 USM Credential Management
- CIDR Network Auto-Discovery and Vendor Fingerprinting
- Real-time Interface Telemetry (bps, pps, errors) for Chart.js
- Device Health Gauges (CPU, RAM, Temperature, Uptime)
- Stateful Alarm Center & Telegram/Slack Webhook Integration
- SNMP Poller Daemon Heartbeat and Status
"""

from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import itertools
import json
import logging
import os
import re
import tempfile
import threading
import uuid
from typing import Any, Dict, List, Optional

from flask import (
    Blueprint,
    jsonify,
    request,
    session,
)

from nms.common.db import DEFAULT_DB_PATH, get_db_connection
from nms.snmp.webhooks import WebhookManager

logger = logging.getLogger("web.snmp")
DISCOVERY_MAX_HOSTS = 1024
DISCOVERY_BG_MAX_HOSTS = 65536

snmp_bp = Blueprint("snmp_bp", __name__)


def _get_db(db_path: Optional[str] = None):
    p = db_path or os.environ.get("NMS_DB_PATH") or DEFAULT_DB_PATH
    return get_db_connection(p)


# =========================================================================
# 1. Daemon & Poller Status API
# =========================================================================
def _port(value, default: int = 161) -> int:
    """Tolerant port parser: empty/invalid/out-of-range input falls back to the SNMP default."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    return port if 0 < port < 65536 else default


@snmp_bp.route("/api/snmp/status", methods=["GET"])
def api_snmp_status():
    """Returns SNMP poller daemon operational state and overall health metrics."""
    db_path = None
    try:
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT daemon_name, last_heartbeat, pid, status, metrics_json FROM daemon_status WHERE daemon_name IN ('snmp_daemon', 'snmp_poller') LIMIT 1"
            )
            row = cursor.fetchone()

            cursor.execute("SELECT count(*) FROM snmp_devices")
            total_devices = cursor.fetchone()[0]

            cursor.execute("SELECT count(*) FROM snmp_devices WHERE status = 'ONLINE'")
            online_devices = cursor.fetchone()[0]

            cursor.execute("SELECT count(*) FROM snmp_interfaces")
            total_interfaces = cursor.fetchone()[0]

            cursor.execute("SELECT count(*) FROM alarms WHERE resolved = 0")
            active_alarms = cursor.fetchone()[0]

        if row:
            metrics = {}
            try:
                metrics = json.loads(row["metrics_json"] or "{}")
            except Exception:
                pass
            return jsonify({
                "running": row["status"] == "RUNNING",
                "status": row["status"],
                "last_heartbeat": row["last_heartbeat"],
                "pid": row["pid"],
                "metrics": metrics,
                "summary": {
                    "total_devices": total_devices,
                    "online_devices": online_devices,
                    "offline_devices": total_devices - online_devices,
                    "total_interfaces": total_interfaces,
                    "active_alarms": active_alarms,
                }
            })
        else:
            return jsonify({
                "running": False,
                "status": "STOPPED",
                "last_heartbeat": None,
                "pid": None,
                "summary": {
                    "total_devices": total_devices,
                    "online_devices": online_devices,
                    "offline_devices": total_devices - online_devices,
                    "total_interfaces": total_interfaces,
                    "active_alarms": active_alarms,
                }
            })
    except Exception as e:
        logger.error(f"Error reading SNMP status: {e}")
        return jsonify({"error": str(e), "running": False}), 500


# =========================================================================
# 2. Device Inventory API
# =========================================================================
@snmp_bp.route("/api/snmp/devices", methods=["GET", "POST"])
def api_snmp_devices():
    """List all managed SNMP devices or create/update a device."""
    db_path = None
    if request.method == "GET":
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT d.*,
                       (SELECT count(*) FROM snmp_interfaces i WHERE i.device_id = d.id) AS interface_count,
                       (SELECT cpu_percent FROM snmp_health h WHERE h.device_id = d.id ORDER BY h.id DESC LIMIT 1) AS last_cpu,
                       (SELECT memory_percent FROM snmp_health h WHERE h.device_id = d.id ORDER BY h.id DESC LIMIT 1) AS last_ram,
                       (SELECT uptime_seconds FROM snmp_health h WHERE h.device_id = d.id ORDER BY h.id DESC LIMIT 1) AS last_uptime
                FROM snmp_devices d
                ORDER BY d.id DESC
                """
            )
            rows = cursor.fetchall()
            devices = [dict(r) for r in rows]
        return jsonify(devices)

    # POST - Create or update device
    data = request.get_json() or request.form.to_dict()
    ip = (data.get("ip") or "").strip()
    port = _port(data.get("port"))
    version = (data.get("version") or "v2c").strip().lower()
    community = (data.get("community") or "public").strip()
    v3_user = (data.get("v3_user") or "").strip()
    v3_auth_proto = (data.get("v3_auth_proto") or "").strip()
    v3_auth_key = (data.get("v3_auth_key") or "").strip()
    v3_priv_proto = (data.get("v3_priv_proto") or "").strip()
    v3_priv_key = (data.get("v3_priv_key") or "").strip()
    vendor = (data.get("vendor") or "Generic").strip()
    sys_name = (data.get("sys_name") or "").strip()
    sys_descr = (data.get("sys_descr") or "").strip()

    if not ip or version not in ("v2c", "v3"):
        return jsonify({"error": "Valid IP and SNMP version ('v2c' or 'v3') are required"}), 400

    try:
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO snmp_devices (
                    ip, port, version, community, v3_user, v3_auth_proto, v3_auth_key,
                    v3_priv_proto, v3_priv_key, vendor, sys_name, sys_descr, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ONLINE')
                ON CONFLICT(ip) DO UPDATE SET
                    port = excluded.port,
                    version = excluded.version,
                    community = excluded.community,
                    v3_user = excluded.v3_user,
                    v3_auth_proto = excluded.v3_auth_proto,
                    v3_auth_key = excluded.v3_auth_key,
                    v3_priv_proto = excluded.v3_priv_proto,
                    v3_priv_key = excluded.v3_priv_key,
                    vendor = excluded.vendor,
                    sys_name = CASE WHEN excluded.sys_name != '' THEN excluded.sys_name ELSE snmp_devices.sys_name END,
                    sys_descr = CASE WHEN excluded.sys_descr != '' THEN excluded.sys_descr ELSE snmp_devices.sys_descr END
                """,
                (ip, port, version, community, v3_user, v3_auth_proto, v3_auth_key,
                 v3_priv_proto, v3_priv_key, vendor, sys_name, sys_descr),
            )
            conn.commit()
            dev_id = cursor.lastrowid
        return jsonify({"success": True, "id": dev_id, "message": "Device saved successfully"})
    except Exception as e:
        logger.error(f"Error saving SNMP device: {e}")
        return jsonify({"error": str(e)}), 500


@snmp_bp.route("/api/snmp/devices/<int:device_id>", methods=["DELETE", "POST"])
def api_snmp_device_delete(device_id: int):
    """Delete a managed SNMP device."""
    db_path = None
    try:
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM snmp_devices WHERE id = ?", (device_id,))
            conn.commit()
        return jsonify({"success": True, "message": "Device deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================================================================
# 3. Interfaces & Real-Time Telemetry API (Chart.js)
# =========================================================================
@snmp_bp.route("/api/snmp/devices/<int:device_id>/interfaces", methods=["GET"])
def api_snmp_device_interfaces(device_id: int):
    """Returns interfaces for a given device."""
    db_path = None
    with _get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, device_id, if_index, if_descr, if_name, if_type, if_speed,
                   if_admin_status, if_oper_status, if_mac, last_updated
            FROM snmp_interfaces
            WHERE device_id = ?
            ORDER BY if_index ASC
            """,
            (device_id,),
        )
        interfaces = [dict(r) for r in cursor.fetchall()]
    return jsonify(interfaces)


@snmp_bp.route("/api/snmp/telemetry/<int:device_id>/<int:if_index>", methods=["GET"])
def api_snmp_telemetry(device_id: int, if_index: int):
    """Returns time-series telemetry points for Chart.js bandwidth visualization."""
    db_path = None
    limit = max(1, min(request.args.get("limit", 60, type=int), 300))

    with _get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, in_bps, out_bps, in_pps, out_pps, in_errors, out_errors
            FROM snmp_telemetry
            WHERE device_id = ? AND if_index = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (device_id, if_index, limit),
        )
        rows = [dict(r) for r in cursor.fetchall()]

    # Reverse so the oldest is first (chronological order for Chart.js)
    rows.reverse()
    return jsonify({
        "device_id": device_id,
        "if_index": if_index,
        "points": rows,
    })


@snmp_bp.route("/api/snmp/health/<int:device_id>", methods=["GET"])
def api_snmp_device_health(device_id: int):
    """Returns recent health statistics (CPU %, Memory %, Temp, Uptime) for a device."""
    db_path = None
    with _get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, cpu_percent, memory_percent, temperature_c, uptime_seconds
            FROM snmp_health
            WHERE device_id = ?
            ORDER BY id DESC
            LIMIT 30
            """,
            (device_id,),
        )
        rows = [dict(r) for r in cursor.fetchall()]
    rows.reverse()
    return jsonify({"device_id": device_id, "health": rows})


# =========================================================================
# 4. CIDR Auto-Discovery API
# =========================================================================
def _job_path(job_id: str) -> str:
    return os.path.join(tempfile.gettempdir(), f"emredius_disc_{job_id}.json")


def _write_job(job_id: str, payload: Dict[str, Any]) -> None:
    # File-backed so any gunicorn worker can answer the status poll.
    tmp = _job_path(job_id) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    os.replace(tmp, _job_path(job_id))


DISCOVERY_CHUNK = 4096


def _iter_chunks(cidr: str):
    """Lazy IPv4 host chunks of a CIDR / IP list (a /0 is never materialised)."""
    for token in cidr.replace("\n", ",").replace(";", ",").split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            ips = [str(i) for i in _range_ips(token)]
            for i in range(0, len(ips), DISCOVERY_CHUNK):
                yield ips[i:i + DISCOVERY_CHUNK]
            continue
        net = ipaddress.ip_network(token, strict=False)
        if net.version != 4:
            continue
        hosts = net.hosts() if net.prefixlen < 31 else iter(net)
        while True:
            chunk = [str(h) for h in itertools.islice(hosts, DISCOVERY_CHUNK)]
            if not chunk:
                break
            yield chunk


def _range_ips(token: str):
    a, b = [p.strip() for p in token.split("-", 1)]
    if "." not in b:
        b = ".".join(a.split(".")[:3] + [b])
    return [ipaddress.IPv4Address(i) for i in range(int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b)) + 1)]


def _count_targets(cidr: str) -> int:
    total = 0
    for token in cidr.replace("\n", ",").replace(";", ",").split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            total += len(_range_ips(token))
            continue
        net = ipaddress.ip_network(token, strict=False)
        if net.version == 4:
            total += max(net.num_addresses - 2, 1) if net.prefixlen < 31 else net.num_addresses
    return total


def _run_scan_job(job_id: str, cidr: str, config: Any, scan_network: Any, total: int) -> None:
    loop = asyncio.new_event_loop()
    devices: List[Dict[str, Any]] = []
    done = 0
    cancelled = False
    try:
        for chunk in _iter_chunks(cidr):
            if os.path.exists(_job_path(job_id) + ".cancel"):
                cancelled = True
                break
            res = loop.run_until_complete(scan_network(dataclasses.replace(config, targets=chunk)))
            devices.extend({"ip": d.ip, "vendor": d.vendor, "sys_name": d.sys_name, "sys_descr": d.sys_descr,
                            "sys_object_id": d.sys_object_id, "interfaces_count": len(d.interfaces)}
                           for d in res.discovered_devices)
            done += len(chunk)
            _write_job(job_id, {"status": "running", "cidr": cidr, "total": total, "done": done,
                                "total_found": len(devices)})
        _write_job(job_id, {"status": "done", "success": True, "cidr": cidr, "cancelled": cancelled,
                            "total": total, "done": done, "total_found": len(devices), "devices": devices})
    except Exception as e:
        logger.error(f"Discovery job error: {e}")
        _write_job(job_id, {"status": "error", "error": str(e)})
    finally:
        loop.close()
        try:
            os.remove(_job_path(job_id) + ".cancel")
        except OSError:
            pass


@snmp_bp.route("/api/snmp/discovery/scan/<job_id>", methods=["DELETE"])
def api_snmp_discovery_scan_cancel(job_id: str):
    if not re.fullmatch(r"[0-9a-f]{32}", job_id) or not os.path.exists(_job_path(job_id)):
        return jsonify({"error": "job not found"}), 404
    open(_job_path(job_id) + ".cancel", "w").close()
    return jsonify({"success": True})


@snmp_bp.route("/api/snmp/discovery/scan/<job_id>", methods=["GET"])
def api_snmp_discovery_scan_status(job_id: str):
    if not re.fullmatch(r"[0-9a-f]{32}", job_id):
        return jsonify({"error": "invalid job"}), 400
    try:
        with open(_job_path(job_id), encoding="utf-8") as fh:
            return jsonify(json.load(fh))
    except FileNotFoundError:
        return jsonify({"error": "job not found"}), 404


@snmp_bp.route("/api/snmp/discovery/scan", methods=["POST"])
def api_snmp_discovery_scan():
    """Asynchronous CIDR network discovery scan."""
    data = request.get_json() or request.form.to_dict()
    cidr = (data.get("cidr") or "").strip()
    community = (data.get("community") or "public").strip()
    port = _port(data.get("port"))
    db_path = os.environ.get("NMS_DB_PATH") or DEFAULT_DB_PATH

    if not cidr:
        return jsonify({"error": "CIDR target is required (e.g. 192.168.1.0/24)"}), 400

    try:
        from nms.snmp.discovery import DiscoveryScanConfig, parse_targets, scan_network

        # Up to a /22 runs inside the web request (gunicorn timeout 120 s); up to a /16 runs as a background job.
        # The superadmin has no size limit (0.0.0.0/0 included).
        is_super = session.get("role") == "superadmin"
        if is_super:
            count = _count_targets(cidr)
        else:
            count = len(parse_targets(cidr, max_hosts=DISCOVERY_BG_MAX_HOSTS + 1))
            if count > DISCOVERY_BG_MAX_HOSTS:
                return jsonify({"error": f"En fazla {DISCOVERY_BG_MAX_HOSTS} adres taranabilir (/16)"}), 400

        # persist_db=False: found devices are only listed; the operator adds them with "Envantere Ekle".
        config = DiscoveryScanConfig(targets=cidr, port=port, v2c_communities=[community],
                                     timeout=1.0, persist_db=False, db_path=db_path)
        if count > DISCOVERY_MAX_HOSTS:
            config.concurrency = 256
            job_id = uuid.uuid4().hex
            _write_job(job_id, {"status": "running", "cidr": cidr, "total": count})
            threading.Thread(target=_run_scan_job, args=(job_id, cidr, config, scan_network, count),
                             daemon=True).start()
            return jsonify({"success": True, "job_id": job_id, "total": count}), 202
        loop = asyncio.new_event_loop()
        try:
            discovered = loop.run_until_complete(scan_network(config)).discovered_devices
        finally:
            loop.close()

        results = []
        for dev in discovered:
            results.append({
                "ip": dev.ip,
                "vendor": dev.vendor,
                "sys_name": dev.sys_name,
                "sys_descr": dev.sys_descr,
                "sys_object_id": dev.sys_object_id,
                "interfaces_count": len(dev.interfaces),
            })

        return jsonify({
            "success": True,
            "cidr": cidr,
            "total_found": len(results),
            "devices": results,
        })
    except Exception as e:
        logger.error(f"Discovery scan error: {e}")
        return jsonify({"error": str(e)}), 500


# =========================================================================
# 5. Alarm Center & Webhook Dispatcher API
# =========================================================================
@snmp_bp.route("/api/snmp/alarms", methods=["GET"])
def api_snmp_alarms():
    """List alarms with active/resolved filtering."""
    db_path = None
    active_only = request.args.get("active_only", "1") == "1"
    limit = max(1, min(request.args.get("limit", 100, type=int), 500))

    query = """
        SELECT a.id, a.timestamp, a.device_id, d.ip AS device_ip, d.sys_name,
               a.if_index, a.alarm_type, a.severity, a.message, a.resolved, a.resolved_at
        FROM alarms a
        LEFT JOIN snmp_devices d ON a.device_id = d.id
    """
    if active_only:
        query += " WHERE a.resolved = 0"
    query += " ORDER BY a.id DESC LIMIT ?"

    with _get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, (limit,))
        rows = [dict(r) for r in cursor.fetchall()]

    return jsonify(rows)


@snmp_bp.route("/api/snmp/alarms/<int:alarm_id>/ack", methods=["POST"])
def api_snmp_alarm_ack(alarm_id: int):
    """Acknowledge and mark an alarm as resolved."""
    db_path = None
    try:
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE alarms SET resolved = 1, resolved_at = CURRENT_TIMESTAMP WHERE id = ?",
                (alarm_id,),
            )
            conn.commit()
        return jsonify({"success": True, "message": "Alarm marked as resolved"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@snmp_bp.route("/api/snmp/webhooks/test", methods=["POST"])
def api_snmp_webhooks_test():
    """Sends a test webhook to configured Telegram/Slack channels."""
    data = request.get_json() or request.form.to_dict()
    channel = data.get("channel", "all")  # "telegram", "slack", "all"
    tg_token = data.get("telegram_bot_token", "").strip()
    tg_chat = data.get("telegram_chat_id", "").strip()
    slack_url = data.get("slack_webhook_url", "").strip()

    mgr = WebhookManager(
        telegram_token=tg_token or None,
        telegram_chat_id=tg_chat or None,
        slack_webhook_url=slack_url or None,
    )

    loop = asyncio.new_event_loop()
    try:
        results = loop.run_until_complete(
            mgr.dispatch_alarm(
                device_id=0,
                device_name="Test Router",
                device_ip="192.168.1.1",
                alarm_type="MANUAL_TEST",
                severity="WARNING",
                message="Enterprise TACACS+ & SNMP NMS Webhook Test Mesajı",
            )
        )
    finally:
        loop.close()

    return jsonify({"success": True, "results": results})
