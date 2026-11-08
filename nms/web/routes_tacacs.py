# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Enterprise TACACS+ Web Management Routes and REST APIs.

Provides comprehensive management for:
- TACACS+ Clients / NAS Network Devices (IP/CIDR, shared secrets, vendor profiles)
- Users, Privilege Levels (0-15), Enable and CHAP credentials
- Regex-based Command Authorization Policy Engine & Live Policy Tester
- Real-time Command Accounting and Forensic Audit Logs with CSV Export
- Daemon status and telemetry metrics
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
from typing import Any, Dict, List, Optional

from flask import (
    Blueprint,
    Response,
    jsonify,
    request,
    session,
)

from nms.common.db import (
    DEFAULT_DB_PATH,
    get_db_connection,
    hash_password,
)
from nms.tacacs.author import RegexPolicyEngine

logger = logging.getLogger("web.tacacs")

tacacs_bp = Blueprint("tacacs_bp", __name__)


def _get_db(db_path: Optional[str] = None):
    p = db_path or os.environ.get("NMS_DB_PATH") or DEFAULT_DB_PATH
    return get_db_connection(p)


# =========================================================================
# 1. Daemon & Service Status API
# =========================================================================
@tacacs_bp.route("/api/tacacs/status", methods=["GET"])
def api_tacacs_status():
    """Returns current status and metrics of the TACACS+ daemon."""
    db_path = None
    try:
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT daemon_name, last_heartbeat, pid, status, metrics_json FROM daemon_status WHERE daemon_name = 'tacacs_daemon'"
            )
            row = cursor.fetchone()

            # Count summary totals
            cursor.execute("SELECT count(*) FROM tacacs_clients WHERE is_active = 1")
            active_clients = cursor.fetchone()[0]

            cursor.execute("SELECT count(*) FROM users WHERE enabled = 1")
            active_users = cursor.fetchone()[0]

            cursor.execute("SELECT count(*) FROM tacacs_rules")
            total_rules = cursor.fetchone()[0]

            cursor.execute("SELECT count(*) FROM tacacs_accounting")
            total_acct_logs = cursor.fetchone()[0]

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
                "port": metrics.get("port", 49),
                "active_connections": metrics.get("active_connections", 0),
                "active_sessions": metrics.get("active_sessions", 0),
                "auth_attempts": metrics.get("authen_attempts", 0),
                "auth_success": metrics.get("authen_successes", 0),
                "author_requests": metrics.get("author_requests", 0),
                "acct_packets": metrics.get("acct_packets", 0),
                "summary": {
                    "active_clients": active_clients,
                    "active_users": active_users,
                    "total_rules": total_rules,
                    "total_acct_logs": total_acct_logs,
                }
            })
        else:
            return jsonify({
                "running": False,
                "status": "STOPPED",
                "last_heartbeat": None,
                "pid": None,
                "port": 49,
                "summary": {
                    "active_clients": active_clients,
                    "active_users": active_users,
                    "total_rules": total_rules,
                    "total_acct_logs": total_acct_logs,
                }
            })
    except Exception as e:
        logger.error(f"Error reading TACACS+ daemon status: {e}")
        return jsonify({"error": str(e), "running": False}), 500


# =========================================================================
# 2. TACACS+ Clients / NAS Management API
# =========================================================================
@tacacs_bp.route("/api/tacacs/clients", methods=["GET", "POST"])
def api_tacacs_clients():
    """List or create TACACS+ network clients."""
    db_path = None
    if request.method == "GET":
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, ip_cidr, shared_secret, vendor, description, is_active, created_at FROM tacacs_clients ORDER BY id DESC"
            )
            rows = cursor.fetchall()
            clients = [dict(r) for r in rows]
        return jsonify(clients)

    # POST - Create or update client
    data = request.get_json() or request.form.to_dict()
    name = (data.get("name") or "").strip()
    ip_cidr = (data.get("ip_cidr") or "").strip()
    shared_secret = (data.get("shared_secret") or "").strip()
    vendor = (data.get("vendor") or "cisco").strip().lower()
    description = (data.get("description") or "").strip()
    is_active = 1 if str(data.get("is_active", "1")).lower() in ("1", "true", "on") else 0

    if not name or not ip_cidr or not shared_secret:
        return jsonify({"error": "name, ip_cidr, and shared_secret are required"}), 400

    try:
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO tacacs_clients (name, ip_cidr, shared_secret, vendor, description, is_active)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_cidr) DO UPDATE SET
                    name = excluded.name,
                    shared_secret = excluded.shared_secret,
                    vendor = excluded.vendor,
                    description = excluded.description,
                    is_active = excluded.is_active
                """,
                (name, ip_cidr, shared_secret, vendor, description, is_active),
            )
            conn.commit()
            client_id = cursor.lastrowid
        return jsonify({"success": True, "id": client_id, "message": "Client saved successfully"})
    except Exception as e:
        logger.error(f"Error saving TACACS+ client: {e}")
        return jsonify({"error": str(e)}), 500


@tacacs_bp.route("/api/tacacs/clients/<int:client_id>", methods=["DELETE", "POST"])
def api_tacacs_client_delete(client_id: int):
    """Delete a TACACS+ client."""
    db_path = None
    try:
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM tacacs_clients WHERE id = ?", (client_id,))
            conn.commit()
        return jsonify({"success": True, "message": "Client deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================================================================
# 3. Users & Privilege Levels (0-15) Management API
# =========================================================================
@tacacs_bp.route("/api/tacacs/users", methods=["GET", "POST"])
def api_tacacs_users():
    """List or create/update TACACS+ users."""
    db_path = None
    if request.method == "GET":
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT u.id, u.username, u.priv_lvl, u.group_id, g.name AS group_name,
                       u.enabled, u.created_at, u.updated_at,
                       CASE WHEN u.password_hash != '' THEN 1 ELSE 0 END AS has_password,
                       CASE WHEN u.enable_password_hash != '' THEN 1 ELSE 0 END AS has_enable,
                       CASE WHEN u.chap_secret != '' THEN 1 ELSE 0 END AS has_chap
                FROM users u
                LEFT JOIN groups g ON u.group_id = g.id
                ORDER BY u.id ASC
                """
            )
            rows = cursor.fetchall()
            users = [dict(r) for r in rows]
        return jsonify(users)

    # POST - Create or update user
    data = request.get_json() or request.form.to_dict()
    username = (data.get("username") or "").strip()
    password = data.get("password")
    enable_password = data.get("enable_password")
    chap_secret = (data.get("chap_secret") or "").strip()
    priv_lvl = int(data.get("priv_lvl", 1))
    group_id = data.get("group_id")
    enabled = 1 if str(data.get("enabled", "1")).lower() in ("1", "true", "on") else 0

    if not username:
        return jsonify({"error": "username is required"}), 400

    try:
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash, enable_password_hash, chap_secret FROM users WHERE username = ?", (username,))
            existing = cursor.fetchone()

            if existing:
                p_hash = hash_password(password) if password else existing["password_hash"]
                e_hash = hash_password(enable_password) if enable_password else existing["enable_password_hash"]
                c_sec = chap_secret if chap_secret else existing["chap_secret"]
                cursor.execute(
                    """
                    UPDATE users SET
                        password_hash = ?,
                        enable_password_hash = ?,
                        chap_secret = ?,
                        priv_lvl = ?,
                        group_id = ?,
                        enabled = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE username = ?
                    """,
                    (p_hash, e_hash, c_sec, priv_lvl, group_id if group_id else None, enabled, username),
                )
            else:
                p_hash = hash_password(password or username)
                e_hash = hash_password(enable_password) if enable_password else ""
                c_sec = chap_secret or ""
                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash, enable_password_hash, chap_secret, priv_lvl, group_id, enabled)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (username, p_hash, e_hash, c_sec, priv_lvl, group_id if group_id else None, enabled),
                )
            conn.commit()
        return jsonify({"success": True, "message": "User saved successfully"})
    except Exception as e:
        logger.error(f"Error saving TACACS+ user: {e}")
        return jsonify({"error": str(e)}), 500


@tacacs_bp.route("/api/tacacs/users/<int:user_id>", methods=["DELETE", "POST"])
def api_tacacs_user_delete(user_id: int):
    """Delete a user."""
    db_path = None
    try:
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
        return jsonify({"success": True, "message": "User deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================================================================
# 4. Command Authorization Rules API & Live Tester
# =========================================================================
@tacacs_bp.route("/api/tacacs/rules", methods=["GET", "POST"])
def api_tacacs_rules():
    """List or add TACACS+ command authorization rules."""
    db_path = None
    if request.method == "GET":
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT r.id, r.group_id, g.name AS group_name, r.priority, r.pattern, r.action, r.description, r.created_at
                FROM tacacs_rules r
                LEFT JOIN groups g ON r.group_id = g.id
                ORDER BY r.group_id ASC, r.priority ASC, r.id ASC
                """
            )
            rows = cursor.fetchall()
            rules = [dict(r) for r in rows]
        return jsonify(rules)

    # POST - Create rule
    data = request.get_json() or request.form.to_dict()
    group_id = int(data.get("group_id", 1))
    priority = int(data.get("priority", 100))
    pattern = (data.get("pattern") or "").strip()
    action = (data.get("action") or "deny").strip().lower()
    description = (data.get("description") or "").strip()

    if not pattern or action not in ("permit", "deny"):
        return jsonify({"error": "Valid pattern and action ('permit' or 'deny') are required"}), 400

    try:
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO tacacs_rules (group_id, priority, pattern, action, description)
                VALUES (?, ?, ?, ?, ?)
                """,
                (group_id, priority, pattern, action, description),
            )
            conn.commit()
            rule_id = cursor.lastrowid
        return jsonify({"success": True, "id": rule_id, "message": "Rule created successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@tacacs_bp.route("/api/tacacs/rules/<int:rule_id>", methods=["DELETE", "POST"])
def api_tacacs_rule_delete(rule_id: int):
    """Delete a command rule."""
    db_path = None
    try:
        with _get_db(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM tacacs_rules WHERE id = ?", (rule_id,))
            conn.commit()
        return jsonify({"success": True, "message": "Rule deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@tacacs_bp.route("/api/tacacs/rules/test", methods=["POST"])
def api_tacacs_rules_test():
    """Live regex authorization evaluation for a given username and command line."""
    db_path = os.environ.get("NMS_DB_PATH") or DEFAULT_DB_PATH
    data = request.get_json() or request.form.to_dict()
    username = (data.get("username") or "operator").strip()
    command = (data.get("command") or "").strip()
    priv_lvl = int(data.get("priv_lvl", 1))

    if not command:
        return jsonify({"error": "command is required"}), 400

    engine = RegexPolicyEngine(db_path=db_path)
    permitted, reason = engine.evaluate(username, command, user_priv=priv_lvl)
    return jsonify({
        "command": command,
        "username": username,
        "priv_lvl": priv_lvl,
        "action": "PERMITTED" if permitted else "DENIED",
        "permitted": permitted,
        "reason": reason,
    })


# =========================================================================
# 5. Real-Time Command Accounting & Forensic Audit Logs API
# =========================================================================
@tacacs_bp.route("/api/tacacs/accounting", methods=["GET"])
def api_tacacs_accounting():
    """Query searchable, filterable real-time command accounting logs."""
    db_path = None
    limit = max(1, min(request.args.get("limit", 100, type=int), 1000))
    offset = max(0, request.args.get("offset", 0, type=int))
    username = request.args.get("username", "").strip()
    device_ip = request.args.get("device_ip", "").strip()
    status = request.args.get("status", "").strip().upper()
    search = request.args.get("search", "").strip()

    query = "SELECT id, timestamp, device_ip, client_ip, username, priv_lvl, cmd, status FROM tacacs_accounting WHERE 1=1"
    params: List[Any] = []

    if username:
        query += " AND username = ?"
        params.append(username)
    if device_ip:
        query += " AND device_ip = ?"
        params.append(device_ip)
    if status in ("PERMITTED", "DENIED"):
        query += " AND status = ?"
        params.append(status)
    if search:
        query += " AND (cmd LIKE ? OR username LIKE ? OR device_ip LIKE ?)"
        pattern = f"%{search}%"
        params.extend([pattern, pattern, pattern])

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with _get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]

        # Total count for pagination
        count_query = "SELECT count(*) FROM tacacs_accounting WHERE 1=1"
        count_params = params[:-2]
        if username:
            count_query += " AND username = ?"
        if device_ip:
            count_query += " AND device_ip = ?"
        if status in ("PERMITTED", "DENIED"):
            count_query += " AND status = ?"
        if search:
            count_query += " AND (cmd LIKE ? OR username LIKE ? OR device_ip LIKE ?)"
        cursor.execute(count_query, count_params)
        total_records = cursor.fetchone()[0]

    return jsonify({
        "total": total_records,
        "limit": limit,
        "offset": offset,
        "records": rows,
    })


@tacacs_bp.route("/api/tacacs/accounting/export", methods=["GET"])
def api_tacacs_accounting_export():
    """Export accounting logs as CSV."""
    db_path = None
    with _get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT timestamp, device_ip, client_ip, username, priv_lvl, cmd, status FROM tacacs_accounting ORDER BY id DESC LIMIT 5000"
        )
        rows = cursor.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Device IP", "Client IP", "Username", "Privilege Level", "Command", "Status"])
    for r in rows:
        writer.writerow([r["timestamp"], r["device_ip"], r["client_ip"], r["username"], r["priv_lvl"], r["cmd"], r["status"]])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=tacacs_command_audit.csv"},
    )
