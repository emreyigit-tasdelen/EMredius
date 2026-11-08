# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""TACACS+ page data from the NMS SQLite database (the CRUD APIs live in the NMS tacacs blueprint)."""
import json
import logging

from ..core import tenant as tn
from ..core import daemon_alive, format_seconds, get_nms_db, safe_int

log = logging.getLogger(__name__)


def daemon_metrics(status_row):
    """daemon_status.metrics_json parsed defensively (never raises)."""
    try:
        m = json.loads((status_row["metrics_json"] if status_row else None) or "{}")
        return m if isinstance(m, dict) else {}
    except (TypeError, ValueError, KeyError, IndexError):
        return {}


def daemon_state(status_row, default_port):
    """Status card values; a daemon only counts as running while its heartbeat is fresh."""
    running = daemon_alive(status_row)
    stale = bool(status_row) and status_row["status"] == "RUNNING" and not running
    m = daemon_metrics(status_row)
    port = safe_int(m.get("port"), default_port)
    if running:
        color, text = "#16a34a", f"ÇALIŞIYOR (Port {port})"
    elif stale:
        color, text = "#f59e0b", "YANIT VERMİYOR"
    else:
        color, text = "#dc2626", "DURDURULDU"
    try:
        uptime = format_seconds(int(float(m.get("uptime_seconds") or 0))) if running else "-"
    except (TypeError, ValueError):
        uptime = "-"
    return {
        "running": running, "color": color, "text": text, "uptime": uptime, "metrics": m,
        "last_heartbeat": (status_row["last_heartbeat"] if status_row and status_row["last_heartbeat"] else "-"),
        "active_sessions": safe_int(m.get("active_sessions"), 0) if running else 0,
    }


_VENDOR_COLORS = {"cisco": "#3b82f6", "mikrotik": "#10b981"}


def _client_view(c):
    vendor = str(c.get("vendor") or "cisco").strip().lower()
    return {"id": safe_int(c.get("id"), 0), "name": str(c.get("name") or ""), "ip": c.get("ip_cidr") or "",
            "secret": c.get("shared_secret") or "", "vendor": vendor.upper(),
            "color": _VENDOR_COLORS.get(vendor, "#8b5cf6"), "active": safe_int(c.get("is_active"), 1) != 0}


def _user_view(u):
    priv = safe_int(u.get("priv_lvl"), 1)
    uid = safe_int(u.get("id"), 0)
    name = str(u.get("username") or "")
    return {"id": uid, "name": name, "priv": priv,
            "priv_color": "#dc2626" if priv >= 15 else ("#f59e0b" if priv >= 7 else "#10b981"),
            "group": u.get("group_name") or "-", "has_enable": bool(u.get("enable_password_hash")),
            "has_chap": bool(u.get("chap_secret")), "enabled": safe_int(u.get("enabled"), 1) != 0,
            "protected": uid == 1 or name.lower() == "admin"}


def _rule_view(r):
    return {"id": safe_int(r.get("id"), 0), "group": r.get("group_name") or "Genel", "priority": safe_int(r.get("priority"), 0),
            "pattern": r.get("pattern") or "", "permit": str(r.get("action") or "").strip().lower() == "permit",
            "description": r.get("description") or "-"}


def _acct_view(a):
    return {"ts": a.get("timestamp") or "-", "device_ip": a.get("device_ip") or "-", "client_ip": a.get("client_ip") or "-",
            "username": a.get("username") or "-", "cmd": a.get("cmd") or "-", "priv": safe_int(a.get("priv_lvl"), 1),
            "permitted": str(a.get("status") or "").strip().upper() == "PERMITTED"}


def page_data():
    """Returns (data, error_message_or_None)."""
    status, clients, users, groups, rules, acct, acct_total = None, [], [], [], [], [], 0
    error = None
    try:
        conn = get_nms_db()
        try:
            cur = conn.cursor()
            cur.execute("SELECT * FROM daemon_status WHERE daemon_name = 'tacacs_daemon'")
            status = cur.fetchone()
            cur.execute("SELECT * FROM tacacs_clients ORDER BY id DESC")
            clients = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT u.*, g.name AS group_name FROM users u LEFT JOIN groups g ON u.group_id = g.id "
                        "ORDER BY u.id ASC")
            users = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT * FROM groups ORDER BY priv_lvl DESC")
            groups = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT r.*, g.name AS group_name FROM tacacs_rules r LEFT JOIN groups g ON r.group_id = g.id "
                        "ORDER BY r.group_id ASC, r.priority ASC, r.id ASC")
            rules = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT * FROM tacacs_accounting ORDER BY id DESC LIMIT 50")
            acct = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT count(*) FROM tacacs_accounting")
            acct_total = cur.fetchone()[0] or 0
        finally:
            conn.close()
    except Exception as e:
        log.error("tacacs page NMS DB error: %s", e)
        error = f"TACACS+ veritabanı okuma hatası: {e}"
        status, clients, users, groups, rules, acct, acct_total = None, [], [], [], [], [], 0
    clients = tn.filter_owned("tacacs_client", clients, lambda c: c.get("ip_cidr"))
    users = tn.filter_owned("tacacs_user", users, lambda u: u.get("username"))
    user_views = [_user_view(u) for u in users]
    return {
        "daemon": daemon_state(status, 49),
        "clients": [_client_view(c) for c in clients],
        "users": user_views,
        "groups": [{"id": safe_int(g.get("id"), 0), "name": g.get("name") or "Grup", "priv": safe_int(g.get("priv_lvl"), 1)}
                   for g in groups],
        "rules": [_rule_view(r) for r in rules],
        "acct_logs": [_acct_view(a) for a in acct],
        "acct_total": acct_total,
        "enabled_user_count": sum(1 for u in user_views if u["enabled"]),
    }, error
