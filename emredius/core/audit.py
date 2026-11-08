# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Administrator audit log (MariaDB `admin_audit_log`)."""
import logging

from flask import has_request_context

from .db import get_db
from .net import get_client_ip

log = logging.getLogger(__name__)

_listeners = []  # fn(user, action, target, details, ip); SIEM yönlendirme vb. kaydeder


def add_listener(fn):
    if fn not in _listeners:
        _listeners.append(fn)


def log_audit(cur, admin_username, action, target="", details="", ip_address=None):
    """Writes one audit row with an existing cursor (joins the caller's transaction)."""
    try:
        ip = get_client_ip() if has_request_context() else (ip_address or "127.0.0.1")
        cur.execute("""
            INSERT INTO admin_audit_log (admin_username, action, target, details, ip_address)
            VALUES (%s, %s, %s, %s, %s)
        """, (admin_username or "Sistem", action, (target or "")[:128], details, ip))
    except Exception as e:
        log.error("log_audit error: %s", e)


def log_admin_action(admin_username, action, target="", details="", ip_address=""):
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                log_audit(cur, admin_username, action, target, details, ip_address)
        finally:
            conn.close()
    except Exception as e:
        log.error("log_admin_action error: %s", e)
    for fn in list(_listeners):
        try:
            fn(admin_username, action, target, details, ip_address or (get_client_ip() if has_request_context() else ""))
        except Exception as e:  # noqa: BLE001
            log.warning("audit listener error: %s", e)
