# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared core layer (no routes). Blueprints import what they need from here."""
from .audit import log_admin_action, log_audit
from .auth import (ROLE_LABELS, authenticate_admin, get_role_display, get_system_linux_users, is_ip_locked,
                   record_failed_login, record_successful_login, verify_system_password)
from .csrf import csrf_input, csrf_token
from .db import connect_direct, get_db, get_nms_db
from .escaping import esc, esc_js, json_script, url_seg
from .net import get_client_ip, get_server_ip, ping_host
from .notify import send_alert
from .rbac import (PAGE_DEFINITIONS, READ_ONLY_ROLES, SUPERADMIN_ONLY_PAGES, VALID_PAGE_KEYS, api_auth_required,
                   can_access_page, get_role_permissions, is_read_only_role, login_required, require_page,
                   wants_json)
from .settings import get_api_token, get_setting, invalidate_settings, nms_settings_sync, set_setting
from .system import (daemon_alive, format_bytes, format_seconds, get_radiusd_status, invalidate_radiusd_status,
                     is_dry_run, restart_radiusd_async, run_cmd)
from .totp import generate_totp_secret, get_totp_token, get_totp_uri, verify_totp_token
from .validators import (GROUPNAME_RE, MAC_RE, OUI_DATABASE, RATE_LIMIT_RE, USERNAME_RE, is_valid_ip,
                         is_valid_vlan, lookup_mac_vendor, normalize_mac, safe_int)
from .web import local_referrer, render_page, url_for

__all__ = [
    "log_admin_action", "log_audit",
    "ROLE_LABELS", "authenticate_admin", "get_role_display", "get_system_linux_users", "is_ip_locked",
    "record_failed_login", "record_successful_login", "verify_system_password",
    "csrf_input", "csrf_token",
    "connect_direct", "get_db", "get_nms_db",
    "esc", "esc_js", "json_script", "url_seg",
    "get_client_ip", "get_server_ip", "ping_host",
    "send_alert",
    "PAGE_DEFINITIONS", "READ_ONLY_ROLES", "SUPERADMIN_ONLY_PAGES", "VALID_PAGE_KEYS", "api_auth_required",
    "can_access_page", "get_role_permissions", "is_read_only_role", "login_required", "require_page", "wants_json",
    "get_api_token", "get_setting", "invalidate_settings", "nms_settings_sync", "set_setting",
    "daemon_alive", "format_bytes", "format_seconds", "get_radiusd_status", "invalidate_radiusd_status",
    "is_dry_run", "restart_radiusd_async", "run_cmd",
    "generate_totp_secret", "get_totp_token", "get_totp_uri", "verify_totp_token",
    "GROUPNAME_RE", "MAC_RE", "OUI_DATABASE", "RATE_LIMIT_RE", "USERNAME_RE", "is_valid_ip", "is_valid_vlan",
    "lookup_mac_vendor", "normalize_mac", "safe_int",
    "local_referrer", "render_page", "url_for",
]
