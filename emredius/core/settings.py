# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Panel settings stored in MariaDB `radius_settings`, with a short in-process cache."""
import hashlib
import logging
import secrets
import threading
import time

from .db import get_db, get_nms_db

log = logging.getLogger(__name__)

_CACHE_TTL = 5.0
_cache = {}
_cache_lock = threading.Lock()
_MISSING = object()


def _read(key):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT setting_value FROM radius_settings WHERE setting_key = %s", (key,))
            row = cur.fetchone()
    finally:
        conn.close()
    return row["setting_value"] if row and row["setting_value"] is not None else _MISSING


def get_setting(key, default=""):
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
    if hit and now - hit[0] < _CACHE_TTL:
        val = hit[1]
    else:
        try:
            val = _read(key)
        except Exception:
            return default
        with _cache_lock:
            _cache[key] = (now, val)
    return default if val is _MISSING else val


def set_setting(key, value):
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO radius_settings (setting_key, setting_value) VALUES (%s, %s) "
                    "ON DUPLICATE KEY UPDATE setting_value = %s", (key, value, value))
        finally:
            conn.close()
    except Exception as e:
        log.error("set_setting error: %s", e)
    finally:
        invalidate_settings(key)


def invalidate_settings(key=None):
    with _cache_lock:
        if key is None:
            _cache.clear()
        else:
            _cache.pop(key, None)


# SHA-256 of the old default token that was published with the legacy code (the token itself is not kept here)
_LEGACY_PUBLIC_API_TOKEN_SHA256 = "944dbd1807e108497f2f4c5efaa0cf2d91b2525c27e99938c4518c7953ad1c0d"


def is_legacy_public_token(tok):
    return hashlib.sha256(tok.encode("utf-8")).hexdigest() == _LEGACY_PUBLIC_API_TOKEN_SHA256


def get_api_token():
    """Returns the configured API token; a missing or publicly-known legacy token is replaced by a random one."""
    tok = get_setting("api_token", "")
    if not tok or len(tok) < 16 or is_legacy_public_token(tok):
        tok = "emr_" + secrets.token_urlsafe(32)
        set_setting("api_token", tok)
    return tok


NMS_SYNCED_KEYS = ("telegram_bot_token", "telegram_chat_id", "slack_webhook_url")


def nms_settings_sync():
    """Copies webhook settings from MariaDB (radius_settings) into the NMS SQLite table nms_settings,
    which the SNMP poller daemon reads to dispatch alarm notifications."""
    try:
        values = {k: get_setting(k, "") or "" for k in NMS_SYNCED_KEYS}
        conn = get_nms_db()
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS nms_settings (key TEXT PRIMARY KEY, value TEXT, "
                         "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
            for k, v in values.items():
                conn.execute(
                    "INSERT INTO nms_settings (key, value, updated_at) VALUES (?, ?, datetime('now','localtime')) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                    (k, v),
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        log.error("nms_settings_sync error: %s", e)


def nms_initial_settings_sync():
    """Start-up sync; skipped when MariaDB is unreachable so empty defaults never overwrite stored values."""
    try:
        conn = get_db()
        conn.close()
    except Exception as e:
        log.warning("NMS settings sync skipped (MariaDB unreachable: %s)", e)
        return
    nms_settings_sync()
