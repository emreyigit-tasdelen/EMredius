# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Sertleştirme: giriş kilidi politikası, 2FA zorunluluğu, oturum/denetim gözden geçirme, NetFlow kaynak IP izin listesi."""
from . import flow_acl as flow_allow

from ..core import get_db, get_nms_db, get_setting, set_setting
from ..core.auth import lock_policy

LOCK_LIMITS = {"login_lock_threshold": (3, 20, 5), "login_lock_minutes": (1, 1440, 15)}  # (min, max, varsayılan)
REVIEW_DAYS = 7


class ValidationError(ValueError):
    pass


def require_2fa():
    return get_setting("require_2fa", "0") == "1"


def get_policy():
    thr, secs = lock_policy()
    return {"login_lock_threshold": thr, "login_lock_minutes": secs // 60, "require_2fa": require_2fa()}


def save_policy(form):
    for key, (lo, hi, _d) in LOCK_LIMITS.items():
        try:
            val = int(form.get(key, ""))
        except ValueError:
            raise ValidationError("Sayısal değer girin.")
        if not lo <= val <= hi:
            raise ValidationError(f"{key}: {lo}–{hi} arasında olmalı.")
        set_setting(key, str(val))
    set_setting("require_2fa", "1" if form.get("require_2fa") else "0")


def review():
    """Son günlerin giriş olayları ve hesap güvenlik durumu."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username, role, totp_enabled, locked_until, failed_attempts, last_login, last_login_ip "
                        "FROM admin_users WHERE status = 'active' ORDER BY username")
            admins = cur.fetchall()
            cur.execute("SELECT admin_username, action, ip_address, created_at FROM admin_audit_log "
                        "WHERE action IN ('HATALI_GİRİŞ','HATALI_2FA') AND created_at >= NOW() - INTERVAL %s DAY "
                        "ORDER BY id DESC LIMIT 50", (REVIEW_DAYS,))
            failures = cur.fetchall()
            cur.execute("SELECT ip_address, COUNT(*) AS n FROM admin_audit_log WHERE action IN ('HATALI_GİRİŞ','HATALI_2FA') "
                        "AND created_at >= NOW() - INTERVAL %s DAY GROUP BY ip_address ORDER BY n DESC LIMIT 10",
                        (REVIEW_DAYS,))
            top_ips = cur.fetchall()
            cur.execute("SELECT admin_username, ip_address, created_at FROM admin_audit_log WHERE action = 'GİRİŞ' "
                        "ORDER BY id DESC LIMIT 15")
            logins = cur.fetchall()
    finally:
        conn.close()
    return {"no_2fa": [a for a in admins if not a.get("totp_enabled")],
            "locked": [a for a in admins if a.get("locked_until") and a["locked_until"] > _now_db(a["locked_until"])],
            "failures": failures, "top_ips": top_ips, "logins": logins, "days": REVIEW_DAYS,
            "admin_count": len(admins)}


def _now_db(ref):
    from datetime import datetime
    return datetime.now(ref.tzinfo) if getattr(ref, "tzinfo", None) else datetime.now()


# ---------- NetFlow kaynak IP izin listesi ----------
def _nms():
    conn = get_nms_db()
    conn.execute(flow_allow.TABLE)
    return conn


def get_flow_sources():
    conn = _nms()
    try:
        row = conn.execute("SELECT v FROM flow_acl WHERE k=?", (flow_allow.KEY,)).fetchone()
        return (row[0] if row else "") or ""
    finally:
        conn.close()


def save_flow_sources(text):
    """Boş = kısıt yok (eski davranış). Geçersiz girdi ValidationError."""
    try:
        nets = flow_allow.parse(text)
    except ValueError as e:
        raise ValidationError(f"Geçersiz IP/CIDR: {e}")
    value = ", ".join(str(n) for n in nets)
    conn = _nms()
    try:
        conn.execute("INSERT INTO flow_acl (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                     (flow_allow.KEY, value))
        conn.commit()
    finally:
        conn.close()
    return value