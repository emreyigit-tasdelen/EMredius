# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Global request security: session revalidation, NMS API access, CSRF, read-only roles, response headers
and error pages."""
import hmac
import logging
from urllib.parse import urlparse

import pymysql

from flask import flash, jsonify, redirect, request, session
from werkzeug.exceptions import HTTPException

from .auth import ROLE_LABELS
from .db import get_db
from .rbac import can_access_page, is_read_only_role, wants_json
from .web import url_for

log = logging.getLogger(__name__)

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_EXEMPT_PREFIXES = ("/login", "/api/v1/", "/static/")
READ_ONLY_ALLOWED_PREFIXES = ("/profile/change-password", "/profile/2fa/", "/api/session/heartbeat", "/logout",
                              "/set-lang/", "/api/notifications")
MUST_2FA_ALLOWED_PREFIXES = ("/profile", "/logout", "/api/session/heartbeat", "/set-lang/", "/static/")
NMS_API_PAGE_MAP = (("/api/tacacs/", "tacacs"), ("/api/snmp/", "snmp"))


def _revalidate_session():
    """Re-checks a logged-in session against admin_users on every request: deleted/disabled accounts are logged
    out immediately and role changes apply without re-login."""
    username = session.get("user")
    if not username:
        return False
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT role, status FROM admin_users WHERE username = %s", (username,))
                row = cur.fetchone()
        finally:
            conn.close()
    except Exception as e:
        log.warning("session revalidation skipped (DB error: %s)", e)
        return True  # DB hiccup: do not lock everybody out
    if not row or row.get("status") != "active":
        return False
    db_role = row.get("role") or "network_admin"
    if session.get("role") != db_role:
        session["role"] = db_role
        session["role_label"] = ROLE_LABELS.get(db_role, db_role)
    return True


def _totp_enabled(username):
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT totp_enabled FROM admin_users WHERE username = %s", (username,))
                row = cur.fetchone()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        return True  # DB hiccup: do not trap the user
    return bool(row and row.get("totp_enabled"))


def _safe_referrer():
    """Referer only when it points at this host (no open redirect through a forged Referer)."""
    ref = request.referrer or ""
    try:
        if ref and urlparse(ref).netloc == request.host:
            return ref
    except ValueError:
        pass
    return None


def _back():
    return redirect(_safe_referrer() or url_for("dashboard"))


def security_gate():
    path = request.path or "/"
    if path.startswith("/static/"):
        return None

    # 1) Session revalidation
    if session.get("logged_in") and not _revalidate_session():
        session.clear()
        if wants_json():
            return jsonify({"success": False, "error": "Oturum sonlandırıldı."}), 401
        flash("Hesabınız devre dışı bırakıldığı veya silindiği için oturumunuz sonlandırıldı.", "warning")
        return redirect(url_for("login"))

    # 1b) Sertleştirme: '2FA zorunlu' iken 2FA'sı olmayan oturum yalnızca profil/2FA kurulumuna gidebilir
    if session.get("logged_in") and session.get("must_2fa"):
        if _totp_enabled(session.get("user")):
            session.pop("must_2fa", None)
        elif not path.startswith(MUST_2FA_ALLOWED_PREFIXES):
            if wants_json():
                return jsonify({"success": False, "error": "Önce 2FA kurulumunu tamamlayın."}), 403
            flash("Güvenlik politikası gereği önce İki Adımlı Doğrulama (2FA) kurulumunu tamamlamalısınız.", "warning")
            return redirect("/profile/2fa/setup")

    # 2) TACACS+ / SNMP REST APIs (NMS blueprints) require a session with page permission
    for prefix, page in NMS_API_PAGE_MAP:
        if path.startswith(prefix):
            if not session.get("logged_in"):
                return jsonify({"success": False, "error": "Oturum gerekli."}), 401
            if not can_access_page(page):
                return jsonify({"success": False, "error": "Bu işlem için yetkiniz bulunmamaktadır."}), 403
            break

    if request.method in UNSAFE_METHODS:
        # 3) CSRF
        if not path.startswith(CSRF_EXEMPT_PREFIXES):
            sent = request.headers.get("X-CSRF-Token") or request.form.get("_csrf_token") or ""
            expected = session.get("_csrf_token") or ""
            if not sent or not expected or not hmac.compare_digest(str(sent), str(expected)):
                if wants_json() or request.headers.get("X-CSRF-Token") is not None:
                    return jsonify({"success": False,
                                    "error": "CSRF doğrulaması başarısız. Sayfayı yenileyip tekrar deneyin."}), 400
                flash("Güvenlik doğrulaması (CSRF) başarısız oldu. Sayfayı yenileyip tekrar deneyin.", "danger")
                return _back()
        # 4) Read-only roles can never mutate state
        if session.get("logged_in") and is_read_only_role() and not path.startswith(READ_ONLY_ALLOWED_PREFIXES):
            if wants_json():
                return jsonify({"success": False, "error": "Salt okunur rol bu işlemi yapamaz."}), 403
            flash("Salt okunur (Denetçi) rolü değişiklik yapamaz.", "danger")
            return _back()
    return None


def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    resp.headers.setdefault("Content-Security-Policy",
                            "script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
    if request.is_secure:
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    if resp.mimetype == "text/html":
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


_ERROR_PAGE = """<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><title>{code} - EMredius</title>
<style>body{{margin:0;font-family:system-ui,sans-serif;background:#0f172a;color:#f8fafc;display:flex;
align-items:center;justify-content:center;min-height:100vh}}.c{{text-align:center}}h1{{font-size:3rem;margin:0}}
a{{color:#60a5fa}}</style></head><body><div class="c"><h1>{code}</h1><p>{message}</p>
<p><a href="/">Ana sayfaya dön</a></p></div></body></html>"""

_ERROR_MESSAGES = {
    400: "Geçersiz istek.",
    403: "Bu işlem için yetkiniz bulunmamaktadır.",
    404: "Sayfa bulunamadı.",
    405: "Bu adres bu yöntemle çağrılamaz.",
    413: "Yüklenen dosya çok büyük.",
    500: "Beklenmeyen bir sunucu hatası oluştu. Ayrıntılar sistem günlüğüne yazıldı.",
    503: "Veritabanına şu an ulaşılamıyor. Birkaç saniye sonra sayfayı yenileyin.",
}


def _error_response(code):
    message = _ERROR_MESSAGES.get(code, "Hata.")
    if wants_json():
        return jsonify({"success": False, "error": message}), code
    return _ERROR_PAGE.format(code=code, message=message), code


def handle_http_error(e):
    return _error_response(e.code or 500)


def handle_unexpected_error(e):
    if isinstance(e, HTTPException):
        return handle_http_error(e)
    if isinstance(e, pymysql.err.OperationalError):  # MariaDB down / unreachable: no stack trace, 503
        log.error("database unavailable on %s %s: %s", request.method, request.path, e)
        return _error_response(503)
    log.exception("unhandled error on %s %s", request.method, request.path)
    return _error_response(500)


def init_app(app):
    app.before_request(security_gate)
    app.after_request(security_headers)
    for code in _ERROR_MESSAGES:
        if code != 500:
            app.register_error_handler(code, handle_http_error)
    app.register_error_handler(Exception, handle_unexpected_error)
