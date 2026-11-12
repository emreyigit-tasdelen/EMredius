# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Login (password + optional TOTP 2FA), logout, session heartbeat."""
import time

from flask import flash, jsonify, redirect, render_template, request, session

from ...core import (authenticate_admin, csrf_token, get_client_ip, get_db, is_ip_locked, log_admin_action,
                     record_failed_login, record_successful_login, url_for, verify_totp_token)
from . import bp

TWOFA_TIMEOUT_SECONDS = 300
TWOFA_MAX_FAILS = 5


def _establish_session(user_data):
    session.clear()
    session.permanent = True
    session["logged_in"] = True
    session["user"] = user_data["username"]
    session["role"] = user_data["role"]
    session["role_label"] = user_data["role_label"]
    session["auth_type"] = user_data["auth_type"]
    session["full_name"] = user_data["full_name"]
    session["support_popup"] = True  # her girişte bir kez destek penceresi
    csrf_token()


def _fetch_admin(username, columns):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(f"SELECT {columns} FROM admin_users WHERE username = %s", (username,))
            return cur.fetchone()
    finally:
        conn.close()


def _flag_2fa_required():
    """Sertleştirme > '2FA zorunlu' açıksa 2FA'sı olmayan oturum, kurulum yapana dek kısıtlanır (security_gate)."""
    from ...services import hardening
    if hardening.require_2fa():
        session["must_2fa"] = True


@bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    client_ip = get_client_ip()
    if is_ip_locked(client_ip):
        flash("Güvenlik Kilidi: Çok fazla başarısız deneme nedeniyle bu IP geçici olarak engellendi.", "danger")
        return render_template("auth/login.html")

    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = (request.form.get("password") or "").strip()
        if not u or not p or len(u) > 64:
            flash("Kullanıcı adı ve şifre zorunludur!", "danger")
            return redirect(url_for("login"))

        success, msg, user_data = authenticate_admin(u, p, client_ip)
        if not success:
            record_failed_login(client_ip)
            flash(msg, "danger")
            return render_template("auth/login.html")

        row = _fetch_admin(u, "totp_secret, totp_enabled") or {}
        if row.get("totp_enabled") and row.get("totp_secret"):
            session.clear()
            session["pending_2fa_user"] = u
            session["pending_user_data"] = user_data
            session["pending_client_ip"] = client_ip
            session["pending_2fa_at"] = time.time()
            session["pending_2fa_fails"] = 0
            return redirect(url_for("login_2fa"))

        record_successful_login(client_ip)
        _establish_session(user_data)
        _flag_2fa_required()
        flash(f"Hoş geldiniz, {user_data['full_name']}! ({user_data['role_label']})", "success")
        return redirect(url_for("dashboard"))

    return render_template("auth/login.html")


@bp.route("/login/2fa", methods=["GET", "POST"])
@bp.route("/login-2fa", methods=["GET", "POST"])
def login_2fa():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    if "pending_2fa_user" not in session or "pending_user_data" not in session:
        return redirect(url_for("login"))

    u = session["pending_2fa_user"]
    user_data = session["pending_user_data"]
    client_ip = get_client_ip()

    if time.time() - float(session.get("pending_2fa_at") or 0) > TWOFA_TIMEOUT_SECONDS:
        session.clear()
        flash("2FA doğrulama süresi doldu. Lütfen tekrar giriş yapın.", "warning")
        return redirect(url_for("login"))

    if is_ip_locked(client_ip):
        session.clear()
        flash("Güvenlik Kilidi: Çok fazla başarısız deneme nedeniyle bu IP geçici olarak engellendi.", "danger")
        return redirect(url_for("login"))

    row = _fetch_admin(u, "totp_secret, status")
    if not row or row.get("status") != "active":
        session.clear()
        flash("Hesabınız aktif değil.", "danger")
        return redirect(url_for("login"))
    totp_secret = row.get("totp_secret")

    if not totp_secret:
        # 2FA was switched off meanwhile
        _establish_session(user_data)
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        token = (request.form.get("token") or "").strip().replace(" ", "")
        if verify_totp_token(totp_secret, token):
            record_successful_login(client_ip)
            _establish_session(user_data)
            flash(f"İki Adımlı Doğrulama Başarılı! Hoş geldiniz, {user_data['full_name']}!", "success")
            return redirect(url_for("dashboard"))
        record_failed_login(client_ip)
        fails = int(session.get("pending_2fa_fails") or 0) + 1
        session["pending_2fa_fails"] = fails
        log_admin_action(u, "HATALI_2FA", "Web Paneli", f"Hatalı 2FA kodu ({fails}/{TWOFA_MAX_FAILS})", client_ip)
        if fails >= TWOFA_MAX_FAILS:
            session.clear()
            flash("Çok fazla hatalı 2FA denemesi. Lütfen tekrar giriş yapın.", "danger")
            return redirect(url_for("login"))
        flash("Hatalı veya süresi geçmiş 2FA doğrulama kodu! Lütfen Authenticator uygulamanızı kontrol edin.", "danger")

    return render_template("auth/login_2fa.html", pending_user=u)


@bp.route("/api/session/heartbeat")
def session_heartbeat():
    if session.get("logged_in") and "user" in session:
        session.modified = True  # re-issues the cookie -> extends the 30 min lifetime
        return jsonify({"status": "ok", "user": session.get("user")})
    return jsonify({"status": "expired"}), 401


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
