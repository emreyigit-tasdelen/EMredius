# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Superadmin security centre (/security: 2FA + password resets), host telemetry APIs and the root CA download."""
import base64
import os
from datetime import datetime

from flask import Response, current_app, flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, login_required, require_page, url_for
from ...services import admins as admin_svc
from ...services import telemetry
from . import bp


def _back():
    return redirect(url_for("security_page"))


@bp.route("/download/ca.crt")
def download_ca_crt():
    path = current_app.config["CA_CERT_PATH"]
    if not os.path.isfile(path):
        return Response("Sertifika dosyası bulunamadı.", status=404, mimetype="text/plain")
    with open(path, "rb") as f:
        data = f.read()
    return Response(data, mimetype="application/x-x509-ca-cert",
                    headers={"Content-Disposition": "attachment; filename=FreeRADIUS-Enterprise-RootCA.crt"})


@bp.route("/download/ca-install.bat")
def download_ca_install_bat():
    path = current_app.config["CA_CERT_PATH"]
    if not os.path.isfile(path):
        return Response("Sertifika dosyası bulunamadı.", status=404, mimetype="text/plain")
    with open(path, "rb") as f:
        b64 = base64.b64encode(f.read()).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    bat = ["@echo off", "set CRT=%TEMP%\\emredius-ca.crt", "set B64=%TEMP%\\emredius-ca.b64",
           "(", "echo -----BEGIN CERTIFICATE-----"]
    bat += ["echo " + l for l in lines]
    bat += ["echo -----END CERTIFICATE-----", ") > \"%B64%\"",
            "certutil -f -decode \"%B64%\" \"%CRT%\" >nul",
            "certutil -user -addstore Root \"%CRT%\"",
            "del \"%B64%\" \"%CRT%\" 2>nul",
            "echo.", "echo Kurulum tamamlandi. Tarayiciyi kapatip yeniden acin.", "pause"]
    return Response("\r\n".join(bat) + "\r\n", mimetype="application/octet-stream",
                    headers={"Content-Disposition": "attachment; filename=EMREDIUS-CA-Kur.bat"})


@bp.route("/api/system/time")
@login_required
def api_system_time():
    now = datetime.now()
    return jsonify({"time": now.strftime("%d.%m.%Y %H:%M:%S"), "timestamp": int(now.timestamp())})


@bp.route("/api/system/telemetry")
@login_required
def api_system_telemetry():
    return jsonify(telemetry.snapshot())


@bp.route("/api/system/telemetry/history")
@login_required
def api_system_telemetry_history():
    try:
        range_key, points = telemetry.history((request.args.get("range") or "15m").strip().lower())
    except Exception as e:
        current_app.logger.error("telemetry history: %s", e)
        return jsonify({"success": False, "error": "Veritabanı hatası.", "points": []}), 503
    return jsonify({"success": True, "range": range_key, "count": len(points), "points": points})


@bp.route("/security")
@require_page("security")
def security_page():
    try:
        data = admin_svc.security_overview()
    except Exception as e:
        current_app.logger.error("security page: %s", e)
        flash("Yönetici listesi okunamadı (veritabanı hatası).", "danger")
        data = {"admins": [], "total_admins": 0, "totp_enabled_count": 0, "totp_disabled_count": 0}
    return render_template("security/index.html", title="Oturum Güvenliği", page_title="Oturum Güvenliği & 2FA Yönetimi",
                           active_tab="security", min_pw=admin_svc.MIN_PASSWORD_LEN, **data)


@bp.route("/api/security/2fa/reset/<path:username>", methods=["POST"])
@require_page("security")
def api_security_2fa_reset(username):
    try:
        admin_svc.reset_totp(username)
    except admin_svc.ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), "2FA_SIFIRLA", username, "Yöneticinin 2FA anahtarı kaldırıldı", get_client_ip())
    flash(f"Yönetici '{username}' için 2FA başarıyla sıfırlandı ve kaldırıldı. Kullanıcı artık parolasını girerek "
          "sisteme erişebilir.", "success")
    return _back()


@bp.route("/api/security/password/reset", methods=["POST"])
@bp.route("/api/security/password/reset/<path:username>", methods=["POST"])
@require_page("security")
def api_security_password_reset(username=None):
    username = (username or request.form.get("username") or "").strip()
    try:
        admin_svc.reset_password(username, (request.form.get("new_password") or "").strip())
    except admin_svc.ServiceError as e:
        flash(str(e), "warning" if "terminal" in str(e) else "danger")
        return _back()
    log_admin_action(session.get("user"), "ŞİFRE_SIFIRLA", username, "Yönetici şifresi güvenlik merkezinden sıfırlandı",
                     get_client_ip())
    flash(f"'{username}' kullanıcısının şifresi başarıyla güncellendi.", "success")
    return _back()
