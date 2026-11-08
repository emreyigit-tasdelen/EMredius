# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Settings: notification channels, voucher branding + API token, and host settings (/api/settings/*:
DNS, sshd, firewalld, timezone). Superadmin-only page ("settings")."""
from datetime import datetime

from flask import current_app, flash, redirect, render_template, request, session

from ...core import get_client_ip, is_dry_run, log_admin_action, nms_settings_sync, require_page, send_alert, url_for
from ...services import chrony
from ...services import system_settings as svc
from . import bp


def _back():
    return redirect(url_for("settings_page"))


def _flash_errors(errors):
    for e in errors:
        flash(e, "danger")


@bp.route("/settings", methods=["GET", "POST"])
@require_page("settings")
def settings_page():
    if request.method == "POST":
        # Each card posts only its own fields; `form` tells them apart so one card never blanks the other's values.
        if request.form.get("form") == "notify":
            errors, values = svc.validate_notifications(request.form)
            if errors:
                _flash_errors(errors)
                return _back()
            svc.save(values)
            nms_settings_sync()
            log_admin_action(session.get("user"), "AYAR_BİLDİRİM", "telegram/slack",
                             f"Telegram: {'açık' if values['telegram_bot_token'] else 'kapalı'}, "
                             f"Webhook: {'açık' if values['slack_webhook_url'] else 'kapalı'}", get_client_ip())
            if "send_test_alert" in request.form:
                send_alert("📡 <b>EMredius:</b> Test uyarısı başarıyla iletildi!")
                flash("Ayarlar kaydedildi ve test bildirimi tetiklendi.", "success")
            else:
                flash("Ayarlar başarıyla kaydedildi.", "success")
        elif request.form.get("form") == "brand":
            errors, values = svc.validate_branding(request.form)
            if errors:
                _flash_errors(errors)
                return _back()
            svc.save(values)
            log_admin_action(session.get("user"), "AYAR_MARKA_API", "radius_settings",
                             f"Başlık: {values['company_brand_name']}, SSID: {values['company_ssid_name']}, "
                             f"API anahtarı: {'değiştirildi' if values['api_token'] else 'korundu'}", get_client_ip())
            flash("Ayarlar başarıyla kaydedildi.", "success")
        else:
            flash("Geçersiz form.", "danger")
        return _back()

    dns1, dns2 = svc.read_dns(current_app.config["RESOLV_CONF"])
    return render_template(
        "settings/index.html",
        title="Ayarlar",
        page_title="Sistem Ayarları & Entegrasyon",
        active_tab="settings",
        v=svc.page_values(),
        ntp=chrony.tracking_info(),
        now=datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
        dns1=dns1 or "8.8.8.8",
        dns2=dns2 or ("1.1.1.1" if not dns1 else ""),
        timezones=svc.TIMEZONES,
        current_tz=svc.current_timezone(),
        dry_run=is_dry_run(),
    )


def _host_action(ok_msg, audit_action, target, details=""):
    ok, msg = ok_msg
    if ok:
        log_admin_action(session.get("user"), audit_action, target, details, get_client_ip())
    flash(msg, "success" if ok else "danger")
    return _back()


@bp.route("/api/settings/dns", methods=["POST"])
@require_page("settings")
def api_settings_dns():
    try:
        dns1, dns2 = svc.write_dns(current_app.config["RESOLV_CONF"], request.form.get("dns1"), request.form.get("dns2"))
    except svc.ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), "AYAR_DNS", "/etc/resolv.conf", f"{dns1} {dns2}".strip(), get_client_ip())
    flash("DNS sunucu adresleri (/etc/resolv.conf) başarıyla güncellendi.", "success")
    return _back()


@bp.route("/api/settings/ssh/reload", methods=["POST"])
@require_page("settings")
def api_settings_ssh_reload():
    return _host_action(svc.reload_ssh(), "SSH_YENİDEN_YÜKLE", "sshd")


@bp.route("/api/settings/firewall/reload", methods=["POST"])
@require_page("settings")
def api_settings_firewall_reload():
    return _host_action(svc.reload_firewall(), "FIREWALL_YENİDEN_YÜKLE", "firewalld")


@bp.route("/api/settings/timezone", methods=["POST"])
@require_page("settings")
def api_settings_timezone():
    tz = (request.form.get("timezone") or "").strip()
    return _host_action(svc.set_timezone(tz), "SAAT_DİLİMİ", tz)
