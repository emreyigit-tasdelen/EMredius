# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Services page: status / journal of the managed systemd services, restart, probes, server reboot, /restart-radius."""
from datetime import datetime

from flask import current_app, flash, jsonify, redirect, render_template, session

from ...core import (esc, get_client_ip, is_dry_run, local_referrer, log_admin_action, require_page, send_alert)
from ...services import system_services as svc
from . import bp


@bp.record_once
def _configure(state):
    svc.configure(state.app.config.get("PANEL_UNIT"))


def _bad_key():
    return jsonify({"success": False, "error": "Geçersiz servis."}), 400


@bp.route("/services")
@require_page("services")
def services_page():
    return render_template("services/index.html", title="Yeniden Başlat", page_title="Servis & Sistem Yeniden Başlat",
                           active_tab="services", services=[svc.detail(k) for k in svc.SERVICES])


@bp.route("/api/services/status/all")
@require_page("services")
def api_services_status_all():
    return jsonify({"success": True, "services": svc.all_details()})


@bp.route("/api/service/status/<srv_key>")
@require_page("services")
def api_service_status(srv_key):
    if srv_key not in svc.SERVICES:
        return _bad_key()
    lines = svc.logs(srv_key)
    return jsonify({"success": True, "detail": svc.detail(srv_key), "lines": lines, "logs": "\n".join(lines),
                    "timestamp": datetime.now().strftime("%H:%M:%S")})


@bp.route("/api/service/test-ping/<srv_key>", methods=["POST"])
@require_page("services")
def api_service_test_ping(srv_key):
    if srv_key not in svc.SERVICES:
        return _bad_key()
    ok, message, output = svc.probe(srv_key, current_app.config["MYSQL_DEFAULTS_FILE"])
    res = {"success": ok, "message": message}
    if output is not None:
        res["output"] = output
    return jsonify(res)


@bp.route("/api/service/restart/<srv_key>", methods=["POST"])
@require_page("services")
def api_service_restart(srv_key):
    if srv_key not in svc.SERVICES:
        return _bad_key()
    ok, msg = svc.restart(srv_key)
    log_admin_action(session.get("user"), "SERVİS_YENİDEN_BAŞLAT", svc.unit_of(srv_key),
                     ("Başarılı: " if ok else "Başarısız: ") + str(msg)[:900], get_client_ip())
    if srv_key == svc.PANEL_KEY:  # this process is about to be restarted: answer quickly
        return jsonify({"success": ok, "message": msg, "is_self": True, "detail": None, "logs": []})
    return jsonify({"success": ok, "message": msg, "is_self": False, "detail": svc.detail(srv_key),
                    "logs": svc.logs(srv_key)})


@bp.route("/api/server/reboot", methods=["POST"])
@require_page(superadmin=True)
def api_server_reboot():
    user, client_ip = session.get("user"), get_client_ip()
    if is_dry_run():
        return jsonify({"success": False, "message": "[staging] Sunucu yeniden başlatma SYSTEM_DRY_RUN modunda engellendi."})
    log_admin_action(user, "SUNUCU_YENİDEN_BAŞLAT", "systemctl reboot", "Sunucu yeniden başlatma komutu verildi", client_ip)
    send_alert(f"⚠️ <b>[Sunucu Yeniden Başlatılıyor]</b> <code>{esc(user)}</code> sunucuyu web panelinden yeniden başlattı.\n"
               f"IP: {esc(client_ip)}")
    svc.reboot_server()
    return jsonify({"success": True,
                    "message": "AlmaLinux sunucusu yeniden başlatılıyor. Sistem yaklaşık 1 dakika içinde tekrar açılacaktır."})


@bp.route("/restart-radius", methods=["POST"])
@require_page("services")
def restart_radius():
    ok, msg = svc.restart_radiusd()
    if ok:
        log_admin_action(session.get("user"), "RADIUS_RESTART", "radiusd", "FreeRADIUS yeniden başlatıldı", get_client_ip())
    flash(msg, "success" if ok else "danger")
    return redirect(local_referrer())
