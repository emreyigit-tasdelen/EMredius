# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Servis Sağlığı (/svchealth): servis durumları + düşünce alarm ayarları."""
from flask import flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page, url_for
from ...services import svchealth as svc
from . import bp


def _view():
    rows = svc.snapshot()
    return render_template("svchealth/index.html", title="Servis Sağlığı", page_title="Servis Sağlığı & Alarm",
                           active_tab="svchealth", rows=rows, summary=svc.summary(rows), cfg=svc.get_settings(),
                           is_super=session.get("role") == "superadmin")


@bp.route("/svchealth")
@require_page("svchealth")
def svchealth_page():
    if not any(r["status"] != "unknown" for r in svc.snapshot()):
        svc.check_all(notify=False)
    return _view()


@bp.route("/svchealth/data")
@require_page("svchealth")
def svchealth_data():
    rows = svc.snapshot()
    return jsonify({"success": True, "rows": rows, "summary": svc.summary(rows)})


@bp.route("/svchealth/check", methods=["POST"])
@require_page("svchealth")
def svchealth_check():
    svc.check_all()
    return redirect(url_for("svchealth_page"))


@bp.route("/svchealth/settings", methods=["POST"])
@require_page(superadmin=True)
def svchealth_settings():
    svc.save_settings(request.form)
    log_admin_action(session.get("user"), "SERVIS_ALARM_AYAR", "svchealth", "Servis alarm ayarları güncellendi",
                     get_client_ip())
    flash("Servis alarm ayarları kaydedildi.", "success")
    return redirect(url_for("svchealth_page"))


@bp.route("/svchealth/test", methods=["POST"])
@require_page(superadmin=True)
def svchealth_test():
    cfg = svc.get_settings()
    if cfg["svchealth_email_enabled"] != "1":
        flash("E-posta alarmı kapalı; önce etkinleştirip kaydedin.", "warning")
    else:
        ok, msg = svc.send_email("EMREDIUS test alarmı", "Bu bir test iletisidir.", cfg)
        flash(msg, "success" if ok else "danger")
    return redirect(url_for("svchealth_page"))