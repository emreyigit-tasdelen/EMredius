# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""SIEM Yönlendirme (/siem, yalnızca süper yönetici): denetim olaylarını syslog/CEF ile dışarı gönderme (varsayılan kapalı)."""
from flask import flash, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import siem as svc
from . import bp

svc.register()


@bp.route("/siem")
@require_page("siem")
def siem_page():
    cfg = svc.get_settings()
    return render_template("siem/index.html", title="SIEM Yönlendirme", page_title="SIEM Yönlendirme", active_tab="siem",
                           cfg=cfg, last=svc.last_status(),
                           sample=svc.format_event(cfg["siem_format"], "admin", "ORNEK_OLAY", "hedef", "örnek ayrıntı", "10.0.0.1"))


@bp.route("/siem/settings", methods=["POST"])
@require_page("siem")
def siem_settings():
    err = svc.save_settings(request.form)
    if err:
        flash(err, "danger")
    else:
        log_admin_action(session.get("user") or "", "SIEM_SETTINGS", "siem",
                         "enabled=%s host=%s" % (1 if request.form.get("siem_enabled") else 0, request.form.get("siem_host", "")[:80]),
                         get_client_ip())
        flash("SIEM ayarları kaydedildi.", "success")
    return redirect("/siem")


@bp.route("/siem/test", methods=["POST"])
@require_page("siem")
def siem_test():
    cfg = svc.get_settings()
    ok, msg = svc.send(svc.format_event(cfg["siem_format"], session.get("user") or "", "SIEM_TEST", "siem", "test iletisi",
                                        get_client_ip()), cfg)
    flash(msg, "success" if ok else "danger")
    return redirect("/siem")
