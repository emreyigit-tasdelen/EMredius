# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Sertifikalar (/certs, yalnızca süper yönetici): EAP/web/CA sertifika geçerliliği ve süre sonu uyarısı."""
from flask import flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import certs as svc
from . import bp

svc.register()


@bp.route("/certs")
@require_page("certs")
def certs_page():
    return render_template("certs/index.html", title="Sertifikalar", page_title="Sertifikalar", active_tab="certs",
                           rows=svc.snapshot(), cfg=svc.get_settings())


@bp.route("/certs/data")
@require_page("certs")
def certs_data():
    return jsonify({"success": True, "rows": svc.snapshot()})


@bp.route("/certs/settings", methods=["POST"])
@require_page("certs")
def certs_settings():
    err = svc.save_settings(request.form)
    if err:
        flash(err, "danger")
    else:
        log_admin_action(session.get("user") or "", "CERT_SETTINGS", "certs", "uyarı eşiği %s gün" % request.form.get("cert_warn_days"),
                         get_client_ip())
        flash("Sertifika uyarı ayarları kaydedildi.", "success")
    return redirect("/certs")


@bp.route("/certs/check", methods=["POST"])
@require_page("certs")
def certs_check():
    n = svc.notify_expiring()
    flash("%d uyarı gönderildi." % n if n else "Gönderilecek uyarı yok (ya da uyarı kanalı kapalı).", "info")
    return redirect("/certs")
