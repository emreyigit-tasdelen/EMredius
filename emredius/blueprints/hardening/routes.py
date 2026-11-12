# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Sertleştirme (/hardening, yalnız süper yönetici): kilit politikası, 2FA zorunluluğu, gözden geçirme, NetFlow kaynak IP."""
from flask import current_app, flash, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page, url_for
from ...services import hardening as svc
from . import bp


@bp.route("/hardening")
@require_page("hardening")
def hardening_page():
    try:
        review = svc.review()
    except Exception as e:  # noqa: BLE001
        current_app.logger.error("hardening review: %s", e)
        flash("Denetim verisi okunamadı (veritabanı hatası).", "danger")
        review = {"no_2fa": [], "locked": [], "failures": [], "top_ips": [], "logins": [], "days": svc.REVIEW_DAYS,
                  "admin_count": 0}
    try:
        flow_sources = svc.get_flow_sources()
    except Exception:  # noqa: BLE001
        flow_sources = ""
    return render_template("hardening/index.html", title="Sertleştirme", page_title="Güvenlik Sertleştirme",
                           active_tab="hardening", policy=svc.get_policy(), review=review, flow_sources=flow_sources)


@bp.route("/hardening/policy", methods=["POST"])
@require_page("hardening")
def hardening_policy():
    try:
        svc.save_policy(request.form)
    except svc.ValidationError as e:
        flash(str(e), "danger")
        return redirect(url_for("hardening_page"))
    log_admin_action(session.get("user"), "SERTLESTIRME_AYAR", "giriş politikası",
                     "kilit/2FA politikası güncellendi", get_client_ip())
    flash("Giriş politikası kaydedildi.", "success")
    return redirect(url_for("hardening_page"))


@bp.route("/hardening/netflow-sources", methods=["POST"])
@require_page("hardening")
def hardening_netflow_sources():
    try:
        value = svc.save_flow_sources(request.form.get("sources", ""))
    except svc.ValidationError as e:
        flash(str(e), "danger")
        return redirect(url_for("hardening_page"))
    log_admin_action(session.get("user"), "NETFLOW_KAYNAK_IP", "UDP 2055/4739", (value or "kısıt yok")[:900],
                     get_client_ip())
    flash("NetFlow kaynak IP listesi kaydedildi (boş = herkes kabul)." if not value else
          f"NetFlow yalnız şu kaynaklardan kabul edilecek: {value}", "success")
    return redirect(url_for("hardening_page"))