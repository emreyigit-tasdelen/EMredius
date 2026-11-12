# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Entegrasyonlar ve Bildirim Kanalları (/integrations, yalnızca süper yönetici): kanal durumu + genel webhook (varsayılan kapalı)."""
from flask import flash, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page, send_alert
from ...services import integrations as svc
from . import bp

svc.register()


@bp.route("/integrations")
@require_page("integrations")
def integrations_page():
    return render_template("integrations/index.html", title="Entegrasyonlar", page_title="Entegrasyonlar & Bildirim Kanalları",
                           active_tab="integrations", channels=svc.channels(), cfg=svc.get_settings())


@bp.route("/integrations/webhook", methods=["POST"])
@require_page("integrations")
def integrations_webhook():
    err = svc.save_settings(request.form)
    if err:
        flash(err, "danger")
    else:
        log_admin_action(session.get("user") or "", "INTEGRATION_WEBHOOK", "webhook",
                         "enabled=%s" % (1 if request.form.get("int_webhook_enabled") else 0), get_client_ip())
        flash("Webhook ayarları kaydedildi.", "success")
    return redirect("/integrations")


@bp.route("/integrations/test", methods=["POST"])
@require_page("integrations")
def integrations_test():
    """Tanımlı tüm kanallara (Telegram/Slack + açıksa genel webhook) test iletisi gönderir."""
    send_alert("EMREDIUS test bildirimi (%s)" % (session.get("user") or ""))
    log_admin_action(session.get("user") or "", "INTEGRATION_TEST", "alert", "", get_client_ip())
    flash("Test bildirimi tanımlı kanallara gönderildi.", "info")
    return redirect("/integrations")


@bp.route("/integrations/webhook-test", methods=["POST"])
@require_page("integrations")
def integrations_webhook_test():
    ok, msg = svc.post_webhook("EMREDIUS webhook testi", "test", force=True)
    flash(msg, "success" if ok else "danger")
    return redirect("/integrations")
