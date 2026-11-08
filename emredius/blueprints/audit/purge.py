# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Law 5651 retention clean-up screen (superadmin only): settings, preview, re-authenticated delete."""
from flask import current_app, flash, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page, url_for
from ...services import admins, audit_purge as svc, backups
from ...services.radius_users import ServiceError
from . import bp


def _archive_dir():
    return current_app.config["ARCHIVE_5651_DIR"]


def _back():
    return redirect(url_for("audit_purge_page"))


@bp.route("/audit/purge")
@require_page(superadmin=True)
def audit_purge_page():
    days = svc.get_retention_days()
    plan, error = None, None
    try:
        plan = svc.build_plan(_archive_dir(), days)
    except ServiceError as e:
        error = str(e)
    return render_template(
        "audit/purge.html", title="5651 Saklama Süresi Temizliği", page_title="5651 Süresi Dolan Kayıtları Temizle",
        active_tab="audit", plan=plan, error=error, retention_days=days, min_days=svc.MIN_RETENTION_DAYS,
        max_days=svc.MAX_RETENTION_DAYS, confirm_text=svc.CONFIRM_TEXT,
        totp_on=admins.totp_enabled(session.get("user")))


@bp.route("/audit/purge/retention", methods=["POST"])
@require_page(superadmin=True)
def audit_purge_retention():
    if request.form.get("confirmed") != "1":
        flash("Saklama süresi değişikliği onaylanmadı.", "danger")
        return _back()
    try:
        old = svc.get_retention_days()
        new = svc.save_retention_days(request.form.get("retention_days"))
    except ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), "5651_SAKLAMA_SURESI", "radius_settings", f"{old} -> {new} gün",
                     get_client_ip())
    flash(f"Saklama süresi {new} gün olarak kaydedildi.", "success")
    return _back()


@bp.route("/audit/purge/run", methods=["POST"])
@require_page(superadmin=True)
def audit_purge_run():
    user = session.get("user")
    ip = get_client_ip()
    days = svc.get_retention_days()
    if (request.form.get("confirm_text") or "").strip() != svc.CONFIRM_TEXT:
        flash(f"Onay metni hatalı: büyük harflerle {svc.CONFIRM_TEXT} yazın.", "danger")
        return _back()
    try:
        admins.verify_reauth(user, request.form.get("password") or "", request.form.get("totp") or "")
    except ServiceError as e:
        log_admin_action(user, "5651_TEMIZLE_RED", "radacct", str(e), ip)
        flash(str(e), "danger")
        return _back()
    log_admin_action(user, "5651_TEMIZLE_BASLA", "radacct", f"saklama {days} gün", ip)
    try:
        backup_path = backups.create_backup(current_app.config, "sql")
    except Exception as e:  # any failure aborts: no backup, no delete
        current_app.logger.error("5651 purge backup: %s", e)
        log_admin_action(user, "5651_TEMIZLE_IPTAL", "radacct", "yedek alınamadı", ip)
        flash("İşlem öncesi yedek alınamadığı için silme yapılmadı.", "danger")
        return _back()
    try:
        res = svc.execute(_archive_dir(), days)
    except ServiceError as e:
        log_admin_action(user, "5651_TEMIZLE_HATA", "radacct", str(e), ip)
        flash(str(e), "danger")
        return _back()
    rng = f"{res['days'][0]} .. {res['days'][-1]}" if res["days"] else "-"
    log_admin_action(user, "5651_TEMIZLE", "radacct",
                     f"{res['deleted']} kayıt, {len(res['days'])} gün ({rng}); atlanan gün {res['blocked_days']}; "
                     f"yedek {backup_path}", ip)
    flash(f"{res['deleted']} kayıt silindi ({len(res['days'])} gün). Atlanan gün: {res['blocked_days']}.", "success")
    return _back()
