# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Misafir Onayları (/approvals): talep ekle, onayla (kupon üretir), reddet, kayıt sil."""
from flask import flash, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import approvals as svc
from ...services.radius_users import ServiceError
from ...services.vouchers import VOUCHER_DURATION_LABELS
from . import bp


def _log(action, target, detail=""):
    log_admin_action(session.get("user"), action, target, detail, get_client_ip())


@bp.route("/approvals")
@require_page("approvals")
def approvals_page():
    status = request.args.get("status", "")
    return render_template("approvals/index.html", title="Misafir Onayları", page_title="Misafir Onayları", active_tab="approvals",
                           rows=svc.list_requests(status=status), status=status, statuses=svc.STATUSES,
                           durations=VOUCHER_DURATION_LABELS)


@bp.route("/approvals/add", methods=["POST"])
@require_page("approvals")
def approvals_add():
    f = request.form
    try:
        name = svc.add_request(f.get("name"), f.get("email"), f.get("sponsor"), f.get("reason"), f.get("duration") or "1d")
        _log("ONAY_TALEP", name, f"sponsor: {f.get('sponsor', '')[:80]}")
        flash("Talep kaydedildi.", "success")
    except ServiceError as e:
        flash(str(e), "danger")
    return redirect("/approvals")


@bp.route("/approvals/<int:rec_id>/approve", methods=["POST"])
@require_page("approvals")
def approvals_approve(rec_id):
    try:
        code, pin = svc.approve(rec_id, session.get("user"))
        _log("ONAY_ONAYLA", code, f"talep {rec_id}")
        flash(f"Onaylandı. Kullanıcı adı: {code}" + (f" · PIN: {pin}" if pin else ""), "success")
    except ServiceError as e:
        flash(str(e), "danger")
    return redirect("/approvals")


@bp.route("/approvals/<int:rec_id>/reject", methods=["POST"])
@require_page("approvals")
def approvals_reject(rec_id):
    try:
        name = svc.reject(rec_id, session.get("user"))
        _log("ONAY_REDDET", name, f"talep {rec_id}")
        flash("Talep reddedildi.", "success")
    except ServiceError as e:
        flash(str(e), "danger")
    return redirect("/approvals")


@bp.route("/approvals/<int:rec_id>/delete", methods=["POST"])
@require_page("approvals")
def approvals_delete(rec_id):
    try:
        name = svc.delete_request(rec_id)
        _log("ONAY_KAYIT_SİL", name, f"talep {rec_id}")
        flash("Kayıt silindi.", "success")
    except ServiceError as e:
        flash(str(e), "danger")
    return redirect("/approvals")
