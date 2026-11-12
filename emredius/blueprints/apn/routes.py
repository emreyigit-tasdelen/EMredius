# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""APN envanteri (/apn): hatlar, sağlayıcılar, konumlar (ekle / düzenle / sil)."""
from flask import flash, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import apn as svc
from ...services.radius_users import ServiceError
from . import bp

LABELS = {"providers": "Sağlayıcı", "locations": "Konum", "lines": "Hat"}


def _log(action, kind, name):
    log_admin_action(session.get("user"), action, name, LABELS.get(kind, kind), get_client_ip())


def _options():
    """Hat formundaki IP havuzu ve profil (grup) seçenekleri; RADIUS DB yoksa boş."""
    pools, groups = [], []
    try:
        from ...services import ippools
        pools = [p["name"] for p in ippools.list_pools()]
    except Exception:  # noqa: BLE001
        pass
    try:
        from ...services import groups as grp
        groups = [g["groupname"] for g in grp.list_groups()]
    except Exception:  # noqa: BLE001
        pass
    return pools, groups


@bp.route("/apn")
@require_page("apn")
def apn_page():
    pools, groups = _options()
    return render_template("apn/index.html", title="APN Envanteri", page_title="APN Envanteri", active_tab="apn",
                           data=svc.overview(), statuses=svc.STATUSES, pools=pools, groups=groups, edit=None, edit_kind="")


@bp.route("/apn/<kind>/<int:rec_id>/edit")
@require_page("apn")
def apn_edit(kind, rec_id):
    try:
        rec = svc.get(kind, rec_id)
    except ServiceError as e:
        flash(str(e), "danger")
        return redirect("/apn")
    pools, groups = _options()
    return render_template("apn/index.html", title="APN Envanteri", page_title="APN Envanteri", active_tab="apn",
                           data=svc.overview(), statuses=svc.STATUSES, pools=pools, groups=groups, edit=rec, edit_kind=kind)


@bp.route("/apn/<kind>/add", methods=["POST"])
@require_page("apn")
def apn_add(kind):
    try:
        name = svc.save(kind, request.form)
        _log("APN_EKLE", kind, name)
        flash(f"'{name}' eklendi.", "success")
    except ServiceError as e:
        flash(str(e), "danger")
    return redirect("/apn")


@bp.route("/apn/<kind>/<int:rec_id>/update", methods=["POST"])
@require_page("apn")
def apn_update(kind, rec_id):
    try:
        name = svc.save(kind, request.form, rec_id)
        _log("APN_GÜNCELLE", kind, name)
        flash(f"'{name}' güncellendi.", "success")
    except ServiceError as e:
        flash(str(e), "danger")
    return redirect("/apn")


@bp.route("/apn/<kind>/<int:rec_id>/delete", methods=["POST"])
@require_page("apn")
def apn_delete(kind, rec_id):
    try:
        name = svc.delete(kind, rec_id)
        _log("APN_SİL", kind, name)
        flash(f"'{name}' silindi.", "success")
    except ServiceError as e:
        flash(str(e), "danger")
    return redirect("/apn")
