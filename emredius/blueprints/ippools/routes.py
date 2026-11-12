# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""IP Havuzları (/ippools): havuz oluştur/sil, kullanıcı ve gruba Framed-Pool ata."""
from flask import flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import ippools as svc
from ...services.radius_users import ServiceError
from . import bp


def _log(action, target, detail=""):
    log_admin_action(session.get("user"), action, target, detail, get_client_ip())


@bp.route("/ippools")
@require_page("ippools")
def ippools_page():
    try:
        pools = svc.list_pools()
    except Exception:  # noqa: BLE001
        pools = []
    return render_template("ippools/index.html", title="IP Havuzları", page_title="IP Havuzları", active_tab="ippools", pools=pools)


@bp.route("/ippools/add", methods=["POST"])
@require_page("ippools")
def ippools_add():
    f = request.form
    try:
        name, n = svc.add_pool(f.get("name"), f.get("start"), f.get("end"), f.get("cidr"), f.get("note"))
        _log("IPPOOL_EKLE", name, f"{n} adres")
        flash(f"'{name}' havuzu oluşturuldu ({n} adres).", "success")
    except ServiceError as e:
        flash(str(e), "danger")
    return redirect("/ippools")


@bp.route("/ippools/delete", methods=["POST"])
@require_page("ippools")
def ippools_delete():
    try:
        name = svc.delete_pool(request.form.get("name"))
        _log("IPPOOL_SİL", name)
        flash(f"'{name}' havuzu silindi.", "success")
    except ServiceError as e:
        flash(str(e), "danger")
    return redirect("/ippools")


@bp.route("/ippools/assign", methods=["POST"])
@require_page("ippools")
def ippools_assign():
    f = request.form
    try:
        pool, target = svc.assign(f.get("name"), f.get("kind"), f.get("target"))
        _log("IPPOOL_ATA", target, f"{f.get('kind')} -> {pool}")
        flash(f"{target} için Framed-Pool = {pool} atandı.", "success")
    except ServiceError as e:
        flash(str(e), "danger")
    return redirect("/ippools")


@bp.route("/ippools/unassign", methods=["POST"])
@require_page("ippools")
def ippools_unassign():
    f = request.form
    try:
        n = svc.unassign(f.get("name"), f.get("kind"), f.get("target"))
        _log("IPPOOL_KALDIR", f.get("target", ""), f"{f.get('kind')} / {f.get('name')}")
        flash("Atama kaldırıldı." if n else "Atama bulunamadı.", "success" if n else "warning")
    except ServiceError as e:
        flash(str(e), "danger")
    return redirect("/ippools")


@bp.route("/ippools/<name>/assignments")
@require_page("ippools")
def ippools_assignments(name):
    try:
        users, groups = svc.assignments_of(name)
    except ServiceError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    return jsonify({"success": True, "users": users, "groups": groups})
