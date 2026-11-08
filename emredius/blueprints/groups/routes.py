# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""RADIUS groups / profiles: list, create-or-update, delete."""
from flask import flash, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page, url_for
from ...services import groups as svc
from ...services.radius_users import ServiceError
from . import bp


def _back():
    return redirect(url_for("groups_page"))


@bp.route("/profiles")
@bp.route("/groups")
@require_page("groups")
def groups_page():
    return render_template("groups/index.html", title="Gruplar", page_title="Grup & Profil Yönetimi (RBAC)",
                           active_tab="groups", groups=svc.list_groups())


@bp.route("/group/add", methods=["POST"])
@require_page("groups")
def add_group_action():
    try:
        groupname, existed, vlan, rate = svc.save_group(request.form.get("groupname"), request.form.get("vlan_id"),
                                                        request.form.get("rate_limit"))
    except ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), "GRUP_GÜNCELLE" if existed else "GRUP_EKLE", groupname,
                     f"VLAN: {vlan or '-'}, Limit: {rate or '-'}", get_client_ip())
    if existed:
        flash(f"'{groupname}' grubu zaten vardı; VLAN / hız ayarları güncellendi.", "success")
    else:
        flash(f"'{groupname}' grubu başarıyla oluşturuldu.", "success")
    return _back()


@bp.route("/group/delete/<path:groupname>", methods=["POST"])
@require_page("groups")
def delete_group_action(groupname):
    try:
        n_attrs, n_members = svc.delete_group(groupname)
    except ServiceError as e:
        flash(str(e), "danger")
        return _back()
    if not (n_attrs or n_members):
        flash("Grup bulunamadı!", "warning")
        return _back()
    groupname = groupname.strip()
    log_admin_action(session.get("user"), "GRUP_SİL", groupname,
                     f"{n_attrs} öznitelik, {n_members} üyelik silindi", get_client_ip())
    flash(f"'{groupname}' grubu silindi ({n_members} üyelik kaldırıldı).", "success")
    return _back()
