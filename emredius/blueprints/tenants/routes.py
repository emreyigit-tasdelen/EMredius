# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Kiracılar (/tenants, yalnızca süper yönetici): kiracı ekle/adlandır/sil, yönetici ataması, çalışılan kiracıyı değiştirme."""
from flask import flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...core import tenant as tn
from . import bp


def _user():
    return session.get("user") or ""


def _audit(action, target, detail=""):
    log_admin_action(_user(), action, str(target)[:64], detail[:200], get_client_ip())


@bp.route("/tenants")
@require_page("tenants")
def tenants_page():
    return render_template("tenants/index.html", title="Kiracılar", page_title="Kiracılar", active_tab="tenants",
                           tenants=tn.list_tenants(), current=tn.current_tenant())


@bp.route("/tenants/add", methods=["POST"])
@require_page("tenants")
def tenants_add():
    err = tn.add_tenant(request.form.get("name"))
    flash(err or "Kiracı eklendi.", "danger" if err else "success")
    if not err:
        _audit("TENANT_ADD", request.form.get("name", ""))
    return redirect("/tenants")


@bp.route("/tenants/<int:tid>/rename", methods=["POST"])
@require_page("tenants")
def tenants_rename(tid):
    err = tn.rename_tenant(tid, request.form.get("name"))
    flash(err or "Kiracı adı değişti.", "danger" if err else "success")
    if not err:
        _audit("TENANT_RENAME", tid, request.form.get("name", ""))
    return redirect("/tenants")


@bp.route("/tenants/<int:tid>/delete", methods=["POST"])
@require_page("tenants")
def tenants_delete(tid):
    err = tn.delete_tenant(tid)
    flash(err or "Kiracı silindi.", "danger" if err else "success")
    if not err:
        _audit("TENANT_DELETE", tid)
    return redirect("/tenants")


@bp.route("/tenants/assign", methods=["POST"])
@require_page("tenants")
def tenants_assign():
    f = request.form
    err = tn.assign_admin(f.get("username"), f.get("tenant_id", type=int) or 0)
    flash(err or "Yönetici kiracıya atandı.", "danger" if err else "success")
    if not err:
        _audit("TENANT_ASSIGN", f.get("username", ""), f"kiracı {f.get('tenant_id')}")
    return redirect("/tenants")


@bp.route("/tenants/own", methods=["POST"])
@require_page("tenants")
def tenants_own():
    f = request.form
    err = tn.set_owner(f.get("kind", ""), f.get("key", ""), f.get("tenant_id", type=int) or 1)
    flash(err or "Kayıt kiracıya bağlandı.", "danger" if err else "success")
    if not err:
        _audit("TENANT_OWN", f"{f.get('kind')}:{f.get('key', '')}", f"kiracı {f.get('tenant_id')}")
    return redirect("/tenants")


@bp.route("/tenants/unassign", methods=["POST"])
@require_page("tenants")
def tenants_unassign():
    tn.unassign_admin(request.form.get("username"))
    _audit("TENANT_UNASSIGN", request.form.get("username", ""))
    return redirect("/tenants")


@bp.route("/tenants/switch", methods=["POST"])
@require_page("tenants")
def tenants_switch():
    tid = request.form.get("tenant_id", type=int) or 1
    if not tn.tenant_exists(tid):
        return jsonify({"success": False, "error": "Kiracı yok."}), 404
    session["tenant_id"] = tid
    _audit("TENANT_SWITCH", tid)
    return redirect("/tenants")
