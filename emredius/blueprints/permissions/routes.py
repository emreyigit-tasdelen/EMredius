# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Yetki Matrisi (/permissions, yalnızca süper yönetici): rol x menü tablosu, satır satır düzenleme, JSON dışa aktarma."""
import json

from flask import Response, flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, get_db, log_admin_action, require_page
from ...core import rbac
from ...services import admins
from ...services.radius_users import ServiceError
from . import bp


def _roles():
    """-> [{'role_key','role_name','all','pages'}] (superadmin dahil; veritabanı yoksa varsayılan roller)."""
    rows = []
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT role_key, role_name, allowed_pages FROM admin_roles ORDER BY id ASC")
                rows = cur.fetchall()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        rows = []
    if not rows:
        rows = [{"role_key": k, "role_name": k, "allowed_pages": ",".join(sorted(v))} for k, v in rbac.DEFAULT_ROLE_PAGES.items()]
        rows.insert(0, {"role_key": "superadmin", "role_name": "Süper Yönetici", "allowed_pages": "*"})
    out = []
    for r in rows:
        raw = (r.get("allowed_pages") or "").strip()
        out.append({"role_key": r["role_key"], "role_name": r.get("role_name") or r["role_key"], "all": raw == "*",
                    "pages": [p.strip() for p in raw.split(",") if p.strip()]})
    return out


def _pages():
    return [(k, label) for k, label in rbac.PAGE_DEFINITIONS if k not in rbac.SUPERADMIN_ONLY_PAGES]


@bp.route("/permissions")
@require_page("permissions")
def permissions_page():
    return render_template("permissions/index.html", title="Yetki Matrisi", page_title="Yetki Matrisi", active_tab="permissions",
                           roles=_roles(), pages=_pages(), superadmin_only=sorted(rbac.SUPERADMIN_ONLY_PAGES))


@bp.route("/permissions/save", methods=["POST"])
@require_page("permissions")
def permissions_save():
    try:
        r = admins.update_role(request.form)
        log_admin_action(session.get("user") or "", "PERMISSIONS_SAVE", r["role_key"], ",".join(r["pages"])[:200], get_client_ip())
        flash(f"{r['role_key']} rolünün yetkileri kaydedildi.", "success")
    except ServiceError as e:
        flash(str(e), "danger")
    return redirect("/permissions")


@bp.route("/permissions/export.json")
@require_page("permissions")
def permissions_export():
    log_admin_action(session.get("user") or "", "PERMISSIONS_EXPORT", "json", "", get_client_ip())
    data = [{"role": r["role_key"], "name": r["role_name"], "all_pages": r["all"], "pages": r["pages"]} for r in _roles()]
    return Response(json.dumps(data, ensure_ascii=False, indent=1), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=permissions.json"})
