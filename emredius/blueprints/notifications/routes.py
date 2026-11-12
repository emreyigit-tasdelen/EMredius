# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Bildirim gelen kutusu API'si (üst çubuktaki çan): liste + okundu. Her oturumlu kullanıcı yalnızca kendi kutusunu görür."""
from flask import jsonify, render_template, request, session

from ...core.rbac import login_required
from ...services import notifications as svc
from . import bp


def _who():
    return session.get("user") or "", session.get("role") or ""


@bp.route("/api/notifications")
@login_required
def notifications_list():
    user, role = _who()
    try:
        data = svc.inbox(user, role, limit=request.args.get("limit", 30), offset=request.args.get("offset", 0),
                         only_unread=request.args.get("unread") == "1", status=request.args.get("status", ""))
    except Exception:  # noqa: BLE001 - çan hiçbir zaman sayfayı bozmasın
        return jsonify({"success": True, "items": [], "unread": 0, "total": 0})
    return jsonify({"success": True, **data})


@bp.route("/api/notifications/read", methods=["POST"])
@login_required
def notifications_read():
    user, role = _who()
    body = request.get_json(silent=True) or {}
    ids = body.get("ids") or request.form.getlist("ids")
    svc.mark_read(user, role, ids=[i for i in ids if str(i).isdigit()], everything=bool(body.get("all") or request.form.get("all")))
    return jsonify({"success": True})


@bp.route("/notifications")
@login_required
def notifications_page():
    return render_template("notifications/index.html", title="Bildirimler", page_title="Bildirimler",
                           active_tab="notifications")
