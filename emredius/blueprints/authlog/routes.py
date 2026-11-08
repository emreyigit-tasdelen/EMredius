# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Kimlik Doğrulama Günlüğü (/authlog): radpostauth arama, özet, CSV."""
from flask import Response, jsonify, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import authlog as svc
from . import bp


def _args():
    try:
        days = int(request.args.get("days", 1))
    except ValueError:
        days = 1
    return (request.args.get("q") or "")[:64], request.args.get("result", ""), max(1, min(days, 365))


@bp.route("/authlog")
@require_page("authlog")
def authlog_page():
    q, result, days = _args()
    return render_template("authlog/index.html", title="Kimlik Doğrulama Günlüğü", page_title="Kimlik Doğrulama Günlüğü",
                           active_tab="authlog", q=q, result=result, days=days)


@bp.route("/authlog/data")
@require_page("authlog")
def authlog_data():
    q, result, days = _args()
    return jsonify({"success": True, **svc.search(q, result, days)})


@bp.route("/authlog/export.csv")
@require_page("authlog")
def authlog_export():
    q, result, days = _args()
    rows = svc.search(q, result, days, limit=5000)["rows"]
    log_admin_action(session.get("user") or "", "AUTHLOG_EXPORT", "authlog.csv", f"{q} {result} {days}g {len(rows)} kayıt",
                     get_client_ip())
    return Response(svc.to_csv(rows), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=authlog.csv"})
