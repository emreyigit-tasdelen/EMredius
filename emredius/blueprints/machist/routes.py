# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""MAC Geçmişi (/machist): kullanıcı/MAC bazlı "son N günde hangi portlardan bağlandı" + RADIUS oturumları."""
from flask import Response, jsonify, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import machist as svc
from . import bp


def _args():
    try:
        days = int(request.args.get("days", 30))
    except ValueError:
        days = 30
    return (request.args.get("q") or "")[:64], max(1, min(days, 365))


@bp.route("/machist")
@require_page("machist")
def machist_page():
    q, days = _args()
    return render_template("machist/index.html", title="MAC Geçmişi", page_title="MAC Geçmişi", active_tab="machist",
                           q=q, days=days)


@bp.route("/machist/data")
@require_page("machist")
def machist_data():
    q, days = _args()
    return jsonify({"success": True, **svc.history(q=q, days=days)})


@bp.route("/machist/export.csv")
@require_page("machist")
def machist_export():
    q, days = _args()
    rows = svc.history(q=q, days=days)["ports"]
    log_admin_action(session.get("user") or "", "MACHIST_EXPORT", "machist.csv", f"{q} {days}g {len(rows)} kayıt", get_client_ip())
    return Response(svc.to_csv(rows), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=machist.csv"})
