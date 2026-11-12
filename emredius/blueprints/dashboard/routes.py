# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Landing page: RADIUS summary, live system telemetry charts, latest live sessions, top traffic."""
from flask import jsonify, render_template, request

from ...core import can_access_page, is_read_only_role, login_required
from ...services import dashboard as dashboard_service
from ...services import dashboard_stats
from . import bp


@bp.route("/")
@login_required
def dashboard():
    summary = dashboard_service.get_summary()
    return render_template(
        "dashboard/index.html",
        title="Genel Bakış",
        page_title="Sistem Özeti & Canlı Metrikler",
        active_tab="dashboard",
        summary=summary,
        traffic_chart=dashboard_service.top_traffic_chart(summary["top_users"]),
        # the disconnect action needs the sessions page permission and a role that may change state
        can_disconnect=can_access_page("sessions") and not is_read_only_role(),
    )


@bp.route("/api/dashboard/stats")
@login_required
def stats_api():
    resp = jsonify(dashboard_stats.get_stats(request.args.get("range")))
    resp.headers["Cache-Control"] = "no-store"
    return resp
