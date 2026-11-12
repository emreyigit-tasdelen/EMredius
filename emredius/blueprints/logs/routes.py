# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Live journal logs page + JSON refresh endpoint."""
from datetime import datetime

from flask import jsonify, render_template, request

from ...core import require_page
from ...services import journal
from . import bp


@bp.route("/api/logs/stream")
@require_page("logs")
def api_logs_stream():
    lines = journal.classified_lines(request.args.get("unit", "all"))
    return jsonify({
        "success": True,
        "html": render_template("logs/_lines.html", log_lines=lines),
        "count": len(lines),
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    })


@bp.route("/logs")
@require_page("logs")
def logs_page():
    return render_template("logs/index.html", title="Canlı Loglar", page_title="AlmaLinux Sunucu Canlı Journal Logları",
                           active_tab="logs", log_lines=journal.classified_lines("all"))
