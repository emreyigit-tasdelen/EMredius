# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Anomaliler (/anomalies): RADIUS verisinden türetilen şüpheli davranışlar (salt okunur)."""
from flask import jsonify, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import anomalies as svc
from . import bp


def _days():
    try:
        return max(1, min(int(request.args.get("days", 1)), 30))
    except ValueError:
        return 1


@bp.route("/anomalies")
@require_page("anomalies")
def anomalies_page():
    return render_template("anomalies/index.html", title="Anomaliler", page_title="Anomaliler", active_tab="anomalies",
                           days=_days())


@bp.route("/anomalies/data")
@require_page("anomalies")
def anomalies_data():
    return jsonify({"success": True, **svc.detect(_days())})


@bp.route("/anomalies/rules", methods=["POST"])
@require_page("anomalies", superadmin=True)
def anomalies_rules():
    saved = svc.save_thresholds(request.form)
    log_admin_action(session.get("user") or "", "ANOMALI_KURAL", "anomalies", str(saved), get_client_ip())
    return jsonify({"success": True, "thresholds": {**svc.thresholds(), **saved}})
