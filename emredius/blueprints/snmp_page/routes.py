# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""SNMP NMS page (data from the NMS SQLite DB; device/alarm CRUD goes through the NMS /api/snmp/* blueprint)."""
from flask import Response, flash, jsonify, render_template, request

from ...core import get_server_ip, require_page
from ...services import snmp as svc
from ...services import snmp_live
from . import bp


@bp.route("/snmp")
@require_page("snmp")
def snmp_page():
    data, error = svc.page_data()
    if error:
        flash(error, "danger")
    return render_template("snmp/index.html", title="SNMP NMS / Ağ İzleme",
                           page_title="SNMP NMS / Çok Markalı Ağ İzleme Platformu", active_tab="snmp",
                           server_ip=get_server_ip(), **data)


@bp.route("/snmp/topology.json")
@require_page("snmp")
def snmp_topology_json():
    resp = jsonify(svc.topology_live(force=request.args.get("force") == "1"))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.route("/snmp/topology/stream")
@require_page("snmp")
def snmp_topology_stream():
    """SSE: pushes the topology snapshot whenever a device's reachability/health changes."""
    gen = snmp_live.open_stream()
    if gen is None:
        return jsonify(error="busy"), 503
    return Response(gen, mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache, no-store", "X-Accel-Buffering": "no", "Connection": "keep-alive"})
