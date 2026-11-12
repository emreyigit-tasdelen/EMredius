# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Döngü Tespiti (/loops): topoloji halkaları ve MAC taşınması; canlı yenileme, CSV/JSON dışa aktarma."""
import json

from flask import Response, jsonify, render_template, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import loops as svc
from . import bp


def _rows(kind):
    return svc.ring_rows() if kind == "rings" else svc.mac_rows() if kind == "macs" else None


@bp.route("/loops")
@require_page("loops")
def loops_page():
    return render_template("loops/index.html", title="Döngü Tespiti", page_title="Döngü Tespiti", active_tab="loops",
                           stats=svc.overview())


@bp.route("/loops/data")
@require_page("loops")
def loops_data():
    return jsonify({"success": True, "stats": svc.overview(), "rings": svc.ring_rows(), "macs": svc.mac_rows()})


@bp.route("/loops/export/<kind>.<fmt>")
@require_page("loops")
def loops_export(kind, fmt):
    rows = _rows(kind)
    if rows is None or fmt not in ("csv", "json"):
        return jsonify({"success": False, "error": "Tür rings/macs, biçim csv/json olmalı."}), 404
    log_admin_action(session.get("user") or "", "LOOPS_EXPORT", f"{kind}.{fmt}", f"{len(rows)} kayıt", get_client_ip())
    if fmt == "json":
        return Response(json.dumps(rows, ensure_ascii=False, indent=1), mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename=loops_{kind}.json"})
    return Response(svc.to_csv(kind, rows), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=loops_{kind}.csv"})
