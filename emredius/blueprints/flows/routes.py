# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Akış Analizi (/flows): NetFlow/IPFIX en çok konuşanlar, uygulamalar, zaman çizelgesi; canlı yenileme, CSV/JSON."""
import json

from flask import Response, jsonify, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import flows as svc
from . import bp


def _args():
    a = request.args
    g = a.get("group", "src")
    return (g if g in svc.GROUPS else "src"), (a.get("range") if a.get("range") in svc.RANGES else "1h"), (a.get("q") or "")[:64]


@bp.route("/flows")
@require_page("flows")
def flows_page():
    return render_template("flows/index.html", title="Akış Analizi", page_title="Akış Analizi", active_tab="flows",
                           stats=svc.overview())


@bp.route("/flows/data")
@require_page("flows")
def flows_data():
    g, rng, q = _args()
    return jsonify({"success": True, "stats": svc.overview(), "top": svc.top(g, rng, q=q), "timeline": svc.timeline(rng)})


@bp.route("/flows/export.<fmt>")
@require_page("flows")
def flows_export(fmt):
    g, rng, q = _args()
    rows = svc.top(g, rng, q=q, limit=200)
    if fmt not in ("csv", "json"):
        return jsonify({"success": False, "error": "Biçim csv veya json olmalı."}), 404
    log_admin_action(session.get("user") or "", "FLOWS_EXPORT", f"{g}.{fmt}", f"{len(rows)} satır", get_client_ip())
    if fmt == "json":
        return Response(json.dumps(rows, ensure_ascii=False, indent=1), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=flows.json"})
    return Response(svc.to_csv(rows), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=flows.csv"})
