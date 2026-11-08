# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Ekipman Sağlığı & Trafik (/health): CPU/bellek/sıcaklık, geçmiş grafik, en yoğun arayüzler; canlı yenileme, CSV/JSON."""
import json

from flask import Response, jsonify, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import health as svc, radiolink as rl
from . import bp


def _rows(kind):
    q = (request.args.get("q") or "")[:64]
    return svc.health_rows(q=q) if kind == "health" else svc.traffic_rows(q=q) if kind == "traffic" else None


@bp.route("/health")
@require_page("health")
def health_page():
    return render_template("health/index.html", title="Ekipman Sağlığı & Trafik", page_title="Ekipman Sağlığı & Trafik",
                           active_tab="health", stats=svc.overview())


@bp.route("/health/data/<kind>")
@require_page("health")
def health_data(kind):
    if kind == "history":
        return jsonify({"success": True, "rows": svc.history(request.args.get("device", 0, type=int),
                                                             request.args.get("hours", 24, type=int))})
    rows = _rows(kind)
    if rows is None:
        return jsonify({"success": False, "error": "Geçersiz tür."}), 404
    return jsonify({"success": True, "rows": rows, "stats": svc.overview()})


@bp.route("/health/export/<kind>.<fmt>")
@require_page("health")
def health_export(kind, fmt):
    rows = _rows(kind)
    if rows is None or fmt not in ("csv", "json"):
        return jsonify({"success": False, "error": "Tür health/traffic, biçim csv/json olmalı."}), 404
    log_admin_action(session.get("user") or "", "HEALTH_EXPORT", f"{kind}.{fmt}", f"{len(rows)} kayıt", get_client_ip())
    if fmt == "json":
        return Response(json.dumps([{c: r.get(c, "") for c in svc.KINDS[kind]} for r in rows], ensure_ascii=False, indent=1),
                        mimetype="application/json", headers={"Content-Disposition": f"attachment; filename={kind}.json"})
    return Response(svc.to_csv(kind, rows), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={kind}.csv"})


@bp.route("/health/radiolink/data")
@require_page("health")
def radiolink_data():
    if request.args.get("history"):
        return jsonify({"success": True, "rows": rl.history(request.args.get("history", 0, type=int),
                                                           request.args.get("hours", 24, type=int))})
    return jsonify({"success": True, "rows": rl.list_links(q=(request.args.get("q") or "")[:64]), "stats": rl.overview()})


@bp.route("/health/radiolink/poll", methods=["POST"])
@require_page("health")
def radiolink_poll():
    log_admin_action(session.get("user") or "", "RADIOLINK_POLL", "", "radyolink yoklaması", get_client_ip())
    return jsonify({"success": rl.poll_async()})


@bp.route("/health/radiolink/export.<fmt>")
@require_page("health")
def radiolink_export(fmt):
    if fmt not in ("csv", "json"):
        return jsonify({"success": False, "error": "Biçim csv/json olmalı."}), 404
    rows = rl.list_links(q=(request.args.get("q") or "")[:64])
    log_admin_action(session.get("user") or "", "RADIOLINK_EXPORT", fmt, f"{len(rows)} kayıt", get_client_ip())
    if fmt == "json":
        return Response(json.dumps([{c: r.get(c, "") for c in rl.KINDS["links"]} for r in rows], ensure_ascii=False, indent=1),
                        mimetype="application/json", headers={"Content-Disposition": "attachment; filename=radiolink.json"})
    return Response(rl.to_csv(rows), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=radiolink.csv"})
