# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Ağ Topolojisi (/topology): LLDP/CDP komşuluk haritası, canlı yenileme, CSV/JSON dışa aktarma."""
import json

from flask import Response, jsonify, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import topology as svc
from . import bp


@bp.route("/topology")
@require_page("topology")
def topology_page():
    return render_template("topology/index.html", title="Ağ Topolojisi", page_title="Ağ Topolojisi",
                           active_tab="topology", f=request.args)


@bp.route("/topology/data")
@require_page("topology")
def topology_data():
    g = svc.graph(q=(request.args.get("q") or "")[:64])
    g["success"] = True
    return jsonify(g)


@bp.route("/topology/discover", methods=["POST"])
@require_page("topology")
def topology_discover():
    started = svc.discover_async()
    if started:
        log_admin_action(session.get("user") or "", "TOPOLOGY_DISCOVER", "-", "komşuluk taraması başlatıldı", get_client_ip())
    return jsonify({"success": started, "error": "" if started else "Tarama zaten çalışıyor."})


@bp.route("/topology/export.<fmt>")
@require_page("topology")
def topology_export(fmt):
    links = svc.list_links()
    log_admin_action(session.get("user") or "", "TOPOLOGY_EXPORT", fmt, f"{len(links)} bağlantı", get_client_ip())
    if fmt == "json":
        return Response(json.dumps(svc.graph(), ensure_ascii=False, indent=1), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=topology.json"})
    if fmt == "csv":
        return Response(svc.links_csv(links), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=topology.csv"})
    return jsonify({"success": False, "error": "Biçim csv veya json olmalı."}), 404


@bp.route("/topology/type", methods=["POST"])
@require_page("topology")
def topology_set_type():
    """Düğümün cihaz türünü elle ata (type='auto' → otomatik tespite dön)."""
    d = request.get_json(silent=True) or request.form
    node, dtype = (d.get("node") or ""), (d.get("type") or "")
    ok, err = svc.set_override(node, dtype, session.get("user") or "")
    if ok:
        log_admin_action(session.get("user") or "", "TOPOLOGY_SET_TYPE", node[:64], dtype or "auto", get_client_ip())
    return jsonify({"success": ok, "error": err}), (200 if ok else 400)
