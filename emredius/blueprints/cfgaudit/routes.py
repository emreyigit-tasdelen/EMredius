# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Konfig Denetimi (/configs/audit, süper yönetici): sürümler arası fark + uyum raporu. Salt okunur."""
import json
import re

from flask import Response, jsonify, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import cfgaudit as svc, configs
from . import bp

_IP = re.compile(r"^[0-9a-fA-F:.]{3,45}$")


def _audit(action, target, detail=""):
    log_admin_action(session.get("user") or "", action, str(target)[:64], detail[:200], get_client_ip())


@bp.route("/configs/audit")
@require_page("configs")
def cfgaudit_page():
    return render_template("cfgaudit/index.html", title="Konfig Denetimi", page_title="Konfig Denetimi", active_tab="configs",
                           rep=svc.report(), changes=svc.recent_changes(30))


@bp.route("/configs/audit/diff/<ip>")
@require_page("configs")
def cfgaudit_diff(ip):
    if not _IP.match(ip):
        return jsonify({"success": False, "error": "Geçersiz IP."}), 400
    versions = configs.list_versions(ip)
    a, b = request.args.get("a", type=int), request.args.get("b", type=int)
    if a is None or b is None:                       # varsayılan: son iki sürüm
        if len(versions) < 2:
            return jsonify({"success": True, "versions": versions, "diff": None})
        b, a = versions[0]["version"], versions[1]["version"]
    d = svc.side_by_side(ip, a, b, request.args.get("ws") == "1", request.args.get("nc") == "1")
    if not d:
        return jsonify({"success": False, "error": "Sürüm yok."}), 404
    _audit("CONFIG_DIFF", ip, f"v{a}..v{b}")
    return jsonify({"success": True, "versions": versions, "diff": d})


@bp.route("/configs/audit/changes")
@require_page("configs")
def cfgaudit_changes():
    return jsonify({"success": True, "changes": svc.recent_changes(request.args.get("limit", 50, type=int))})


@bp.route("/configs/audit/report.<fmt>")
@require_page("configs")
def cfgaudit_report(fmt):
    if fmt not in ("csv", "json"):
        return jsonify({"success": False, "error": "Biçim csv veya json olmalı."}), 404
    rep = svc.report()
    _audit("CONFIG_AUDIT_EXPORT", fmt, f"{rep['summary']['devices']} cihaz")
    if fmt == "json":
        return Response(json.dumps(rep, ensure_ascii=False, indent=1), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=config_audit.json"})
    return Response(svc.report_csv(rep), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=config_audit.csv"})
