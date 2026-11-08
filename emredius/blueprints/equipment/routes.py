# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Ekipman & MAC Tabloları (/equipment): port envanteri, MAC tabloları, şasi/modüller, ön panel; canlı yenileme, CSV/JSON."""
import json

from flask import Response, jsonify, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import equipment as svc
from . import bp


def _user():
    return session.get("user") or ""


def _dev():
    return (request.args.get("device") or "")[:45]


def _rows(kind):
    a = request.args
    if kind == "ports":
        return svc.list_ports(device_ip=_dev(), q=(a.get("q") or "")[:64], state=a.get("state", ""))
    if kind == "macs":
        return svc.list_macs(device_ip=_dev(), port=(a.get("port") or "")[:64], q=(a.get("q") or "")[:64],
                             vlan=a.get("vlan", ""))
    if kind == "chassis":
        return svc.list_chassis(device_ip=_dev())
    return None


@bp.route("/equipment")
@require_page("equipment")
def equipment_page():
    return render_template("equipment/index.html", title="Ekipman & MAC Tabloları", page_title="Ekipman & MAC Tabloları",
                           active_tab="equipment", f=request.args, stats=svc.overview(), devices=svc.device_summary())


@bp.route("/equipment/data/<kind>")
@require_page("equipment")
def equipment_data(kind):
    if kind == "summary":
        return jsonify({"success": True, "stats": svc.overview(), "devices": svc.device_summary()})
    if kind == "panel":
        return jsonify({"success": True, "ports": svc.panel(_dev()), "chassis": svc.list_chassis(device_ip=_dev())})
    rows = _rows(kind)
    if rows is None:
        return jsonify({"success": False, "error": "Geçersiz tür."}), 404
    return jsonify({"success": True, "rows": rows[:2000], "total": len(rows), "stats": svc.overview()})


@bp.route("/equipment/discover", methods=["POST"])
@require_page("equipment")
def equipment_discover():
    started = svc.discover_async()
    if started:
        log_admin_action(_user(), "EQUIPMENT_DISCOVER", "-", "port/MAC/şasi taraması başlatıldı", get_client_ip())
    return jsonify({"success": started, "error": "" if started else "Tarama zaten çalışıyor."})


@bp.route("/equipment/export/<kind>.<fmt>")
@require_page("equipment")
def equipment_export(kind, fmt):
    rows = _rows(kind)
    if rows is None or fmt not in ("csv", "json"):
        return jsonify({"success": False, "error": "Tür ports/macs/chassis, biçim csv/json olmalı."}), 404
    log_admin_action(_user(), "EQUIPMENT_EXPORT", f"{kind}.{fmt}", f"{len(rows)} kayıt", get_client_ip())
    if fmt == "json":
        cols = svc.KINDS[kind]
        return Response(json.dumps([{c: r.get(c, "") for c in cols} for r in rows], ensure_ascii=False, indent=1),
                        mimetype="application/json", headers={"Content-Disposition": f"attachment; filename={kind}.json"})
    return Response(svc.to_csv(kind, rows), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={kind}.csv"})
