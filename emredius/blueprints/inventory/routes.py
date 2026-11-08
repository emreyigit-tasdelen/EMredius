# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Aktif Cihazlar (/inventory): kayıtlı IP aralıkları, keşif ve cihaz envanteri (arama/filtre, CSV/JSON, canlı yenileme)."""
import json

from flask import Response, current_app, flash, jsonify, redirect, render_template, request

from ...core import get_client_ip, log_admin_action, require_page, safe_int, url_for
from ...services import inventory as svc
from . import bp
from flask import session


def _user():
    return session.get("user") or ""


def _filters():
    a = request.args
    return {"q": (a.get("q") or "").strip()[:64], "vendor": (a.get("vendor") or "")[:64],
            "dtype": (a.get("type") or "")[:32], "status": a.get("status") if a.get("status") in ("ONLINE", "OFFLINE") else ""}


@bp.route("/inventory")
@require_page("inventory")
def inventory_page():
    return render_template("inventory/index.html", title="Aktif Cihazlar", page_title="Aktif Cihazlar",
                           active_tab="inventory", ranges=svc.list_ranges(), stats=svc.overview(),
                           filters=svc.device_filters(), devices=svc.list_devices(**_filters(), limit=500),
                           f=request.args)


@bp.route("/inventory/data")
@require_page("inventory")
def inventory_data():
    devs = svc.list_devices(**_filters())
    return jsonify({"success": True, "stats": svc.overview(), "devices": devs, "ranges": svc.list_ranges()})


@bp.route("/inventory/export.<fmt>")
@require_page("inventory")
def inventory_export(fmt):
    devs = svc.list_devices(**_filters())
    log_admin_action(_user(), "INVENTORY_EXPORT", fmt, f"{len(devs)} cihaz", get_client_ip())
    if fmt == "json":
        slim = [{k: d[k] for k in svc.CSV_COLS} for d in devs]
        return Response(json.dumps(slim, ensure_ascii=False, indent=1), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=inventory.json"})
    if fmt == "csv":
        return Response(svc.devices_csv(devs), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=inventory.csv"})
    return jsonify({"success": False, "error": "Biçim csv veya json olmalı."}), 404


@bp.route("/inventory/range/add", methods=["POST"])
@require_page("inventory")
def inventory_range_add():
    f = request.form
    err = svc.add_range(f.get("cidr", ""), f.get("name", ""), f.get("communities", "public"), f.get("interval_min", 0))
    if err:
        flash(err, "danger")
    else:
        log_admin_action(_user(), "INVENTORY_RANGE_ADD", (f.get("cidr") or "")[:64], "IP aralığı eklendi", get_client_ip())
        flash("IP aralığı eklendi.", "success")
    return redirect(url_for("inventory_page"))


@bp.route("/inventory/range/<int:range_id>/delete", methods=["POST"])
@require_page("inventory")
def inventory_range_delete(range_id):
    if svc.delete_range(range_id):
        log_admin_action(_user(), "INVENTORY_RANGE_DELETE", str(range_id), "IP aralığı silindi", get_client_ip())
        flash("Aralık silindi (bulunan cihazlar envanterde kalır).", "success")
    else:
        flash("Aralık bulunamadı.", "danger")
    return redirect(url_for("inventory_page"))


@bp.route("/inventory/range/<int:range_id>/scan", methods=["POST"])
@require_page("inventory")
def inventory_range_scan(range_id):
    started = svc.scan_range_async(range_id, history_path=current_app.config.get("IPSCAN_HISTORY_PATH", ""))
    if started:
        log_admin_action(_user(), "INVENTORY_SCAN", str(range_id), "keşif başlatıldı", get_client_ip())
    return jsonify({"success": started, "error": "" if started else "Bu aralık zaten taranıyor."})
