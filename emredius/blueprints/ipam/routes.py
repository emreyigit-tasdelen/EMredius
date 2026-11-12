# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""IPAM (/ipam): alt ağ planı, doluluk, boş adresler, keşifle karşılaştırma; canlı yenileme, CSV/JSON."""
import json
import re

from flask import Response, flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import ipam as svc
from . import bp

_CIDR = re.compile(r"^[0-9.]{7,15}/\d{1,2}$")


def _user():
    return session.get("user") or ""


@bp.route("/ipam")
@require_page("ipam")
def ipam_page():
    return render_template("ipam/index.html", title="IPAM", page_title="IPAM", active_tab="ipam", subnets=svc.list_subnets(request.args.get("q", "")[:64]),
                           stats=svc.overview(), kinds=svc.KINDS, f=request.args)


@bp.route("/ipam/data")
@require_page("ipam")
def ipam_data():
    return jsonify({"success": True, "stats": svc.overview(), "subnets": svc.list_subnets(request.args.get("q", "")[:64])})


@bp.route("/ipam/detail")
@require_page("ipam")
def ipam_detail():
    cidr = (request.args.get("cidr") or "")[:20]
    rows = svc.compare(cidr) if _CIDR.match(cidr) else None
    if rows is None:
        return jsonify({"success": False, "error": "Geçersiz alt ağ."}), 400
    return jsonify({"success": True, "rows": rows[:3000], "total": len(rows), "free": svc.free_addresses(cidr)})


@bp.route("/ipam/subnet/add", methods=["POST"])
@require_page("ipam")
def ipam_subnet_add():
    f = request.form
    err = svc.add_subnet(f.get("cidr"), f.get("name"), f.get("vlan"), f.get("gateway", ""), f.get("site", ""), f.get("note", ""))
    if err:
        flash(err, "danger")
    else:
        log_admin_action(_user(), "IPAM_SUBNET_ADD", (f.get("cidr") or "")[:32], (f.get("name") or "")[:64], get_client_ip())
    return redirect("/ipam")


@bp.route("/ipam/subnet/<int:sid>/delete", methods=["POST"])
@require_page("ipam")
def ipam_subnet_delete(sid):
    if svc.delete_subnet(sid):
        log_admin_action(_user(), "IPAM_SUBNET_DELETE", str(sid), "alt ağ silindi", get_client_ip())
    return redirect("/ipam")


@bp.route("/ipam/addr/add", methods=["POST"])
@require_page("ipam")
def ipam_addr_add():
    f = request.form
    err = svc.add_addr(f.get("ip"), f.get("name"), f.get("owner", ""), f.get("kind", "static"), f.get("note", ""))
    if err:
        flash(err, "danger")
    else:
        log_admin_action(_user(), "IPAM_ADDR_ADD", (f.get("ip") or "")[:45], (f.get("name") or "")[:64], get_client_ip())
    return redirect("/ipam")


@bp.route("/ipam/addr/<int:aid>/delete", methods=["POST"])
@require_page("ipam")
def ipam_addr_delete(aid):
    if svc.delete_addr(aid):
        log_admin_action(_user(), "IPAM_ADDR_DELETE", str(aid), "adres kaydı silindi", get_client_ip())
    return jsonify({"success": True})


@bp.route("/ipam/export.<fmt>")
@require_page("ipam")
def ipam_export(fmt):
    rows = svc.list_subnets(request.args.get("q", "")[:64])
    if fmt not in ("csv", "json"):
        return jsonify({"success": False, "error": "Biçim csv veya json olmalı."}), 404
    log_admin_action(_user(), "IPAM_EXPORT", fmt, f"{len(rows)} alt ağ", get_client_ip())
    if fmt == "json":
        return Response(json.dumps([{c: r[c] for c in svc.CSV_COLS} for r in rows], ensure_ascii=False, indent=1),
                        mimetype="application/json", headers={"Content-Disposition": "attachment; filename=ipam.json"})
    return Response(svc.subnets_csv(rows), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=ipam.csv"})
