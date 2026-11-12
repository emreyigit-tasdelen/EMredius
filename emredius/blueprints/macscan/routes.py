# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""MAC Tarama (/macscan): cihaz -> port -> MAC -> üretici/IP/kullanıcı -> PoE tek tabloda; canlı yenileme, arama, CSV/JSON."""
import json

from flask import Response, jsonify, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import macscan as svc
from . import bp


def _rows():
    a = request.args
    return svc.list_rows(device_ip=(a.get("device") or "")[:45], q=(a.get("q") or "")[:64], vlan=a.get("vlan", ""),
                         access_only=a.get("access") == "1", poe_only=a.get("poe") == "1")


@bp.route("/macscan")
@require_page("macscan")
def macscan_page():
    return render_template("macscan/index.html", title="MAC Tarama", page_title="MAC Tarama", active_tab="macscan",
                           f=request.args, stats=svc.overview())


@bp.route("/macscan/data")
@require_page("macscan")
def macscan_data():
    rows = _rows()
    return jsonify({"success": True, "rows": rows[:2000], "total": len(rows), "stats": svc.overview(),
                    "poe": svc.list_poe(device_ip=(request.args.get("device") or "")[:45])})


@bp.route("/macscan/scan", methods=["POST"])
@require_page("macscan")
def macscan_scan():
    started = svc.scan_async()
    if started:
        log_admin_action(session.get("user") or "", "MACSCAN_RUN", "-", "MAC/PoE/ARP taraması başlatıldı", get_client_ip())
    return jsonify({"success": started, "error": "" if started else "Tarama zaten çalışıyor."})


@bp.route("/macscan/export.<fmt>")
@require_page("macscan")
def macscan_export(fmt):
    if fmt not in ("csv", "json"):
        return jsonify({"success": False, "error": "Biçim csv veya json olmalı."}), 404
    rows = _rows()
    log_admin_action(session.get("user") or "", "MACSCAN_EXPORT", f"macscan.{fmt}", f"{len(rows)} kayıt", get_client_ip())
    if fmt == "json":
        return Response(json.dumps([{c: r.get(c, "") for c in svc.COLS} for r in rows], ensure_ascii=False, indent=1),
                        mimetype="application/json", headers={"Content-Disposition": "attachment; filename=macscan.json"})
    return Response(svc.to_csv(rows), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=macscan.csv"})
