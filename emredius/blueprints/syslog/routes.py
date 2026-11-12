# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Syslog toplama ve arama (/syslog): filtre, sayfalama, CSV dışa aktarma, saklama süresi ayarı.
Veri ayrı toplayıcı serviste (nms/syslogd); bu sayfa yalnızca okur."""
from flask import Response, flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import syslog as svc
from ...services.syslog import FACILITIES, SEVERITIES
from . import bp


@bp.route("/syslog")
@require_page("syslog")
def syslog_page():
    f = svc.parse_filters(request.args)
    data, error = svc.search(f)
    return render_template("syslog/index.html", title="Syslog", page_title="Syslog", active_tab="syslog", data=data,
                           error=error, f=f, facilities=FACILITIES, severities=SEVERITIES, settings=svc.get_settings(),
                           args=request.args)


@bp.route("/syslog/data")
@require_page("syslog")
def syslog_data():
    data, error = svc.search(svc.parse_filters(request.args))
    if error:
        return jsonify({"success": False, "error": error}), 503
    return jsonify({"success": True, "data": data})


@bp.route("/syslog/export.csv")
@require_page("syslog")
def syslog_export():
    try:
        body = svc.export_csv(svc.parse_filters(request.args))
    except Exception:  # noqa: BLE001
        return jsonify({"success": False, "error": "Syslog verisi okunamadı."}), 503
    return Response(body, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=syslog.csv"})


@bp.route("/syslog/settings", methods=["POST"])
@require_page("syslog", superadmin=True)
def syslog_settings():
    err = svc.save_settings(request.form.get("retention_days"), request.form.get("allowed_sources", ""))
    if err:
        flash(err, "danger")
    else:
        log_admin_action(session.get("user") or "", "SYSLOG_SETTINGS", "syslog",
                         "saklama %s gün" % request.form.get("retention_days"), get_client_ip())
        flash("Syslog ayarları kaydedildi.", "success")
    return redirect("/syslog")
