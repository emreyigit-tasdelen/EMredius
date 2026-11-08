# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Raporlar (/reports): NetFlow top-talker raporu, anında ve zamanlanmış CSV/PDF; e-posta varsayılan kapalı."""
from flask import Response, flash, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import flows, reports as svc
from . import bp


def _user():
    return session.get("user") or ""


@bp.route("/reports")
@require_page("reports")
def reports_page():
    return render_template("reports/index.html", title="Raporlar", page_title="Raporlar", active_tab="reports",
                           schedules=svc.list_schedules(), runs=svc.list_runs(), windows=list(flows.WINDOWS),
                           mail_on=svc.mail_enabled(), human=svc.human)


@bp.route("/reports/generate", methods=["POST"])
@require_page("reports")
def reports_generate():
    f = request.form
    rid, err = svc.generate("NetFlow top-talker", f.get("window", "24h"), f.get("fmt", "csv"))
    if err:
        flash(err, "danger")
    else:
        log_admin_action(_user(), "REPORT_GENERATE", str(rid), f"{f.get('window')} {f.get('fmt')}", get_client_ip())
    return redirect("/reports")


@bp.route("/reports/schedule/add", methods=["POST"])
@require_page("reports")
def reports_schedule_add():
    f = request.form
    err = svc.add_schedule(f.get("name"), f.get("window"), f.get("fmt"), f.get("every"), f.get("email_to", ""))
    if err:
        flash(err, "danger")
    else:
        log_admin_action(_user(), "REPORT_SCHEDULE_ADD", (f.get("name") or "")[:64], f"{f.get('window')} {f.get('fmt')} {f.get('every')}",
                         get_client_ip())
    return redirect("/reports")


@bp.route("/reports/schedule/<int:sid>/<action>", methods=["POST"])
@require_page("reports")
def reports_schedule_action(sid, action):
    if svc.schedule_action(sid, action):
        log_admin_action(_user(), "REPORT_SCHEDULE_" + action.upper(), str(sid), "rapor zamanlaması", get_client_ip())
    return redirect("/reports")


@bp.route("/reports/download/<int:run_id>")
@require_page("reports")
def reports_download(run_id):
    r = svc.get_run(run_id)
    if not r:
        return Response("Rapor yok.", status=404)
    name, fmt, content = r
    return Response(content, mimetype="application/pdf" if fmt == "pdf" else "text/csv",
                    headers={"Content-Disposition": f"attachment; filename=rapor_{run_id}.{fmt}"})
