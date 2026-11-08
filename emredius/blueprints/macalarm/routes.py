# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""MAC Alarmları (/macalarms): port flap, PoE aşımı, MAC taşınması, yeni MAC kuralları; olaylar Alarmlar panelinde de görünür."""
from flask import jsonify, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import alarms, macalarm as svc
from . import bp


@bp.route("/macalarms")
@require_page("macalarm")
def macalarm_page():
    return render_template("macalarm/index.html", title="MAC Alarmları", page_title="MAC Alarmları", active_tab="macalarm",
                           mail_on=alarms.mail_enabled())


@bp.route("/macalarms/data")
@require_page("macalarm")
def macalarm_data():
    return jsonify({"success": True, "rules": svc.list_rules(), "events": svc.list_events(), "mail_on": alarms.mail_enabled()})


@bp.route("/macalarms/rule/<rtype>", methods=["POST"])
@require_page("macalarm")
def macalarm_rule(rtype):
    f = request.form
    err = svc.set_rule(rtype, enabled=(f.get("enabled") == "1") if "enabled" in f else None, param=f.get("param"),
                       severity=f.get("severity"), email_to=f.get("email_to") if "email_to" in f else None)
    if not err:
        log_admin_action(session.get("user") or "", "MACALARM_RULE", rtype, ", ".join(f"{k}={v}" for k, v in f.items() if k != "_csrf_token")[:200],
                         get_client_ip())
    return jsonify({"success": not err, "error": err}), (400 if err else 200)


@bp.route("/macalarms/run", methods=["POST"])
@require_page("macalarm")
def macalarm_run():
    return jsonify({"success": True, "opened": svc.evaluate()})
