# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Alarmlar (/alarms): aktif/tüm alarmlar, onay/çözüm, eşik ve e-posta kuralları, trap olayları; canlı yenileme, CSV/JSON."""
import json

from flask import Response, flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import alarms as svc
from . import bp


def _user():
    return session.get("user") or ""


def _filters():
    a = request.args
    return {"status": a.get("status") if a.get("status") in svc.STATUSES else "",
            "severity": a.get("severity") if a.get("severity") in svc.SEVERITIES else "",
            "source": (a.get("source") or "")[:16], "q": (a.get("q") or "")[:64]}


def _creds():
    try:
        from ...services import configs
        return configs.list_creds()
    except Exception:  # noqa: BLE001
        return []


@bp.route("/alarms")
@require_page("alarms")
def alarms_page():
    return render_template("alarms/index.html", title="Alarmlar", page_title="Alarmlar", active_tab="alarms",
                           rules=svc.list_rules(), ssh=svc.ssh_settings(), creds=_creds(), stats=svc.overview(), metrics=svc.METRICS, severities=svc.SEVERITIES)


@bp.route("/alarms/data")
@require_page("alarms")
def alarms_data():
    return jsonify({"success": True, "stats": svc.overview(), "events": svc.list_events(**_filters()), "rules": svc.list_rules()})


@bp.route("/alarms/<event_id>/ack", methods=["POST"])
@require_page("alarms")
def alarms_ack(event_id):
    ok = event_id.isdigit() and svc.ack(int(event_id), _user())
    if ok:
        log_admin_action(_user(), "ALARM_ACK", event_id, "alarm onaylandı", get_client_ip())
    return jsonify({"success": bool(ok)})


@bp.route("/alarms/<event_id>/resolve", methods=["POST"])
@require_page("alarms")
def alarms_resolve(event_id):
    ok = event_id.isdigit() and svc.resolve(int(event_id))
    if ok:
        log_admin_action(_user(), "ALARM_RESOLVE", event_id, "alarm çözüldü", get_client_ip())
    return jsonify({"success": bool(ok)})


@bp.route("/alarms/rule/add", methods=["POST"])
@require_page("alarms")
def alarms_rule_add():
    f = request.form
    err = svc.add_rule(f.get("name"), f.get("metric"), f.get("threshold"), f.get("severity", "WARNING"), f.get("email_to", ""))
    if err:
        flash(err, "danger")
    else:
        log_admin_action(_user(), "ALARM_RULE_ADD", (f.get("name") or "")[:64], f"{f.get('metric')} {f.get('threshold')}", get_client_ip())
    return redirect("/alarms")


@bp.route("/alarms/rule/<int:rule_id>/<action>", methods=["POST"])
@require_page("alarms")
def alarms_rule_action(rule_id, action):
    if action == "delete" and svc.delete_rule(rule_id):
        log_admin_action(_user(), "ALARM_RULE_DELETE", str(rule_id), "kural silindi", get_client_ip())
    elif action == "toggle" and svc.toggle_rule(rule_id):
        log_admin_action(_user(), "ALARM_RULE_TOGGLE", str(rule_id), "kural aç/kapa", get_client_ip())
    return redirect("/alarms")


@bp.route("/alarms/ssh", methods=["POST"])
@require_page("alarms")
def alarms_ssh_settings():
    from ...core import set_setting
    f = request.form
    cred = f.get("cred_id", type=int) or 0
    on = f.get("enabled") == "1" and cred > 0
    set_setting("alarm_ssh_enabled", "1" if on else "0")
    set_setting("alarm_ssh_cred_id", str(cred))
    set_setting("alarm_ssh_minutes", str(min(max(f.get("minutes", 15, type=int), 5), 1440)))
    log_admin_action(_user(), "ALARM_SSH_SETTINGS", "ssh", f"açık={on} kimlik={cred}", get_client_ip())
    return redirect("/alarms")


@bp.route("/alarms/export.<fmt>")
@require_page("alarms")
def alarms_export(fmt):
    rows = svc.list_events(**_filters(), limit=5000)
    if fmt not in ("csv", "json"):
        return jsonify({"success": False, "error": "Biçim csv veya json olmalı."}), 404
    log_admin_action(_user(), "ALARM_EXPORT", fmt, f"{len(rows)} alarm", get_client_ip())
    if fmt == "json":
        return Response(json.dumps([{c: r.get(c, "") for c in svc.CSV_COLS} for r in rows], ensure_ascii=False, indent=1),
                        mimetype="application/json", headers={"Content-Disposition": "attachment; filename=alarms.json"})
    return Response(svc.events_csv(rows), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=alarms.csv"})
