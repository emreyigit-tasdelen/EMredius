# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Konfig Yönetimi (/configs, yalnızca süper yönetici): sürümlü yedek, fark, şablon, uyumluluk kuralı, tek/filo gönderim."""
import json
import re

from flask import Response, current_app, flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import configs as svc
from . import bp

_IP = re.compile(r"^[0-9a-fA-F:.]{3,45}$")


def _user():
    return session.get("user") or ""


def _key():
    return current_app.config["SECRET_KEY"]


def _audit(action, target, detail=""):
    log_admin_action(_user(), action, str(target)[:64], detail[:200], get_client_ip())


@bp.route("/configs")
@require_page("configs")
def configs_page():
    return render_template("configs/index.html", title="Konfig Yönetimi", page_title="Konfig Yönetimi", active_tab="configs",
                           comp=svc.compliance(), sched=svc.schedule_settings(), creds=svc.list_creds(), templates=svc.list_templates(), rules=svc.list_rules(),
                           stats=svc.overview(), kinds=svc.RULE_KINDS)


@bp.route("/configs/data")
@require_page("configs")
def configs_data():
    return jsonify({"success": True, "stats": svc.overview(), "devices": svc.compliance()})


@bp.route("/configs/<ip>/versions")
@require_page("configs")
def configs_versions(ip):
    return jsonify({"success": True, "versions": svc.list_versions(ip) if _IP.match(ip) else []})


@bp.route("/configs/<ip>/v/<int:version>")
@require_page("configs")
def configs_version(ip, version):
    v = svc.get_version(ip, version) if _IP.match(ip) else None
    if not v:
        return jsonify({"success": False, "error": "Sürüm yok."}), 404
    _audit("CONFIG_VIEW", ip, f"v{version}")
    return jsonify({"success": True, "version": version, "content": v["content"], "created": v["created"]})


@bp.route("/configs/<ip>/diff")
@require_page("configs")
def configs_diff(ip):
    d = svc.diff(ip, request.args.get("a", 0, type=int), request.args.get("b", 0, type=int)) if _IP.match(ip) else None
    if not d:
        return jsonify({"success": False, "error": "Sürüm yok."}), 404
    return jsonify(dict(d, success=True))


@bp.route("/configs/<ip>/backup", methods=["POST"])
@require_page("configs")
def configs_backup(ip):
    ver, err = svc.collect(ip, _key(), request.form.get("cred_id", type=int) or 0, _user()) if _IP.match(ip) else (None, "Geçersiz IP.")
    flash(err or f"{ip} için sürüm {ver} kaydedildi.", "danger" if err else "success")
    if not err:
        _audit("CONFIG_BACKUP", ip, f"v{ver}")
    return redirect("/configs")


@bp.route("/configs/<ip>/upload", methods=["POST"])
@require_page("configs")
def configs_upload(ip):
    ver, err = svc.manual_backup(ip, request.form.get("content", ""), _user(), request.form.get("note", "")) if _IP.match(ip) else (None, "Geçersiz IP.")
    flash(err or f"{ip} için sürüm {ver} kaydedildi.", "danger" if err else "success")
    if not err:
        _audit("CONFIG_UPLOAD", ip, f"v{ver}")
    return redirect("/configs")


@bp.route("/configs/cred/add", methods=["POST"])
@require_page("configs")
def configs_cred_add():
    f = request.form
    err = svc.add_cred(_key(), f.get("name"), f.get("username"), f.get("password"), f.get("enable", ""), f.get("port", 22))
    if err:
        flash(err, "danger")
    else:
        _audit("CONFIG_CRED_ADD", f.get("name", ""), "kimlik bilgisi eklendi")
    return redirect("/configs")


@bp.route("/configs/<kind>/<int:item_id>/delete", methods=["POST"])
@require_page("configs")
def configs_delete(kind, item_id):
    fn = {"cred": svc.delete_cred, "template": svc.delete_template, "rule": svc.delete_rule}.get(kind)
    if fn and fn(item_id):
        _audit("CONFIG_DELETE", f"{kind}:{item_id}")
    return redirect("/configs")


@bp.route("/configs/template/add", methods=["POST"])
@require_page("configs")
def configs_template_add():
    f = request.form
    err = svc.add_template(f.get("name"), f.get("body"), f.get("vendor", ""))
    if err:
        flash(err, "danger")
    else:
        _audit("CONFIG_TEMPLATE_ADD", f.get("name", ""))
    return redirect("/configs")


@bp.route("/configs/rule/add", methods=["POST"])
@require_page("configs")
def configs_rule_add():
    f = request.form
    err = svc.add_rule(f.get("name"), f.get("kind"), f.get("pattern"), f.get("vendor", ""))
    if err:
        flash(err, "danger")
    else:
        _audit("CONFIG_RULE_ADD", f.get("name", ""), f.get("pattern", ""))
    return redirect("/configs")


@bp.route("/configs/push", methods=["POST"])
@require_page("configs")
def configs_push():
    f = request.form
    variables = {}
    for line in (f.get("vars") or "").splitlines():
        k, _, v = line.partition("=")
        if k.strip():
            variables[k.strip()] = v.strip()
    ips = [i.strip() for i in re.split(r"[,\s]+", f.get("ips") or "") if _IP.match(i.strip())]
    dry = f.get("dry_run", "1") != "0" or f.get("confirm") != "GONDER"
    res = svc.push(ips, f.get("template_id", type=int) or 0, variables, _key(), f.get("cred_id", type=int) or 0, _user(), dry_run=dry)
    _audit("CONFIG_PUSH_DRY" if dry else "CONFIG_PUSH", f"{len(ips)} cihaz", f"şablon {f.get('template_id')} ok={sum(1 for r in res if r.get('ok'))}")
    return render_template("configs/push_result.html", title="Konfig Yönetimi", page_title="Gönderim sonucu", active_tab="configs",
                           results=res, dry=dry)


@bp.route("/configs/schedule", methods=["POST"])
@require_page("configs")
def configs_schedule():
    f = request.form
    from ...core import set_setting
    cred = f.get("cred_id", type=int) or 0
    hours = min(max(f.get("hours", 24, type=int), 1), 168)
    on = f.get("enabled") == "1" and cred > 0
    set_setting("cfg_backup_enabled", "1" if on else "0")
    set_setting("cfg_backup_cred_id", str(cred))
    set_setting("cfg_backup_hours", str(hours))
    _audit("CONFIG_SCHEDULE", "backup", f"açık={on} her {hours} sa kimlik={cred}")
    flash("Zamanlanmış yedek ayarı kaydedildi." if on or f.get("enabled") != "1" else "Zamanlanmış yedek için bir SSH kimliği seçin.", "success" if on or f.get("enabled") != "1" else "danger")
    return redirect("/configs")


@bp.route("/configs/export.<fmt>")
@require_page("configs")
def configs_export(fmt):
    rows = svc.compliance()
    if fmt not in ("csv", "json"):
        return jsonify({"success": False, "error": "Biçim csv veya json olmalı."}), 404
    _audit("CONFIG_EXPORT", fmt, f"{len(rows)} cihaz")
    if fmt == "json":
        return Response(json.dumps(rows, ensure_ascii=False, indent=1), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=compliance.json"})
    return Response(svc.compliance_csv(rows), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=compliance.csv"})
