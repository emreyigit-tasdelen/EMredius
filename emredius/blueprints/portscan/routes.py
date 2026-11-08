# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Port scanner (/portscan): TCP connect scan of one host, single port, range or all 1-65535 ports.
The panel-wide simultaneous-scan limit is set here by the superadmin; there is no per-administrator limit."""
from flask import current_app, flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page, url_for
from ...services import portscan as svc
from . import bp


def _history_path():
    return current_app.config.get("PORTSCAN_HISTORY_PATH", "")


def _viewer():
    return session.get("user") or "", session.get("role") == "superadmin"


@bp.route("/portscan", methods=["GET", "POST"])
@require_page("portscan")
def portscan_page():
    if request.method == "GET":   # IP ve port tarama tek ekranda birleşti
        return redirect("/ip-scan")
    form = {"target": "", "ports": "", "preset": "common", "timeout": svc.DEFAULT_TIMEOUT}
    if request.method == "POST":
        form = {
            "target": (request.form.get("target") or "").strip()[:253],
            "ports": (request.form.get("ports") or "").strip()[:512],
            "preset": request.form.get("preset") or "common",
            "timeout": svc.parse_timeout(request.form.get("timeout")),
        }
        user, is_super = _viewer()
        try:
            ip = svc.resolve_target(form["target"], allow_public=is_super)
            ports = svc.parse_ports(form["ports"], form["preset"])
            job_id = svc.start_scan(ip, ports, form["timeout"], user=user, label=form["target"],
                                    client_ip=get_client_ip(), history_path=_history_path())
        except svc.ScanError as e:
            flash(str(e), "danger")
        else:
            return redirect(url_for("portscan_page", job=job_id))
    user, is_super = _viewer()
    job_id = request.args.get("job") or svc.running_job_id(user)
    job = svc.get_job(job_id, user, is_super, history_path=_history_path()) if job_id else None
    running = svc.running_jobs()
    return render_template("portscan/index.html", title="Port Tarama", page_title="Port Tarama (TCP)",
                           active_tab="portscan", job=job, form=form, presets=svc.PRESET_LABELS,
                           timeouts=svc.TIMEOUT_CHOICES, max_concurrent=svc.get_max_concurrent(),
                           max_limit=svc.MAX_CONCURRENT_LIMIT, running=running if is_super else [],
                           running_count=len(running), recent=svc.recent_jobs(user, is_super, _history_path()), is_super=is_super)


@bp.route("/portscan/settings", methods=["POST"])
@require_page("portscan", superadmin=True)
def portscan_settings():
    old = svc.get_max_concurrent()
    err = svc.set_max_concurrent(request.form.get("max_concurrent"))
    if err:
        flash(err, "danger")
    else:
        new = svc.get_max_concurrent()
        log_admin_action(_viewer()[0], "PORT_SCAN_SETTINGS", "portscan_max_concurrent", f"{old} -> {new}",
                         get_client_ip())
        flash(f"Eşzamanlı tarama sınırı {new} olarak kaydedildi.", "success")
    return redirect(url_for("portscan_page"))


@bp.route("/portscan/job/<job_id>")
@require_page("portscan")
def portscan_job(job_id):
    job = svc.get_job(job_id, *_viewer(), history_path=_history_path())
    if job is None:
        return jsonify({"success": False, "error": "Tarama bulunamadı."}), 404
    return jsonify({"success": True, "job": job})


@bp.route("/portscan/job/<job_id>/cancel", methods=["POST"])
@require_page("portscan")
def portscan_cancel(job_id):
    if not svc.cancel_job(job_id, *_viewer()):
        return jsonify({"success": False, "error": "Tarama bulunamadı."}), 404
    return jsonify({"success": True})


@bp.route("/portscan/job/<job_id>/delete", methods=["POST"])
@require_page("portscan", superadmin=True)
def portscan_delete(job_id):
    removed = svc.delete_history(_history_path(), job_id)
    if removed is None:
        return jsonify({"success": False, "error": "Tarama bulunamadı veya hâlâ çalışıyor."}), 404
    log_admin_action(_viewer()[0], "PORT_SCAN_DELETE", str(removed.get("label", ""))[:128],
                     f"tarama kaydı silindi (sahip: {removed.get('user', '-')}, id: {job_id})", get_client_ip())
    return jsonify({"success": True})
