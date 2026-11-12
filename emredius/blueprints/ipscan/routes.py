# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""IP scan (/ip-scan): host discovery on any network, as a background job with progress and a stop button.
Each administrator may run up to N scans at once (N set here by the superadmin) and sees only their own scans;
the superadmin also sees every running scan. The last 20 scans per administrator are kept."""
from urllib.parse import urlencode

from flask import current_app, flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, get_server_ip, log_admin_action, require_page, safe_int, url_for
from ...services import ipscan as svc
from ...services import portscan as psvc
from . import bp


def _viewer():
    return session.get("user") or "", session.get("role") == "superadmin"


def _history_path():
    return current_app.config.get("IPSCAN_HISTORY_PATH", "")


def _default_target():
    ip = get_server_ip()
    return ip.rsplit(".", 1)[0] + ".0/24" if ip else ""


def _parse_ports(form):
    """(ports|None, timeout, error) from the 'port_mode' / 'ports' / 'port_timeout' form fields."""
    mode = (form.get("port_mode") or "off").strip()
    timeout = psvc.parse_timeout(form.get("port_timeout"))
    if mode == "off":
        return None, timeout, None
    try:
        if mode == "custom":
            return psvc.parse_ports((form.get("ports") or "").strip()[:512], ""), timeout, None
        return psvc.parse_ports("", mode), timeout, None
    except psvc.ScanError as e:
        return None, timeout, str(e)


@bp.route("/ip-scan/start", methods=["POST"])
@require_page("ipscan", "portscan")
def ipscan_start():
    """Starts a scan without leaving the page; the page then shows ?job=<id>."""
    target = (request.form.get("target") or "").strip()[:64]
    net, err = svc.parse_target(target)
    if err:
        return jsonify({"success": False, "error": err}), 400
    ports, port_timeout, perr = _parse_ports(request.form)
    if perr:
        return jsonify({"success": False, "error": perr}), 400
    user, is_super = _viewer()
    try:
        job_id = svc.start_scan(net, user=user, resolve_names=request.form.get("resolve_names") == "1",
                                client_ip=get_client_ip(), history_path=_history_path(), ports=ports,
                                port_timeout=port_timeout, allow_public=is_super)
    except svc.ScanError as e:
        return jsonify({"success": False, "error": str(e)}), 409
    keep = {"job": job_id, "target": target, "port_mode": request.form.get("port_mode") or "off",
            "ports": (request.form.get("ports") or "")[:512], "port_timeout": port_timeout,
            "resolve_names": "1" if request.form.get("resolve_names") == "1" else "0"}
    return jsonify({"success": True, "job_id": job_id, "message": f"{net} taraması başlatıldı.",
                    "redirect": "/ip-scan?" + urlencode(keep)})


@bp.route("/ip-scan", methods=["GET", "POST"])
@require_page("ipscan", "portscan")
def ipscan_page():
    target = (request.args.get("target") or "").strip()[:64] or _default_target()
    resolve_names = request.args.get("resolve_names", "1") != "0"
    port_form = {"mode": request.args.get("port_mode") if request.args.get("port_mode") in
                 ("off", "custom", *psvc.PRESETS) else "off",
                 "ports": (request.args.get("ports") or "")[:512],
                 "timeout": psvc.parse_timeout(request.args.get("port_timeout"))}
    if request.method == "POST":
        target = (request.form.get("target") or "").strip()[:64]
        resolve_names = request.form.get("resolve_names") == "1"
        net, err = svc.parse_target(target)
        if err:
            flash(err, "danger")
        else:
            try:
                job_id = svc.start_scan(net, user=_viewer()[0], resolve_names=resolve_names,
                                        client_ip=get_client_ip(), history_path=_history_path())
            except svc.ScanError as e:
                flash(str(e), "warning")
            else:
                return redirect(url_for("ipscan_page", job=job_id))
    user, is_super = _viewer()
    job_id = request.args.get("job") or svc.running_job_id(user)
    job = svc.get_job(job_id, user, is_super, history_path=_history_path()) if job_id else None
    running = svc.running_jobs(None if is_super else user)
    return render_template("ipscan/index.html", title="IP Tarama", page_title="IP Tarama / Ağ Keşfi",
                           active_tab="ipscan", job=job, target=target, resolve_names=resolve_names,
                           max_concurrent=svc.get_max_concurrent(), max_limit=svc.MAX_CONCURRENT_LIMIT,
                           port_form=port_form, port_presets=psvc.PRESET_LABELS,
                           port_counts={k: len(v) for k, v in psvc.PRESETS.items()}, max_probes=svc.MAX_PORT_PROBES, port_timeouts=psvc.TIMEOUT_CHOICES,
                           running=running, own_running=sum(1 for r in running if r["user"] == user), is_super=is_super,
                           history=svc.list_history(user, _history_path()))


@bp.route("/ip-scan/settings", methods=["POST"])
@require_page("ipscan", superadmin=True)
def ipscan_settings():
    old = svc.get_max_concurrent()
    err = svc.set_max_concurrent(request.form.get("max_concurrent"))
    if err:
        return jsonify({"success": False, "error": err}), 400
    new = svc.get_max_concurrent()
    log_admin_action(_viewer()[0], "IP_SCAN_SETTINGS", "ipscan_max_concurrent", f"{old} -> {new}", get_client_ip())
    return jsonify({"success": True, "message": f"Eşzamanlı tarama sınırı {new} olarak kaydedildi."})


@bp.route("/ip-scan/job/<job_id>")
@require_page("ipscan", "portscan")
def ipscan_job(job_id):
    job = svc.get_job(job_id, *_viewer(), since=safe_int(request.args.get("since"), 0, min_value=0),
                      history_path=_history_path())
    if job is None:
        return jsonify({"success": False, "error": "Tarama bulunamadı."}), 404
    return jsonify({"success": True, "job": job})


@bp.route("/ip-scan/job/<job_id>/cancel", methods=["POST"])
@require_page("ipscan", "portscan")
def ipscan_cancel(job_id):
    if not svc.cancel_job(job_id, *_viewer()):
        return jsonify({"success": False, "error": "Tarama bulunamadı."}), 404
    return jsonify({"success": True})


@bp.route("/ip-scan/history/<scan_id>/delete", methods=["POST"])
@require_page("ipscan", superadmin=True)
def ipscan_history_delete(scan_id):
    removed = svc.delete_history(_history_path(), scan_id)
    if removed is None:
        return jsonify({"success": False, "error": "Tarama kaydı bulunamadı."}), 404
    log_admin_action(_viewer()[0], "IP_SCAN_DELETE", str(removed.get("network", ""))[:128],
                     f"tarama kaydı silindi (sahip: {removed.get('user', '-')}, id: {scan_id})", get_client_ip())
    return jsonify({"success": True})
