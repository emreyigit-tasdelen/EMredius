# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""İzlenen IP'ler (/watch): ping ile durum/gecikme izleme, geçmiş grafik, CSV/JSON dışa aktarma."""
import json
import threading

from flask import Response, flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import watch as svc
from . import bp


def _user():
    return session.get("user") or ""


@bp.route("/watch")
@require_page("watch")
def watch_page():
    return render_template("watch/index.html", title="İzlenen IP'ler", page_title="İzlenen IP'ler", active_tab="watch",
                           targets=svc.list_targets(), stats=svc.overview(), f=request.args)


@bp.route("/watch/data")
@require_page("watch")
def watch_data():
    return jsonify({"success": True, "stats": svc.overview(), "targets": svc.list_targets(q=(request.args.get("q") or "")[:64])})


@bp.route("/watch/history/<int:target_id>")
@require_page("watch")
def watch_history(target_id):
    return jsonify({"success": True, "rows": svc.history(target_id)})


@bp.route("/watch/add", methods=["POST"])
@require_page("watch")
def watch_add():
    err = svc.add_target(request.form.get("ip", ""), request.form.get("name", ""))
    if err:
        flash(err, "danger")
    else:
        ip = (request.form.get("ip") or "").strip()[:45]
        log_admin_action(_user(), "WATCH_ADD", ip, "izlenen IP eklendi", get_client_ip())
        threading.Thread(target=svc.check_all, daemon=True).start()
    return redirect("/watch")


@bp.route("/watch/<int:target_id>/delete", methods=["POST"])
@require_page("watch")
def watch_delete(target_id):
    if svc.delete_target(target_id):
        log_admin_action(_user(), "WATCH_DELETE", str(target_id), "izlenen IP silindi", get_client_ip())
    return redirect("/watch")


@bp.route("/watch/check", methods=["POST"])
@require_page("watch")
def watch_check():
    threading.Thread(target=svc.check_all, daemon=True).start()
    return jsonify({"success": True})


@bp.route("/watch/export.<fmt>")
@require_page("watch")
def watch_export(fmt):
    rows = svc.list_targets(q=(request.args.get("q") or "")[:64])
    if fmt not in ("csv", "json"):
        return jsonify({"success": False, "error": "Biçim csv veya json olmalı."}), 404
    log_admin_action(_user(), "WATCH_EXPORT", fmt, f"{len(rows)} hedef", get_client_ip())
    if fmt == "json":
        return Response(json.dumps([{c: r.get(c) for c in svc.CSV_COLS} for r in rows], ensure_ascii=False, indent=1),
                        mimetype="application/json", headers={"Content-Disposition": "attachment; filename=watch.json"})
    return Response(svc.targets_csv(rows), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=watch.csv"})
