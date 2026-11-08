# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Kara Liste (/blacklist), Karantina (/quarantine), Uygulama Kayıtları (/enforcement).
Yalnızca kayıt/işaretleme: cihaza veya NAS'a hiçbir şey yazılmaz, veri silinmez."""
from flask import Response, jsonify, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import nacmarks as svc
from . import bp

_PAGES = {"blacklist": ("Kara Liste", "blacklist"), "quarantine": ("Karantina", "quarantine")}


def _list_page(kind):
    title = _PAGES[kind][0]
    return render_template("nacmarks/marks.html", title=title, page_title=title, active_tab=kind, kind=kind)


@bp.route("/blacklist")
@require_page("blacklist")
def blacklist_page():
    return _list_page("blacklist")


@bp.route("/quarantine")
@require_page("quarantine")
def quarantine_page():
    return _list_page("quarantine")


@bp.route("/enforcement")
@require_page("enforcement")
def enforcement_page():
    return render_template("nacmarks/enforcement.html", title="Uygulama Kayıtları", page_title="Uygulama Kayıtları",
                           active_tab="enforcement")


@bp.route("/enforcement/data")
@require_page("enforcement")
def enforcement_data():
    return jsonify({"success": True, "events": svc.list_events()})


def _register(kind):
    @require_page(kind)
    def data():
        return jsonify({"success": True, "marks": svc.list_marks(kind, active_only=request.args.get("all") != "1")})

    @require_page(kind)
    def add():
        actor = session.get("user") or ""
        try:
            mid = svc.add_mark(kind, request.form.get("mac"), request.form.get("username"), request.form.get("reason"),
                               request.form.get("hours"), actor, match=request.form.get("match") or "exact")
        except svc.MarkError as e:
            return jsonify({"success": False, "error": str(e)}), 400
        log_admin_action(actor, "NAC_" + kind.upper() + "_EKLE",
                         f"{request.form.get('mac', '')} {request.form.get('username', '')}".strip()[:128],
                         "kayıt/işaretleme (cihaza yazılmadı)", get_client_ip())
        return jsonify({"success": True, "id": mid})

    @require_page(kind)
    def release(mark_id):
        actor = session.get("user") or ""
        if not svc.release(mark_id, actor):
            return jsonify({"success": False, "error": "Kayıt bulunamadı."}), 404
        log_admin_action(actor, "NAC_" + kind.upper() + "_KALDIR", str(mark_id), "işaret kaldırıldı", get_client_ip())
        return jsonify({"success": True})

    @require_page(kind)
    def export():
        log_admin_action(session.get("user") or "", "NAC_" + kind.upper() + "_EXPORT", kind, "csv", get_client_ip())
        return Response(svc.export_csv(kind), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={kind}.csv"})

    @require_page(kind)
    def template():
        return Response(svc.TEMPLATE, mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={kind}-import-template.csv"})

    @require_page(kind)
    def import_():
        f = request.files.get("file")
        if not f:
            return jsonify({"success": False, "error": "Dosya seçilmedi."}), 400
        raw = f.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            return jsonify({"success": False, "error": "Dosya 2 MB sınırını aşıyor."}), 400
        actor = session.get("user") or ""
        res = svc.import_csv(kind, raw.decode("utf-8-sig", "replace"), actor)
        log_admin_action(actor, "NAC_" + kind.upper() + "_IMPORT", kind, f"{res['added']} eklendi, {len(res['errors'])} hata",
                         get_client_ip())
        return jsonify({"success": True, **res})

    bp.add_url_rule(f"/{kind}/export.csv", f"{kind}_export", export)
    bp.add_url_rule(f"/{kind}/import-template.csv", f"{kind}_template", template)
    bp.add_url_rule(f"/{kind}/import", f"{kind}_import", import_, methods=["POST"])
    bp.add_url_rule(f"/{kind}/data", f"{kind}_data", data)
    bp.add_url_rule(f"/{kind}/add", f"{kind}_add", add, methods=["POST"])
    bp.add_url_rule(f"/{kind}/<int:mark_id>/release", f"{kind}_release", release, methods=["POST"])


for _k in _PAGES:
    _register(_k)
