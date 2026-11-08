# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""NAS clients (access points, switches, firewalls): list with live ping, add, delete. FreeRADIUS reloads after changes."""
from flask import flash, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page, restart_radiusd_async, url_for
from ...services import nas as svc
from ...services.radius_users import ServiceError
from . import bp


def _back():
    return redirect(url_for("nas_page"))


@bp.route("/nas")
@require_page("nas")
def nas_page():
    return render_template("nas/index.html", title="Ağ Cihazları", page_title="Ağ Donanımı (NAS) Yönetimi",
                           active_tab="nas", nas_list=svc.list_nas(), type_choices=svc.NAS_TYPE_CHOICES)


@bp.route("/nas/add", methods=["POST"])
@require_page("nas")
def add_nas_action():
    errors, d = svc.validate_nas(request.form)
    if errors:
        for e in errors:
            flash(e, "danger")
        return _back()
    try:
        svc.add_nas(d)
    except ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), "NAS_EKLE", d["nasname"],
                     f"Kısa ad: {d['shortname']}, Tip: {d['type']}, CoA portu: {d['port']}", get_client_ip())
    restart_radiusd_async()
    flash(f"'{d['shortname']}' ({d['nasname']}) başarıyla eklendi. FreeRADIUS istemci listesini yüklemek için yeniden "
          f"başlatılıyor (birkaç saniye sürebilir).", "success")
    return _back()


@bp.route("/nas/delete/<int:nas_id>", methods=["POST"])
@require_page("nas")
def delete_nas_action(nas_id):
    row = svc.delete_nas(nas_id)
    if not row:
        flash("Cihaz bulunamadı!", "danger")
        return _back()
    log_admin_action(session.get("user"), "NAS_SIL", row.get("nasname") or str(nas_id),
                     f"Kısa ad: {row.get('shortname') or '-'}", get_client_ip())
    restart_radiusd_async()
    flash(f"'{row.get('shortname') or row.get('nasname')}' cihazı silindi. FreeRADIUS değişikliği uygulamak için yeniden "
          f"başlatılıyor.", "success")
    return _back()
