# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""MAC whitelist (MAB / IoT devices): list, add, delete."""
from flask import flash, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page, url_for
from ...services import macs as svc
from ...services.radius_users import ServiceError
from . import bp


def _back():
    return redirect(url_for("macs_page"))


@bp.route("/mac-auth")
@bp.route("/macs")
@require_page("macs")
def macs_page():
    macs, unknown = svc.list_macs()
    return render_template("macs/index.html", title="MAC Whitelist", page_title="MAC Authentication Bypass (MAB & IoT)",
                           active_tab="macs", macs=macs, unknown_attempts=unknown, desc_max_len=svc.MAC_DESC_MAX_LEN)


@bp.route("/mac/add", methods=["POST"])
@require_page("macs")
def add_mac_action():
    try:
        mac, vendor, vlan = svc.add_mac(request.form.get("mac"), request.form.get("description"),
                                        request.form.get("vlan_id"))
    except ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), "MAC_EKLE", mac, f"Üretici: {vendor}, VLAN: {vlan or '-'}", get_client_ip())
    flash(f"MAC '{mac}' ({vendor}) başarıyla izinli listeye eklendi.", "success")
    return _back()


@bp.route("/mac/delete/<mac>", methods=["POST"])
@require_page("macs")
def delete_mac_action(mac):
    try:
        mac = svc.delete_mac(mac)
    except ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), "MAC_SİL", mac, "MAC whitelist kaydı silindi", get_client_ip())
    flash(f"'{mac}' silindi.", "success")
    return _back()
