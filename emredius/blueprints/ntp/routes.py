# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""NTP time server page (chrony status, upstream sources, device config snippets) and /api/ntp/* actions."""
from concurrent.futures import ThreadPoolExecutor

from flask import jsonify, render_template, session

from ...core import get_client_ip, get_server_ip, log_admin_action, require_page
from ...services import chrony
from . import bp


@bp.route("/system")
@bp.route("/ntp")
@require_page("ntp")
def ntp_page():
    # the three host queries are independent; run them side by side so the page waits for the slowest only
    with ThreadPoolExecutor(max_workers=3) as ex:
        tracking, sources, udp_123 = ex.submit(chrony.tracking_info), ex.submit(chrony.sources_list),             ex.submit(chrony.udp_123_listening)
        tracking, sources, udp_123 = tracking.result(), sources.result(), udp_123.result()
    return render_template("ntp/index.html", title="NTP Sunucusu", page_title="NTP Zaman Sunucusu", active_tab="ntp",
                           tracking=tracking, sources=sources, udp_123=udp_123, server_ip=get_server_ip())


@bp.route("/api/ntp/sync", methods=["POST"])
@require_page("ntp", "settings")
def api_ntp_sync():
    ok, msg = chrony.makestep()
    if ok:
        log_admin_action(session.get("user"), "NTP_EŞİTLE", "chronyc makestep", msg[:200], get_client_ip())
        return jsonify({"success": True, "output": msg, **chrony.status()})
    return jsonify({"success": False, "error": msg})


@bp.route("/api/ntp/status")
@require_page("ntp", "settings")
def api_ntp_status():
    return jsonify({"success": True, **chrony.status()})


@bp.route("/api/ntp/restart", methods=["POST"])
@require_page(superadmin=True)
def api_ntp_restart():
    ok, msg = chrony.restart()
    if ok:
        log_admin_action(session.get("user"), "NTP_YENİDEN_BAŞLAT", "chronyd", "", get_client_ip())
        return jsonify({"success": True, "output": msg, **chrony.status()})
    return jsonify({"success": False, "error": msg})
