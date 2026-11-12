# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Web terminal page (/cli, /terminal) and /api/cli/* (superadmin only; every execution is audit-logged)."""
from flask import jsonify, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import cli
from . import bp


@bp.route("/cli")
@bp.route("/terminal")
@require_page("cli")
def cli_page():
    return render_template("cli/index.html", catalog=cli.CATALOG, title="Web Terminal & CLI", page_title="Web Terminal & CLI", active_tab="cli")


@bp.route("/api/cli/execute", methods=["POST"])
@require_page("cli")
def api_cli_execute():
    cmd = (request.form.get("command") or "").strip()
    if not cmd:
        return jsonify({"success": False, "error": "Boş komut girilemez."})
    run, err = cli.check_command(cmd)
    if err:
        return jsonify({"success": False, "command": cmd, "returncode": -1, "error": err})
    res = cli.execute(run)
    log_admin_action(session.get("user"), "cli_execute", run[:120],
                     f"Exit: {res['returncode']}, Time: {res['duration_ms']}ms, Stdout: {len(res['stdout'])}b, "
                     f"Stderr: {len(res['stderr'])}b", get_client_ip())
    return jsonify(dict(res, success=True, command=run))


@bp.route("/api/cli/autocomplete", methods=["POST"])
@require_page("cli")
def api_cli_autocomplete():
    return jsonify({"success": True, "matches": cli.autocomplete(request.form.get("prefix"))})
