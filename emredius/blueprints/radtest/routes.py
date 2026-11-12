# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""RADIUS test tool (/test): radtest against the local server."""
from flask import flash, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import radtest as svc
from . import bp


@bp.route("/test", methods=["GET", "POST"])
@require_page("test")
def test_page():
    test_result = None
    username = ""
    secret = "testing123"
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        secret = (request.form.get("secret") or "testing123").strip()
        err = svc.validate(username, password, secret)
        if err:
            flash(err, "danger")
        else:
            test_result = svc.run_radtest(username, password, secret)
            log_admin_action(session.get("user"), "RADTEST", username[:128],
                             "Access-Accept" if test_result["success"] else "Access-Reject / hata", get_client_ip())
    return render_template("radtest/index.html", title="Test Aracı", page_title="Canlı RADIUS Doğrulama Aracı",
                           active_tab="test", test_result=test_result, username=username, secret=secret)
