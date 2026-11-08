# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Smoke test over every registered route: anonymous access is refused, logged-in GETs never crash (DB is
unreachable in tests: pages degrade or answer 503, never 500), unsafe methods need a CSRF token."""
from conftest import login_as

PUBLIC = {"/download/ca.crt", "/download/ca-install.bat", "/login", "/login/2fa", "/logout", "/api/openapi.json", "/static/<path:filename>"}
# streams / downloads that legitimately need real files or a live process
SKIP_GET = {"/api/logs/stream"}


def _rules(app):
    for r in app.url_map.iter_rules():
        if r.rule.startswith("/static"):
            continue
        yield r


def test_anonymous_is_refused(app, client):
    for r in _rules(app):
        if r.arguments or r.rule in PUBLIC or "GET" not in r.methods:
            continue
        res = client.get(r.rule)
        assert res.status_code in (302, 401, 403), (r.rule, res.status_code)


def test_superadmin_get_pages_do_not_crash(app, client):
    from nms.common.db import init_db
    init_db(app.config["NMS_DB_PATH"])
    login_as(client, "superadmin")
    checked = 0
    for r in _rules(app):
        if r.arguments or "GET" not in r.methods or r.rule in SKIP_GET or r.rule == "/logout":
            continue
        res = client.get(r.rule)
        # 503 = page needs MariaDB (unreachable in tests); anything else 5xx is a bug
        assert res.status_code < 500 or res.status_code == 503, (r.rule, res.status_code, res.get_data(as_text=True)[:300])
        checked += 1
    assert checked > 40


def test_unsafe_methods_need_csrf(app, client):
    login_as(client, "superadmin")
    for r in _rules(app):
        if r.arguments or r.rule.startswith(("/login", "/api/v1/")):
            continue
        for m in ("POST", "DELETE"):
            if m in r.methods:
                res = client.open(r.rule, method=m, headers={"X-CSRF-Token": "wrong"})
                assert res.status_code in (302, 400, 403), (m, r.rule, res.status_code)


def test_sidebar_toggle_wired_once(app, client):
    """Each sidebar button has exactly one handler (a second one toggled the menu back on every click) and the
    page has a single backdrop (a duplicate without onclick covered the real one on mobile)."""
    import os
    login_as(client, "superadmin")
    html = client.get("/").get_data(as_text=True)
    assert html.count('id="sidebarBackdrop"') == 1
    assert html.count('data-on-click="toggleSidebar()"') == 2
    js = open(os.path.join(app.static_folder, "js", "security.js"), encoding="utf-8").read()
    assert "getElementById('sidebarToggleBtn')" not in js
