# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Logic of scripts/browser_check.py that needs no browser: route selection and the problem verdict."""
import importlib.util
import os

from conftest import ROOT

_spec = importlib.util.spec_from_file_location("browser_check", os.path.join(ROOT, "scripts", "browser_check.py"))
bc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bc)

CLEAN = {"path": "/x", "status": 200, "seconds": 0.3, "console": [], "pageerrors": [], "failed": [], "bad": [],
         "error": ""}


def test_collect_routes_skips_unsuitable_rules(app):
    routes = bc.collect_routes(app)
    assert "/login" in routes and len(routes) > 30
    assert not any(r.startswith(bc.SKIP_PREFIXES) or r in bc.SKIP for r in routes)
    assert not any("<" in r for r in routes)


def test_clean_page_has_no_problems():
    assert bc.evaluate(CLEAN, 10) == []


def test_problems_are_reported():
    page = dict(CLEAN, status=500, seconds=12.0, console=["boom"], pageerrors=["TypeError"],
                failed=["http://x/a.js net::ERR_FAILED"], bad=["404 http://x/b.css"], error="Timeout")
    kinds = " ".join(bc.evaluate(page, 10))
    for word in ("HTTP 500", "slow", "console: boom", "pageerror", "request failed", "sub-request: 404", "navigation"):
        assert word in kinds


def test_expected_status_is_tolerated():
    page = dict(CLEAN, path="/netflow/data", status=503, console=["Failed to load resource: 503"])
    assert bc.evaluate(page, 10) == []
    sub = dict(CLEAN, path="/netflow", console=["Failed to load resource: 503"], bad=["503 http://127.0.0.1:5100/netflow/data"])
    assert bc.evaluate(sub, 10) == []
