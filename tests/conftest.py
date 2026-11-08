# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import os
import sys

try:
    import pytest
except ImportError:  # tests/run_tests.py works without pytest
    pytest = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Never read the server's env file / secrets during tests
os.environ["EMREDIUS_ENV_FILE"] = os.devnull

from emredius import create_app  # noqa: E402

TEST_CONFIG = {
    "TESTING": True,
    "SECRET_KEY": "test-secret-key-0123456789abcdef0123456789",
    "SESSION_COOKIE_SECURE": False,
    # unreachable DB: connection is refused immediately, code paths must degrade gracefully
    "DB_HOST": "127.0.0.1",
    "DB_PORT": 1,
    "DB_PASSWORD": "",
    "START_BACKGROUND_JOBS": False,
    "SYSTEM_DRY_RUN": True,
}


def make_app(tmp_path):
    cfg = dict(TEST_CONFIG, NMS_DB_PATH=str(tmp_path / "nms.db"),
               IPSCAN_HISTORY_PATH=str(tmp_path / "ipscan_history.json"),
               PORTSCAN_HISTORY_PATH=str(tmp_path / "portscan_history.json"))
    app = create_app(cfg)

    # stand-ins for pages that later steps provide as blueprints
    if "dashboard" not in app.extensions["emredius_short_endpoints"] and "dashboard" not in app.view_functions:
        app.add_url_rule("/", "dashboard", lambda: "dashboard")

    from emredius.core import require_page

    @require_page("backups")
    def _backups_probe():
        return "backups-ok"

    @require_page("dashboard")
    def _dashboard_probe():
        return "dashboard-ok"

    app.add_url_rule("/probe/backups", "probe_backups", _backups_probe, methods=["GET", "POST"])
    app.add_url_rule("/probe/dashboard", "probe_dashboard", _dashboard_probe, methods=["GET", "POST"])
    return app


if pytest is not None:
    @pytest.fixture()
    def app(tmp_path):
        return make_app(tmp_path)

    @pytest.fixture()
    def client(app):
        return app.test_client()


def login_as(client, role, user="tester"):
    with client.session_transaction() as s:
        s["logged_in"] = True
        s["user"] = user
        s["role"] = role
        s["role_label"] = role
        s["_csrf_token"] = "tok"
    return "tok"
