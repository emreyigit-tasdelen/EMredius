# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import journal


def test_logs_escaped_and_classified(client, monkeypatch):
    monkeypatch.setattr(journal, "run_cmd", lambda cmd: (0, "x sshd <script>\nboom FAILED\nplain", ""))
    login_as(client, "superadmin")
    body = client.get("/logs").get_data(as_text=True)
    assert '<div class="log-line info">x sshd &lt;script&gt;</div>' in body
    assert '<div class="log-line err">boom FAILED</div>' in body and '<div class="log-line">plain</div>' in body
    data = client.get("/api/logs/stream?unit=radiusd;rm").get_json()
    assert data["count"] == 3 and "&lt;script&gt;" in data["html"]


def test_unit_sanitized(monkeypatch):
    seen = []
    monkeypatch.setattr(journal, "run_cmd", lambda cmd: seen.append(cmd) or (0, "", ""))
    journal.fetch_lines("--help; rm -rf /")
    assert seen[0] == ["journalctl", "-u", "helprm-rf", "-n", "200", "--no-pager"]
