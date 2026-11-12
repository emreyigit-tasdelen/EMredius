# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import system_services as svc


def _fake_run(calls):
    def run(cmd, timeout=15, input_text=None):
        calls.append(cmd)
        if cmd[:2] == ["systemctl", "show"]:
            return 0, "ActiveState=active\nSubState=running\nMainPID=42\nMemoryCurrent=10485760", ""
        if cmd[0] == "radiusd":
            return 1, "", "line1\n/etc/raddb/sites-enabled/default[12]: syntax error"
        return 0, "", ""
    return run


def test_panel_unit_from_config(app):
    assert svc.unit_of("radius-admin") == "emredius-panel.service"


def test_restart_radiusd_refuses_broken_config(monkeypatch):
    calls = []
    monkeypatch.setattr(svc, "run_cmd", _fake_run(calls))
    ok, msg = svc.restart("radiusd")
    assert not ok and "syntax error" in msg and ["systemctl", "restart", "radiusd.service"] not in calls


def test_services_page(client, monkeypatch):
    monkeypatch.setattr(svc, "run_cmd", _fake_run([]))
    monkeypatch.setattr(svc, "storage_usage", lambda k: "1.0 MB")
    login_as(client, "helpdesk")
    assert client.get("/services").status_code == 302
    login_as(client, "superadmin")
    body = client.get("/services").get_data(as_text=True)
    assert "emredius-panel.service" in body and "PID: <strong id=\"pid-val-radiusd\" style=\"color:#0f172a;\">42</strong>" in body
    assert client.get("/api/service/status/nope").status_code == 400


def test_reboot_superadmin_only_and_dry_run(client):
    with client.session_transaction() as sess:
        sess["role"] = "custom_ops"
    tok = login_as(client, "network_admin")
    assert client.post("/api/server/reboot", headers={"X-CSRF-Token": tok}).status_code == 403
    tok = login_as(client, "superadmin")
    j = client.post("/api/server/reboot", headers={"X-CSRF-Token": tok}).get_json()
    assert j["success"] is False and "SYSTEM_DRY_RUN" in j["message"]


def test_restart_radius_redirect_is_local(client, monkeypatch):
    monkeypatch.setattr(svc, "run_cmd", _fake_run([]))
    tok = login_as(client, "superadmin")
    r = client.post("/restart-radius", data={"_csrf_token": tok}, headers={"Referer": "https://evil.example/users"})
    assert r.status_code == 302 and r.headers["Location"] == "/users"
    assert client.get("/restart-radius").status_code == 405


def test_nms_entry_controls_new_unit_not_legacy():
    """The legacy enterprise-daemons unit is removed; starting it from the panel would fight emredius-nms for TCP 49."""
    from emredius.services import system_services as ss
    assert ss.unit_of("enterprise-daemons") == "emredius-nms.service"
    assert "enterprise-daemons.service" not in {v["unit"] for v in ss.SERVICES.values()}
