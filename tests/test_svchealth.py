# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import svchealth as svc


def test_page_and_data(client):
    login_as(client, "superadmin")
    r = client.get("/svchealth")
    assert r.status_code == 200 and "FreeRADIUS" in r.get_data(as_text=True)
    j = client.get("/svchealth/data").get_json()
    assert j["success"] and j["summary"]["total"] == len(svc.CHECKS)


def test_requires_login(client):
    assert client.get("/svchealth").status_code in (302, 401)


def test_alert_only_after_two_fails_once_then_recovery():
    svc._state.clear()
    assert svc._mark("x", "down", "d", 1) is None
    assert svc._mark("x", "down", "d", 2) == "down"
    assert svc._mark("x", "down", "d", 3) is None  # tekrar alarm yok
    assert svc._mark("x", "up", "ok", 4) == "up"
    assert svc._mark("x", "up", "ok", 5) is None


def test_notify_off_by_default(monkeypatch):
    sent = []
    monkeypatch.setattr(svc, "send_alert", lambda m: sent.append(m))
    monkeypatch.setattr(svc, "send_email", lambda *a, **k: sent.append("mail"))
    monkeypatch.setattr(svc, "get_settings", lambda: dict(svc.SETTING_DEFAULTS))
    svc.notify_event("Servis", "down", "x")
    assert sent == []
    monkeypatch.setattr(svc, "get_settings", lambda: dict(svc.SETTING_DEFAULTS, svchealth_alert_enabled="1"))
    svc.notify_event("Servis", "down", "x")
    assert len(sent) == 1 and "SERVİS DÜŞTÜ" in sent[0]


def test_email_needs_config():
    ok, msg = svc.send_email("s", "b", dict(svc.SETTING_DEFAULTS))
    assert not ok and "SMTP" in msg


def test_settings_post_superadmin_only(client, monkeypatch):
    saved = {}
    monkeypatch.setattr(svc, "set_setting", lambda k, v: saved.__setitem__(k, v))
    tok = login_as(client, "helpdesk")
    r = client.post("/svchealth/settings", data={"_csrf_token": tok, "svchealth_alert_enabled": "on"})
    assert saved == {} and r.status_code in (302, 403)
    tok = login_as(client, "superadmin")
    client.post("/svchealth/settings", data={"_csrf_token": tok, "svchealth_alert_enabled": "on",
                                              "svchealth_smtp_password": ""})
    assert saved["svchealth_alert_enabled"] == "1" and saved["svchealth_email_enabled"] == "0"
    assert "svchealth_smtp_password" not in saved