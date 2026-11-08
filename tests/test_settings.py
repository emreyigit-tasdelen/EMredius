# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import chrony
from emredius.services import system_settings as svc

TRACKING = """Reference ID    : C0A80101 (ntp.local)
Stratum         : 3
System time     : 0.000012 seconds fast of NTP time
Last offset     : -0.000004 seconds
Leap status     : Normal"""

SOURCES = """MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^* time.cloudflare.com           3   6   377    35   -120us[ -150us] +/-   12ms
^+ 192.168.1.1                   2   6   377    34   +80us[  +80us] +/-   20ms"""


def test_chrony_parsers():
    t = chrony.parse_tracking(0, TRACKING)
    assert t["stratum"] == "3" and t["ref_id"].startswith("C0A80101") and t["last_offset"] == "-0.000004 seconds"
    assert chrony.parse_tracking(1, "")["is_synced"] is False
    s = chrony.parse_sources(SOURCES)
    assert [x["name"] for x in s] == ["time.cloudflare.com", "192.168.1.1"] and s[0]["state"] == "^*"
    assert chrony.parse_tracking(0, TRACKING, s)["is_synced"] is True
    # all sources unreachable: tracking still reports the stale reference with rc 0
    stale = chrony.parse_sources(SOURCES.replace("^*", "^?").replace("^+", "^?"))
    assert chrony.parse_tracking(0, TRACKING, stale)["is_synced"] is False
    assert chrony.parse_tracking(0, TRACKING.replace("Normal", "Not synchronised"))["is_synced"] is False
    named = chrony.parse_sources(SOURCES.replace("192.168.1.1  ", "pool.ntp.org"))
    m = chrony.merge_source_hosts(chrony.parse_sources(SOURCES), named)
    assert [x["host"] for x in m] == ["", "pool.ntp.org"]
    assert "host" not in chrony.merge_source_hosts(chrony.parse_sources(SOURCES), [])[0]


def test_validate_notifications():
    errors, d = svc.validate_notifications({"telegram_bot_token": "123456:" + "A" * 35, "telegram_chat_id": "-100123",
                                            "slack_webhook_url": "https://hooks.slack.com/services/X"})
    assert not errors and d["telegram_chat_id"] == "-100123"
    errors, _ = svc.validate_notifications({"telegram_bot_token": "x", "telegram_chat_id": "a b",
                                            "slack_webhook_url": "http://evil\" onmouseover=1"})
    assert len(errors) == 3
    assert svc.validate_notifications({})[0] == []


def test_validate_branding():
    assert svc.validate_branding({"company_brand_name": "Acme", "company_ssid_name": "Acme-WiFi", "api_token": ""})[0] == []
    errors, _ = svc.validate_branding({"company_brand_name": "", "company_ssid_name": "x" * 33, "api_token": "short"})
    assert len(errors) == 3


def test_dns(tmp_path, monkeypatch):
    conf = tmp_path / "resolv.conf"
    conf.write_text("search lan\nnameserver 10.0.0.1\nnameserver 10.0.0.2\nnameserver 10.0.0.3\n")
    assert svc.read_dns(str(conf)) == ["10.0.0.1", "10.0.0.2"]
    assert svc.read_dns(str(tmp_path / "none")) == ["", ""]
    for args in (("", ""), ("8.8.8.8", "evil\nnameserver 6.6.6.6")):
        try:
            svc.write_dns(str(conf), *args)
            assert False
        except svc.ServiceError:
            pass
    try:  # dry run (test config) never writes the file
        svc.write_dns(str(conf), "1.1.1.1", "")
        assert False
    except svc.ServiceError as e:
        assert "staging" in str(e)
    monkeypatch.setattr(svc, "is_dry_run", lambda: False)
    svc.write_dns(str(conf), "1.1.1.1", "9.9.9.9")
    assert svc.read_dns(str(conf)) == ["1.1.1.1", "9.9.9.9"]


def test_host_actions_blocked_in_dry_run():
    assert svc.reload_ssh()[0] is False and svc.reload_firewall()[0] is False
    assert svc.set_timezone("Europe/Istanbul")[0] is False
    assert svc.set_timezone("Mars/Base") == (False, "Geçersiz zaman dilimi.")
    assert chrony.makestep()[0] is False and chrony.restart()[0] is False


def test_settings_page_escapes_and_rbac(client, monkeypatch):
    monkeypatch.setattr(svc, "page_values", lambda: {"bot_token": '"><script>x</script>', "chat_id": "", "slack_wh": "",
                                                     "brand": "A&B", "ssid": "s", "api_token": "t" * 20})
    login_as(client, "network_admin")
    assert client.get("/settings").status_code == 302
    login_as(client, "superadmin")
    body = client.get("/settings").get_data(as_text=True)
    assert "&#34;&gt;&lt;script&gt;" in body and "A&amp;B" in body and "SYSTEM_DRY_RUN" in body


def test_settings_forms_do_not_blank_each_other(client, monkeypatch):
    saved = []
    monkeypatch.setattr(svc, "save", lambda values: saved.append(dict(values)))
    from emredius.blueprints.settings import routes
    monkeypatch.setattr(routes, "nms_settings_sync", lambda: None)
    tok = login_as(client, "superadmin")
    client.post("/settings", data={"_csrf_token": tok, "form": "brand", "company_brand_name": "Acme",
                                   "company_ssid_name": "Acme-WiFi", "api_token": ""})
    assert saved == [{"company_brand_name": "Acme", "company_ssid_name": "Acme-WiFi", "api_token": ""}]
    client.post("/settings", data={"_csrf_token": tok, "form": "notify", "telegram_bot_token": "bad"})
    assert len(saved) == 1
