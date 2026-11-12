# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import chrony

SOURCES = """MS Name/IP address         Stratum Poll Reach LastRx Last sample
===============================================================================
^* <evil>.pool                   2   6   377    35   -120us[ -150us] +/-   12ms"""


def test_ntp_page(client, monkeypatch):
    def run(cmd, timeout=15, input_text=None):
        if cmd[:1] == ["chronyc"]:
            # UDP command port (SELinux, see chrony.py), no reverse DNS, short timeout
            assert cmd[1:4] == ["-h", "127.0.0.1", "-n"] and timeout <= 5
            cmd = ["chronyc"] + cmd[4:]
        if cmd[:2] == ["chronyc", "sources"]:
            return 0, SOURCES, ""
        if cmd[:2] == ["chronyc", "tracking"]:
            return 0, "Stratum         : 3\nReference ID    : X (y)", ""
        return 0, "UNCONN 0 0 0.0.0.0:123 0.0.0.0:*", ""
    monkeypatch.setattr(chrony, "run_cmd", run)
    from emredius.blueprints.ntp import routes as ntp_routes
    monkeypatch.setattr(ntp_routes, "get_server_ip", lambda: "10.9.8.7")
    login_as(client, "helpdesk")
    assert client.get("/ntp").status_code == 302
    login_as(client, "superadmin")
    body = client.get("/system").get_data(as_text=True)
    assert "&lt;evil&gt;.pool" in body and "Stratum 3" in body and "UDP 123 Dinleniyor" in body
    # server IP comes from the host, not the legacy hard-coded 192.0.2.10
    assert "10.9.8.7" in body and "192.0.2.10" not in body


def test_makestep_runs_in_own_unit(monkeypatch):
    calls = []

    def run(cmd, timeout=15, input_text=None):
        calls.append(cmd)
        if cmd[:2] == ["systemctl", "show"]:
            return 0, "abc123\n", ""
        if cmd[0] == "journalctl":
            assert cmd[1] == "_SYSTEMD_INVOCATION_ID=abc123"
            return 0, "200 OK\n", ""
        return 0, "", ""
    monkeypatch.setattr(chrony, "run_cmd", run)
    assert chrony.makestep() == (True, "200 OK")
    assert calls[0] == ["systemctl", "start", "emredius-chrony-makestep.service"]
    assert not any(c[0] == "chronyc" for c in calls)  # panel never talks to chronyd for makestep itself

    def run_fail(cmd, timeout=15, input_text=None):
        if cmd[:2] == ["systemctl", "start"]:
            return 1, "", "Job failed."
        if cmd[:2] == ["systemctl", "show"]:
            return 0, "abc123\n", ""
        return 0, "506 Cannot talk to daemon\n", ""
    monkeypatch.setattr(chrony, "run_cmd", run_fail)
    assert chrony.makestep() == (False, "506 Cannot talk to daemon")


def test_ntp_actions_blocked_in_dry_run(client):
    tok = login_as(client, "superadmin")
    assert client.post("/api/ntp/sync", headers={"X-CSRF-Token": tok}).get_json()["success"] is False
    assert client.post("/api/ntp/restart", headers={"X-CSRF-Token": tok}).get_json()["success"] is False


def test_ntp_status_json(client, monkeypatch):
    def run(cmd, timeout=15, input_text=None):
        if cmd[-1] == "tracking":
            return 0, "Stratum         : 2\nLeap status     : Normal", ""
        return 0, SOURCES, ""
    monkeypatch.setattr(chrony, "run_cmd", run)
    login_as(client, "superadmin")
    data = client.get("/api/ntp/status").get_json()
    assert data["success"] and data["tracking"]["stratum"] == "2" and len(data["sources"]) == 1


NEW_NTP_DEVICES = [
    ("arista", "Arista EOS"), ("nxos", "Cisco NX-OS (Nexus)"), ("iosxr", "Cisco IOS-XR"),
    ("dell", "Dell SmartFabric OS10 (DNOS)"), ("nokia", "Nokia SR OS"),
    ("exos", "Extreme ExtremeXOS (EXOS)"), ("ruckus", "Ruckus / CommScope FastIron (ICX)"),
    ("checkpoint", "Check Point Gaia OS"), ("sophos", "Sophos Firewall (SFOS)"),
    ("alliedware", "Allied Telesis AlliedWare Plus"), ("reyee", "Ruijie / ReyeeOS"),
    ("f5", "F5 BIG-IP TMOS"), ("omniswitch", "Alcatel-Lucent Enterprise AOS (OmniSwitch)"),
]


def test_ntp_device_cards_and_filter(client, monkeypatch):
    import re
    from emredius.blueprints.ntp import routes as ntp_routes
    monkeypatch.setattr(ntp_routes, "get_server_ip", lambda: "10.9.8.7")
    login_as(client, "superadmin")
    body = client.get("/ntp").get_data(as_text=True)
    keys = re.findall(r'class="ntp-device-card" data-key="([^"]+)" data-category="([^"]+)" data-vendor="([^"]+)"', body)
    assert len(keys) == 23 and len({k[0] for k in keys}) == 23  # 10 existing + 13 new, no duplicates
    for key, name in NEW_NTP_DEVICES:
        assert f'data-key="{key}"' in body and name in body
        assert f"copyNtpConfig('{key}', this)" in body
    assert all(cat and vendor for _, cat, vendor in keys)
    for el in ("ntpDeviceSearch", "ntpBrandPills", "ntpTypePills", "ntpDevicePills", "ntpNoResult"):
        assert f'id="{el}"' in body
    assert "10.9.8.7" in body and "192.0.2.10" not in body
    js = client.get("/static/js/app.js").get_data(as_text=True)
    for key, _ in NEW_NTP_DEVICES:
        assert f"  {key}: `" in js


def test_ntp_filter_pills_toggle_off(client):
    login_as(client, "superadmin")
    js = client.get("/static/js/ntp.js").get_data(as_text=True)
    assert "ntpFilter.brand === k ? '' : k" in js and "ntpFilter.type === k ? '' : k" in js


def test_ntp_code_blocks_not_translated(client):
    login_as(client, "superadmin")
    body = client.get("/ntp").get_data(as_text=True)
    assert body.count('<div class="ntp-code-terminal notranslate" translate="no">') == 23
    assert 'class="ntp-code-terminal">' not in body
    js = client.get("/static/js/app.js").get_data(as_text=True)
    assert js.count("[translate=\"no\"], .notranslate") >= 2
