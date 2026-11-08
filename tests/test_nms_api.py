# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from nms.common.db import init_db


def test_nms_api_requires_session_and_page(app, client):
    init_db(app.config["NMS_DB_PATH"])
    assert client.get("/api/tacacs/status").status_code == 401
    login_as(client, "helpdesk")
    assert client.get("/api/snmp/devices").status_code == 403
    login_as(client, "network_admin")
    r = client.get("/api/tacacs/status")
    assert r.status_code == 200 and r.get_json()["running"] is False
    assert client.get("/api/snmp/devices").status_code == 200


def test_nms_api_csrf_and_db_path_ignored(app, client, tmp_path):
    init_db(app.config["NMS_DB_PATH"])
    tok = login_as(client, "network_admin")
    body = {"name": "sw1", "ip_cidr": "10.0.0.1/32", "shared_secret": "s3cret-Abc!", "vendor": "cisco"}
    assert client.post("/api/tacacs/clients", json=body).status_code == 400
    other = tmp_path / "other.db"
    r = client.post(f"/api/tacacs/clients?db_path={other}", json=body, headers={"X-CSRF-Token": tok})
    assert r.status_code in (200, 201), r.get_data(as_text=True)
    assert not other.exists()  # the DB path can no longer be chosen by the request
    assert "sw1" in [c["name"] for c in client.get("/api/tacacs/clients").get_json()]


def test_snmp_discovery_scan_uses_scan_network(app, client, monkeypatch):
    """The scan endpoint imported a CidrScanner class that never existed (500 on every scan)."""
    from nms.snmp import discovery
    init_db(app.config["NMS_DB_PATH"])
    seen = {}

    async def fake_scan(config, client=None):
        seen["config"] = config
        return discovery.DiscoveryScanResult(scanned_ips=4, discovered_devices=[
            discovery.DiscoveredDevice(ip="10.0.0.2", vendor="Cisco", sys_name="sw2")])

    monkeypatch.setattr(discovery, "scan_network", fake_scan)
    tok = login_as(client, "network_admin")
    h = {"X-CSRF-Token": tok}
    r = client.post("/api/snmp/discovery/scan", json={"cidr": "10.0.0.0/30", "community": "c0mm"}, headers=h)
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    assert d["total_found"] == 1 and d["devices"][0]["ip"] == "10.0.0.2" and d["devices"][0]["vendor"] == "Cisco"
    cfg = seen["config"]
    assert cfg.targets == "10.0.0.0/30" and cfg.v2c_communities == ["c0mm"] and cfg.persist_db is False
    # /16 runs as a background job; larger is rejected
    r = client.post("/api/snmp/discovery/scan", json={"cidr": "10.0.0.0/16"}, headers=h)
    assert r.status_code == 202 and r.get_json()["job_id"]
    r = client.post("/api/snmp/discovery/scan", json={"cidr": "10.0.0.0/15"}, headers=h)
    assert r.status_code == 400
    assert client.post("/api/snmp/discovery/scan", json={"cidr": ""}, headers=h).status_code == 400


def test_snmp_buttons_device_alarm_flow(app, client):
    """Add / delete device, ack alarm and an invalid port must give JSON (not an HTML 500) for the page buttons."""
    init_db(app.config["NMS_DB_PATH"])
    h = {"X-CSRF-Token": login_as(client, "network_admin")}
    r = client.post("/api/snmp/devices", json={"ip": "10.9.9.9", "port": None, "version": "v2c"}, headers=h)
    assert r.status_code == 200 and r.get_json()["success"] is True
    r = client.post("/api/snmp/devices", json={"ip": "10.9.9.8", "port": "abc", "version": "v2c"}, headers=h)
    assert r.status_code == 200, r.get_data(as_text=True)
    devs = {d["ip"]: d for d in client.get("/api/snmp/devices").get_json()}
    assert devs["10.9.9.9"]["port"] == 161 and devs["10.9.9.8"]["port"] == 161
    assert client.post("/api/snmp/devices", json={"ip": "", "version": "v2c"}, headers=h).status_code == 400
    r = client.delete(f"/api/snmp/devices/{devs['10.9.9.9']['id']}", headers=h)
    assert r.status_code == 200 and r.get_json()["success"] is True
    assert "10.9.9.9" not in [d["ip"] for d in client.get("/api/snmp/devices").get_json()]
    assert client.post("/api/snmp/alarms/1/ack", headers=h).get_json()["success"] is True
    r = client.post("/api/snmp/discovery/scan", json={"cidr": "10.0.0.0/30", "port": "x"}, headers=h)
    assert r.status_code != 500 or r.is_json


def test_snmp_js_buttons_have_handlers():
    """Every onclick handler used by the SNMP page exists, and fetches go through the error-aware helper."""
    import re
    html = open("emredius/templates/snmp/index.html", encoding="utf-8").read()
    js = open("emredius/static/js/snmp.js", encoding="utf-8").read()
    base = open("emredius/static/js/security.js", encoding="utf-8").read()
    for name in set(re.findall(r'onclick="([A-Za-z_]\w*)\(', html)):
        assert re.search(rf"function {name}\b|window\.{name}\s*=", js + base), name
    assert "querySelectorAll('.tab-btn')[2]" not in js  # chart tab button is not index 2
    assert "r => r.json()" not in js


def test_snmp_js_does_not_redeclare_modal_helpers():
    """`function openModal` in snmp.js replaced window.openModal with itself (infinite recursion, dead modal buttons)."""
    js = open("emredius/static/js/snmp.js", encoding="utf-8").read()
    assert "function openModal" not in js and "function closeModal" not in js


def test_discovery_chunks_are_lazy_for_huge_targets():
    from nms.web import routes_snmp as r
    assert r._count_targets("0.0.0.0/0") == 2**32 - 2
    first = next(r._iter_chunks("0.0.0.0/0"))
    assert len(first) == r.DISCOVERY_CHUNK and first[0] == "0.0.0.1"
    assert sum(len(c) for c in r._iter_chunks("10.0.0.0/22,10.1.0.5")) == 1022 + 1
