# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import inventory as inv, radiolink as rl


def test_parse_and_state():
    m = rl.parse_values("mikrotik", {"rssi": "72", "noise": b"95", "tx_rate": "300000000", "ccq": "90"})
    assert m["rssi"] == -72 and m["noise"] == -95 and m["snr"] == 23 and m["tx_rate"] == 300.0
    assert rl.state_of(m) == "ok"
    assert rl.state_of(rl.parse_values("ubiquiti", {"rssi": "-80", "ccq": "95"})) == "warn"
    assert rl.state_of(rl.parse_values("siklu", {})) == "nodata"
    assert rl.parse_values("ubiquiti", {"rssi": "abc"})["rssi"] is None


def test_detect_vendor():
    assert rl.detect_vendor({"sys_object_id": ".1.3.6.1.4.1.14988.1"}) == "mikrotik"
    assert rl.detect_vendor({"sys_object_id": "1.3.6.1.4.1.41112.1.4"}) == "ubiquiti"
    assert rl.detect_vendor({"vendor": "Cambium Networks"}) == "cambium"
    assert rl.detect_vendor({"vendor": "Cisco"}) == ""


def test_links_pages_api(app, client, monkeypatch):
    with app.app_context():
        c = inv._db()
        c.execute("INSERT INTO inv_devices (tenant_id,ip,sys_name,vendor,snmp_ok,snmp_community,status) "
                  "VALUES (1,'10.1.1.1','rl1','Ubiquiti',1,'public','ONLINE')")
        c.commit(); c.close()
        monkeypatch.setattr(rl, "poll_device", lambda ip, com, ven: rl.parse_values(ven, {"rssi": "-82", "noise": "-95", "ccq": "70"}))
        assert rl.poll_all() == {"devices": 1}
        rows = rl.list_links()
        assert len(rows) == 1 and rows[0]["state"] == "warn" and rows[0]["snr"] == 13
        assert len(rl.history(rows[0]["id"])) == 1 and rl.list_links(q="zzz") == []
        assert rl.overview()["warn"] == 1 and not rl.overview()["enabled"]
        assert "'=x" in rl.to_csv([dict(rows[0], name="=x")])
    login_as(client, "superadmin")
    assert client.get("/health").status_code == 200
    assert client.get("/health/radiolink/data").get_json()["rows"][0]["ip"] == "10.1.1.1"
    assert client.get("/health/radiolink/data?history=1").get_json()["success"]
    assert client.get("/health/radiolink/export.csv").status_code == 200
    assert client.get("/health/radiolink/export.json").status_code == 200
    assert client.get("/health/radiolink/export.x").status_code == 404
    login_as(client, "helpdesk")
    assert client.get("/health/radiolink/data").status_code in (302, 403)
