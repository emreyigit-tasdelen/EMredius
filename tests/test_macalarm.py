# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import alarms, equipment as eq, macalarm as ma, machist as mh, macscan as ms


def _port(c, oper):
    eq.save_device_data(c, "10.0.0.1", [{"if_index": 1, "name": "Gi1/0/1", "descr": "", "alias": "", "if_type": 6, "speed_mbps": 1000,
                                         "admin_status": "up", "oper_status": oper, "mac": ""}], [], [])
    c.commit()


def _events(source="mac"):
    return alarms.list_events(source=source)


def test_rules_defaults_and_validation(app):
    with app.app_context():
        rules = {r["rtype"]: r for r in ma.list_rules()}
        assert set(rules) == {"port_flap", "poe_over", "mac_move", "new_mac"}
        assert all(r["enabled"] and r["email_to"] == "" for r in rules.values())  # bildirim yok
        assert ma.set_rule("poe_over", param=80, severity="CRITICAL") == ""
        assert ma.list_rules()[1]["param"] == 80
        assert ma.set_rule("poe_over", param=500)  # aralık dışı
        assert ma.set_rule("port_flap", param=1)
        assert ma.set_rule("nope", enabled=False)
        assert ma.set_rule("mac_move", email_to="a b@x") != ""
        assert ma.set_rule("mac_move", severity="X") != ""


def test_port_flap_alarm_and_resolve(app):
    with app.app_context():
        c = eq._db()
        ma.set_rule("port_flap", param=3)
        _port(c, "up")
        ma.evaluate(now=1000)
        for i, oper in enumerate(["down", "up", "down"]):
            _port(c, oper)
            ma.evaluate(now=1001 + i)
        ev = _events()
        assert len(ev) == 1 and "Port flap" in ev[0]["message"] and ev[0]["status"] != "resolved"
        ma.evaluate(now=1001 + 700)  # pencere geçti
        assert _events()[0]["status"] == "resolved"


def test_poe_over_alarm(app):
    with app.app_context():
        c = ms._db()
        ms.save_device(c, "10.0.0.1", [], [{"grp": 1, "budget_w": 100, "used_w": 95, "oper": "on"}], [])
        c.commit()
        assert ma.evaluate() == 1
        assert "PoE" in _events()[0]["message"]
        ms.save_device(c, "10.0.0.1", [], [{"grp": 1, "budget_w": 100, "used_w": 10, "oper": "on"}], [])
        c.commit()
        ma.evaluate()
        assert _events()[0]["status"] == "resolved"


def test_mac_move_and_new_alarm_respect_enabled(app):
    with app.app_context():
        r = lambda mac, dev, port: {"mac": mac, "device_ip": dev, "port": port, "vlan": 1, "uplink": False}  # noqa: E731
        mh.record(rows=[r("aa:bb:cc:00:00:01", "10.0.0.1", "Gi1/0/1")])
        ma.set_rule("new_mac", enabled=False)
        mh.record(rows=[r("aa:bb:cc:00:00:01", "10.0.0.2", "Gi1/0/2"), r("aa:bb:cc:00:00:02", "10.0.0.2", "Gi1/0/3")])
        assert ma.evaluate() == 1  # yalnızca taşınma
        assert "MAC taşındı" in _events()[0]["message"]
        assert ma.evaluate() == 0  # olaylar işlendi


def test_macalarm_pages(client):
    login_as(client, "superadmin")
    assert client.get("/macalarms").status_code == 200
    j = client.get("/macalarms/data").get_json()
    assert j["success"] and len(j["rules"]) == 4
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "tok"
    r = client.post("/macalarms/rule/poe_over", data={"param": "70", "_csrf_token": "tok"})
    assert r.status_code == 200 and r.get_json()["success"]
    assert client.post("/macalarms/rule/poe_over", data={"param": "0", "_csrf_token": "tok"}).status_code == 400
