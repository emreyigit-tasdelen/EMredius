# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import cfgaudit as ca, configs as cf, inventory as inv


def _dev(ip, vendor="Cisco"):
    c = inv._db()
    c.execute("INSERT INTO inv_devices (tenant_id,ip,sys_name,vendor,status) VALUES (1,?,?,?,'ONLINE')", (ip, "sw-" + ip[-1], vendor))
    c.commit(); c.close()


def _seed(app):
    with app.app_context():
        _dev("10.0.0.1"); _dev("10.0.0.2")
        body = "\n".join(f"l{i}" for i in range(20))
        cf.manual_backup("10.0.0.1", "hostname a\n! c\nservice password-encryption\n" + body + "\nend")
        cf.manual_backup("10.0.0.1", "hostname b\n! c\nservice password-encryption\n" + body + "\nntp x\nend")
        cf.manual_backup("10.0.0.2", "transport input telnet")
        cf.add_rule("şifreleme", "must_contain", r"^service password-encryption")
        cf.add_rule("telnet yok", "must_not_contain", r"transport input telnet")


def test_side_by_side_and_changes(app):
    _seed(app)
    with app.app_context():
        d = ca.side_by_side("10.0.0.1", 1, 2)
        assert d["added"] == 1 and d["changed"] == 1 and d["removed"] == 0 and any(r["op"] == "skip" for r in d["rows"])
        assert ca.side_by_side("10.0.0.1", 1, 9) is None and ca.side_by_side("10.0.0.1", 1, 2, tenant_id=2) is None
        assert ca.side_by_side("10.0.0.1", 1, 1)["same"]
        ch = ca.recent_changes()
        assert {c["ip"] for c in ch} == {"10.0.0.1", "10.0.0.2"} and [c for c in ch if c["version"] == 2][0]["added"] >= 2
        assert [c for c in ch if c["ip"] == "10.0.0.2"][0]["first"]


def test_report(app):
    _seed(app)
    with app.app_context():
        rep = ca.report()
        s = rep["summary"]
        assert s["devices"] == 2 and s["rules"] == 2 and s["failing"] == 1 and s["full"] == 1 and s["avg"] == 50
        assert rep["devices"][0]["ip"] == "10.0.0.2" and rep["devices"][0]["score"] == 0
        assert {r["name"]: r["pct"] for r in rep["rules"]} == {"şifreleme": 50, "telnet yok": 50}
        assert "10.0.0.2" in ca.report_csv(rep) and ca.report(tenant_id=2)["summary"]["devices"] == 0


def test_pages_rbac(app, client):
    _seed(app)
    assert client.get("/configs/audit").status_code in (302, 403)
    login_as(client, "superadmin")
    assert client.get("/configs/audit").status_code == 200
    j = client.get("/configs/audit/diff/10.0.0.1").get_json()
    assert j["diff"]["added"] == 1 and client.get("/configs/audit/diff/10.0.0.1?a=1&b=9").status_code == 404
    assert client.get("/configs/audit/diff/bad!ip").status_code == 400
    assert client.get("/configs/audit/diff/10.0.0.2").get_json()["diff"] is None
    assert client.get("/configs/audit/changes").get_json()["success"]
    assert client.get("/configs/audit/report.csv").status_code == 200 and client.get("/configs/audit/report.json").status_code == 200
    assert client.get("/configs/audit/report.xml").status_code == 404
