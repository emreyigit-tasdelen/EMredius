# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import watch as w


def test_parse_ping_and_add():
    assert w.parse_ping("64 bytes from x: icmp_seq=1 ttl=64 time=0.52 ms\n time=1.2 ms") == 0.52
    assert w.parse_ping("Reply from 1.1.1.1: bytes=32 time<1ms TTL=64") == 1.0
    assert w.parse_ping("Request timed out") is None
    assert w.ping("bad;ip") == (False, None, 100)


def test_targets_history_tenant(app, monkeypatch):
    with app.app_context():
        assert w.add_target("999.1.1.1")
        assert w.add_target("10.0.0.5", "gw") == ""
        assert w.add_target("10.0.0.5") == "Bu IP zaten izleniyor."
        monkeypatch.setattr(w, "ping", lambda ip: (True, 2.5, 0))
        assert w.check_all() == 1
        t = w.list_targets()[0]
        assert (t["status"], t["rtt_ms"], t["name"]) == ("UP", 2.5, "gw") and t["last_change"]
        monkeypatch.setattr(w, "ping", lambda ip: (False, None, 100))
        w.check_all()
        assert w.list_targets()[0]["status"] == "DOWN" and len(w.history(t["id"])) == 2
        assert w.history(t["id"], tenant_id=2) == [] and not w.delete_target(t["id"], tenant_id=2)
        assert w.overview() == {"total": 1, "up": 0, "down": 1}
        assert "'=x" in w.targets_csv([dict(t, name="=x")])
        assert w.delete_target(t["id"]) and w.list_targets() == []


def test_pages_rbac(client):
    login_as(client, "superadmin")
    assert client.get("/watch").status_code == 200
    assert client.get("/watch/data").get_json()["success"]
    assert client.get("/watch/export.csv").status_code == 200
    assert client.get("/watch/export.json").status_code == 200
    assert client.get("/watch/export.xml").status_code == 404
    assert client.get("/watch/history/1").get_json()["rows"] == []
    login_as(client, "helpdesk")
    assert client.get("/watch").status_code in (302, 403)
