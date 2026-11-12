# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import sessions as svc


def test_radclient_attr_value():
    assert svc.radclient_attr_value('a"b\\c\nd') == 'a\\"b\\\\cd'


def test_find_nas():
    rows = [{"nasname": "10.0.0.0/8", "id": 1}, {"nasname": "10.1.0.0/16", "id": 2}, {"nasname": "10.1.2.3", "id": 3}]
    assert svc.find_nas("10.1.2.3", rows)["id"] == 3
    assert svc.find_nas("10.1.9.9", rows)["id"] == 2
    assert svc.find_nas("192.168.1.1", rows) is None


def test_sessions_page(client, monkeypatch):
    monkeypatch.setattr(svc, "list_sessions", lambda: {"active_total": 2, "active": [
        {"radacctid": 7, "username": "<u>", "framedipaddress": None, "callingstationid": None, "nasipaddress": "1.1.1.1",
         "acctstarttime": None, "acctsessiontime": 60, "acctinputoctets": 1, "acctoutputoctets": 2}], "past": []})
    login_as(client, "superadmin")
    body = client.get("/sessions").get_data(as_text=True)
    assert "&lt;u&gt;" in body and "/session/disconnect/7" in body and "en yeni 1 tanesi" in body


def test_disconnect_ack(client, monkeypatch):
    monkeypatch.setattr(svc, "disconnect", lambda rid: {"result": "ack", "username": "u", "target": "1.1.1.1:3799",
                                                        "detail": ""})
    tok = login_as(client, "superadmin")
    client.post("/session/disconnect/7", data={"_csrf_token": tok})
    with client.session_transaction() as s:
        assert "Disconnect-ACK" in str(s.get("_flashes"))
