# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import nas as svc


def test_normalize_nasname():
    assert svc.normalize_nasname("192.168.001.0/24") is None or svc.normalize_nasname("192.168.1.7/24") == "192.168.1.0/24"
    assert svc.normalize_nasname("Core-SW.local") == "core-sw.local"
    assert svc.normalize_nasname("999.1.1.1") is None and svc.normalize_nasname("-x") is None
    assert svc.ping_target("10.0.0.0/24") is None and svc.ping_target("10.0.0.5/32") == "10.0.0.5"


def test_validate_nas():
    errors, d = svc.validate_nas({"shortname": "ap1", "nasname": "10.0.0.1", "secret": "abcd", "type": "unifi"})
    assert not errors and d["type"] == "ubiquiti" and d["port"] == 3799
    errors, _ = svc.validate_nas({"shortname": "a b", "nasname": "x..y", "secret": "a b c", "type": "zzz", "ports": "0"})
    assert len(errors) == 5


def test_nas_page(client, monkeypatch):
    monkeypatch.setattr(svc, "list_nas", lambda: [{"id": 3, "nasname": "10.0.0.0/24", "shortname": "o'k", "type": "cisco",
                                                  "secret": "<s>", "description": None, "reach": "block", "coa_port": 3799}])
    login_as(client, "network_admin")
    body = client.get("/nas").get_data(as_text=True)
    assert "&lt;s&gt;" in body and "o\\u0027k cihazını" in body and "Ağ Bloğu" in body


def test_nas_add_restarts_radius(client, monkeypatch):
    added, restarted = [], []
    monkeypatch.setattr(svc, "add_nas", added.append)
    from emredius.blueprints.nas import routes
    monkeypatch.setattr(routes, "restart_radiusd_async", lambda: restarted.append(1))
    tok = login_as(client, "network_admin")
    client.post("/nas/add", data={"_csrf_token": tok, "shortname": "ap1", "nasname": "10.0.0.1", "secret": "abcd"})
    assert added and restarted
