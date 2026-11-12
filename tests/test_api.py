# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import api_v1 as svc
from emredius.services import radius_users

TOKEN = "t" * 32


def _auth(monkeypatch):
    import emredius.core.rbac as rbac
    monkeypatch.setattr(rbac, "get_api_token", lambda: TOKEN)
    return {"X-API-Key": TOKEN}


def test_api_requires_token(client, monkeypatch):
    _auth(monkeypatch)
    assert client.get("/api/v1/stats").status_code == 401
    assert client.get("/api/v1/stats", headers={"X-API-Key": "wrong"}).status_code == 401


def test_api_db_down_is_503(client, monkeypatch):
    h = _auth(monkeypatch)
    r = client.get("/api/v1/users", headers=h)
    assert r.status_code == 503 and r.get_json()["status"] == "error"


def test_api_create_user_validates(client, monkeypatch):
    h = _auth(monkeypatch)
    calls = []

    def fake_add(fields, wh, sd):
        calls.append(fields)
        if fields["username"] == "dup":
            raise radius_users.ServiceError("'dup' kullanıcısı zaten mevcut!")
        return {"username": fields["username"]}
    monkeypatch.setattr(radius_users, "add_user", fake_add)
    assert client.post("/api/v1/users", headers=h, data="x", content_type="application/json").status_code == 400
    assert client.post("/api/v1/users", headers=h, json={"username": "a"}).status_code == 400
    assert client.post("/api/v1/users", headers=h, json={"username": "dup", "password": "p"}).status_code == 409
    r = client.post("/api/v1/users", headers=h, json={"username": "bob", "password": "secret1", "vlan_id": 20})
    assert r.status_code == 201 and calls[-1]["vlan"] == "20" and calls[-1]["desc"] == "API Oluşturdu"


def test_api_delete_user(client, monkeypatch):
    h = _auth(monkeypatch)

    def fake_state(u, action):
        if u == "nobody":
            raise radius_users.ServiceError("Kullanıcı bulunamadı!")
        return u
    monkeypatch.setattr(radius_users, "change_user_state", fake_state)
    assert client.delete("/api/v1/users/nobody", headers=h).status_code == 404
    assert client.delete("/api/v1/users/bob", headers=h).get_json()["status"] == "success"


def test_api_stats(client, monkeypatch):
    h = _auth(monkeypatch)
    monkeypatch.setattr(svc, "stats", lambda: {"total_users": 3, "active_sessions": 1, "nas_count": 2})
    j = client.get("/api/v1/stats", headers=h).get_json()
    assert j["total_users"] == 3 and "radiusd_status" in j


def test_docs_need_login(client):
    assert client.get("/api/openapi.json").status_code == 401
    login_as(client, "helpdesk")
    assert client.get("/api/openapi.json").get_json()["openapi"] == "3.0.0"
    body = client.get("/api/docs").get_data(as_text=True)
    assert "/static/vendor/swagger-ui/swagger-ui-bundle.js" in body and "cdnjs" not in body


def test_nms_api_endpoints_and_spec(client, monkeypatch):
    h = _auth(monkeypatch)
    for path in ("health", "watch", "alarms", "loops", "flows/top", "topology", "inventory/devices", "boards", "ipam/subnets",
                 "configs/compliance", "equipment/ports", "equipment/macs", "equipment/chassis"):
        r = client.get("/api/v1/" + path, headers=h)
        assert r.status_code == 200 and r.get_json()["status"] == "success", path
    assert client.get("/api/v1/equipment/zzz", headers=h).status_code == 404
    assert client.get("/api/v1/alarms").status_code == 401
    login_as(client, "superadmin")
    paths = client.get("/api/openapi.json").get_json()["paths"]
    for p in ("/topology", "/alarms", "/flows/top", "/ipam/subnets", "/equipment/{kind}", "/boards/{board_id}"):
        assert p in paths
