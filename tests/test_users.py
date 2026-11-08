# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import radius_users as svc

XSS = "<img src=x onerror=alert(1)>"


def _user(**kw):
    u = {"username": "ali'veli", "vlan_id": "20", "static_ip": None, "rate_limit": "10M/5M", "login_time": None,
         "sim_use": "1", "is_disabled": 0, "groupname": XSS, "description": XSS, "created_at": None}
    u.update(kw)
    return u


def test_users_page_renders_escaped(client, monkeypatch):
    monkeypatch.setattr(svc, "list_users", lambda: ([_user(), _user(username="b", is_disabled=1)], [XSS, "staff"]))
    login_as(client, "superadmin")
    r = client.get("/users")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert XSS not in body and "&lt;img src=x" in body
    assert "/user/disable/ali%27veli" in body and "/user/enable/b" in body
    assert "ali\\u0027veli kullanıcısını silmek" in body
    assert "/static/js/users.js" in body and 'name="_csrf_token"' in body
    assert "&#34;single_device&#34;: true" in body or "&quot;single_device&quot;: true" in body


def test_users_rbac(client):
    assert client.get("/users").status_code == 302
    login_as(client, "helpdesk_readonly_does_not_exist")
    r = client.get("/users")
    assert r.status_code == 302 and r.headers["Location"].endswith("/")


def test_user_add_calls_service(client, monkeypatch):
    calls = []

    def fake_add(fields, wh, sd):
        calls.append((fields, wh, sd))
        return {"username": "x", "group": "", "vlan": "", "rate": "", "static_ip": ""}
    monkeypatch.setattr(svc, "add_user", fake_add)
    tok = login_as(client, "superadmin")
    assert client.post("/user/add", data={"username": "x", "password": "p"}).status_code == 302
    assert not calls  # no CSRF token -> rejected
    r = client.post("/user/add", data={"_csrf_token": tok, "username": "x", "password": "p", "work_hours_only": "1"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/users")
    assert calls[0][0]["username"] == "x" and calls[0][1] is True and calls[0][2] is False


def test_state_routes_are_post_only(client):
    login_as(client, "superadmin")
    assert client.get("/user/delete/x").status_code == 405


def test_validate_fields():
    err, _ = svc.validate_radius_user_fields({"username": "a b", "password": "p"})
    assert err
    err, d = svc.validate_radius_user_fields({"username": "ab", "password": "p", "vlan": "020", "group": "STAFF"},
                                             group_names=["staff"])
    assert err is None and d["vlan"] == "20" and d["group"] == "staff"
    assert svc.validate_radius_user_fields({"username": "ab", "password": "p", "vlan": "5000"})[0]
    assert svc.validate_radius_user_fields({"username": "ab", "password": "p", "static_ip": "::1"})[0]


def test_csv_cells_and_parse():
    assert svc.csv_cell("=1+1") == "'=1+1" and svc.csv_uncell("'=1+1") == "=1+1"
    colmap, rows = svc.parse_import_csv("username;password;vlan_id\nu1;p1;10\n".encode("utf-8-sig"))
    assert colmap["username"] == 0 and colmap["vlan"] == 2 and rows == [(2, ["u1", "p1", "10"])]
    colmap, rows = svc.parse_import_csv(b"u1,p1,10,5M/2M,desc\n")
    assert colmap == {"username": 0, "password": 1, "vlan": 2, "rate": 3, "desc": 4} and len(rows) == 1
