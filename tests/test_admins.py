# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from werkzeug.datastructures import MultiDict

from conftest import login_as
from emredius.services import admins as svc


def test_sanitize_pages():
    assert svc.sanitize_pages(["users", "backups", "cli", "bogus", "nas"]) == "users,nas"
    assert svc.sanitize_pages([]) == "dashboard"


def test_add_role_validation():
    for form, msg in ((MultiDict({"role_key": "", "role_name": ""}), "zorunlu"),
                      (MultiDict({"role_key": "Bad Key", "role_name": "x"}), "Rol anahtarı"),
                      (MultiDict({"role_key": "helpdesk", "role_name": "x"}), "ayrılmıştır")):
        try:
            svc.add_role(form)
            assert False
        except svc.ServiceError as e:
            assert msg in str(e)


def test_create_admin_validation():
    cases = (("bad name", "web", "longpassword", "1-64"), ("ok", "web", "short", "en az 8"), ("ok", "x", "", "hesap türü"),
             ("no_such_linux_user_zz", "system", "", "bulunamadı"))
    for u, t, pw, msg in cases:
        try:
            svc.create_admin(u, "", "", "network_admin", t, pw)
            assert False
        except svc.ServiceError as e:
            assert msg in str(e)


def test_protected_targets():
    assert svc.is_protected_target("ROOT", "alice") and svc.is_protected_target("Alice", "alice")
    assert not svc.is_protected_target("bob", "alice")
    try:
        svc.delete_admin("alice", "alice")
        assert False
    except svc.ServiceError:
        pass


def test_csv_cell():
    assert svc.csv_cell("=cmd()") == "'=cmd()" and svc.csv_cell(None) == "" and svc.csv_cell("ok") == "ok"


def _page_data():
    return {"admins": [{"username": "<b>x</b>", "email": None, "full_name": None, "auth_type": "web", "role": "custom",
                        "status": "active", "role_icon": "🛡️", "role_name": "Özel", "role_style": "", "last_login": None,
                        "last_login_ip": None},
                       {"username": "tester", "auth_type": "system", "role": "superadmin", "status": "active",
                        "role_icon": "👑", "role_name": "Süper", "role_style": ""}],
            "audit_logs": [{"created_at": "2026", "admin_username": "a", "action": "GİRİŞ", "badge": "badge-active",
                            "target": "<t>", "details": None, "ip_address": "1.2.3.4"}],
            "roles": [{"role_key": "custom", "role_name": "O'Reilly", "icon": "🛡️", "description": None, "is_system": 0,
                       "all_pages": False, "pages": ["users"], "deletable": True}],
            "role_options": [("custom", "🛡️ Özel (custom)")],
            "admins_public": {"<b>x</b>": {"username": "<b>x</b>"}}, "roles_public": {},
            "linux_users": ["root"], "total_admins": 2, "web_admins": 1, "sys_admins": 1, "active_admins": 2}


def test_admins_page(client, monkeypatch):
    monkeypatch.setattr(svc, "page_data", _page_data)
    login_as(client, "network_admin")
    assert client.get("/admins").status_code == 302
    login_as(client, "superadmin", user="tester")
    body = client.get("/admins").get_data(as_text=True)
    assert "&lt;b&gt;x&lt;/b&gt;" in body and "<b>x</b>" not in body
    assert "\\u003cb\\u003ex" in body  # JSON data island is escaped
    assert "O\\u0027Reilly rolünü" in body
    assert "/admin/delete/%3Cb%3Ex%3C%2Fb%3E" in body and "/admin/delete/tester" not in body  # own account protected


def test_admins_page_db_down(client):
    login_as(client, "superadmin")
    assert "veritabanı hatası" in client.get("/admins").get_data(as_text=True)


def test_admin_actions_post_only(client):
    login_as(client, "superadmin")
    for url in ("/admin/delete/x", "/admin/toggle-status/x", "/role/delete/x"):
        assert client.get(url).status_code == 405


def test_profile_and_2fa(client, monkeypatch):
    monkeypatch.setattr(svc, "get_profile", lambda u: {"auth_type": "web", "role": "helpdesk", "full_name": "<i>A</i>"})
    monkeypatch.setattr(svc, "totp_enabled", lambda u: False)
    login_as(client, "helpdesk")
    body = client.get("/profile").get_data(as_text=True)
    assert "&lt;i&gt;A&lt;/i&gt;" in body and "/profile/change-password" in body
    body = client.get("/profile/2fa/setup").get_data(as_text=True)
    assert "otpauth://totp/" in body and "api.qrserver.com" not in body and "qrcode.min.js" in body
    enabled = []
    monkeypatch.setattr(svc, "enable_totp", lambda u, s, t: enabled.append((u, s)))
    with client.session_transaction() as s:
        secret = s["setup_2fa_secret"]
    client.post("/profile/2fa/verify", data={"_csrf_token": "tok", "token": "123456", "secret": "ATTACKER"})
    assert enabled == [("tester", secret)]


def test_set_lang_open_redirect(client):
    r = client.get("/set-lang/en", headers={"Referer": "https://evil.example/x"})
    assert r.headers["Location"] == "/x" and "app_lang=en" in r.headers.get("Set-Cookie", "")
    r = client.get("/set-lang/xx", headers={"Referer": "http://localhost/users?q=1"})
    assert r.headers["Location"].endswith("/users?q=1") and "Set-Cookie" not in r.headers
