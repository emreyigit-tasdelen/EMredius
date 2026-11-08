# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import time

from pymysql.constants import SERVER_STATUS

from conftest import login_as
from emredius.core import (esc, esc_js, generate_totp_secret, get_totp_token, is_valid_ip, is_valid_vlan,
                           json_script, normalize_mac, safe_int, url_seg, verify_totp_token)
from emredius.core import db as core_db
from emredius.core import system


# ---------- pure helpers ----------

def test_escaping():
    assert esc('<a href="x">\'') == "&lt;a href=&quot;x&quot;&gt;&#x27;"
    assert esc(None) == ""
    assert "'" not in esc_js("a'b") and "<" not in esc_js("</script>")
    assert url_seg("a/b c") == "a%2Fb%20c"
    assert "</" not in json_script({"x": "</script>"})


def test_validators():
    assert is_valid_ip("10.0.0.1") and not is_valid_ip("10.0.0.256")
    assert is_valid_ip("10.0.0.0/24", allow_cidr=True) and not is_valid_ip("10.0.0.0/24")
    assert is_valid_vlan("1") and is_valid_vlan("4094")
    assert not is_valid_vlan("0") and not is_valid_vlan("4095") and not is_valid_vlan("١٢")
    assert safe_int("5", 0, 1, 10) == 5 and safe_int("50", 0, 1, 10) == 0 and safe_int("x", -1) == -1
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff" and normalize_mac("zz") is None


def test_totp_roundtrip():
    secret = generate_totp_secret()
    assert verify_totp_token(secret, get_totp_token(secret))
    assert not verify_totp_token(secret, "12345")
    assert not verify_totp_token(secret, "abcdef")


def test_dry_run_guard():
    blocked = system._blocked_in_dry_run
    assert blocked(["systemctl", "restart", "radiusd"])
    assert blocked(["reboot"])
    assert blocked(["firewall-cmd", "--add-port=161/udp"])
    assert blocked(["chronyc", "-n", "makestep"])
    assert not blocked(["systemctl", "is-active", "radiusd"])
    assert not blocked(["chronyc", "-n", "tracking"])
    assert not blocked(["chronyc", "-h", "127.0.0.1", "-n", "-N", "sources"])
    assert blocked(["chronyc", "-h", "127.0.0.1", "makestep"])
    assert not blocked(["firewall-cmd", "--list-all"])
    assert not blocked(["radtest", "u", "p", "127.0.0.1", "0", "s"])
    assert blocked(["radclient", "-r", "1", "10.0.0.1:3799", "disconnect", "s"])
    assert not blocked(["radclient", "127.0.0.1:18121", "status", "s"])
    system.set_dry_run(True)
    try:
        rc, _, err = system.run_cmd(["systemctl", "restart", "radiusd"])
        assert rc == 1 and "staging" in err
    finally:
        system.set_dry_run(False)


# ---------- connection pool ----------

class FakeRaw:
    def __init__(self):
        self.open = True
        self.server_status = 0
        self.autocommit_on = True
        self.rolled_back = False
        self.closed = False

    def rollback(self):
        self.rolled_back = True
        self.server_status = 0

    def get_autocommit(self):
        return self.autocommit_on

    def autocommit(self, v):
        self.autocommit_on = v

    def ping(self, reconnect=False):
        pass

    def close(self):
        self.closed = True
        self.open = False


def test_pool_reuses_and_rolls_back(monkeypatch):
    pool = core_db._Pool()
    created = []
    monkeypatch.setattr(core_db.pymysql, "connect", lambda **kw: created.append(FakeRaw()) or created[-1])
    pool.configure({"host": "x"}, max_idle=2)

    a = pool.acquire()
    a.server_status = SERVER_STATUS.SERVER_STATUS_IN_TRANS
    a.autocommit_on = False
    pool.release(a)
    assert a.rolled_back and a.autocommit_on
    assert pool.acquire() is a  # reused
    b, c, d = pool.acquire(), pool.acquire(), pool.acquire()
    for x in (a, b, c, d):
        pool.release(x)
    assert sum(x.closed for x in (a, b, c, d)) == 2  # only max_idle kept


def test_pooled_connection_close_returns_once(monkeypatch):
    released = []
    monkeypatch.setattr(core_db._pool, "release", released.append)
    raw = FakeRaw()
    conn = core_db.PooledConnection(raw)
    with conn:
        assert conn.open
    conn.close()
    assert released == [raw]


# ---------- app / security gate ----------

def test_app_factory_and_short_endpoints(app):
    with app.test_request_context():
        from emredius.core import url_for
        assert url_for("login") == "/login"
        assert url_for("auth.login") == "/login"
        assert url_for("static", filename="css/base.css") == "/static/css/base.css"


def test_login_page_renders(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert b"<form" in r.data and b'name="password"' in r.data
    assert r.headers["X-Frame-Options"] == "DENY" and r.headers["Cache-Control"] == "no-store"


def test_login_2fa_without_pending_redirects(client):
    r = client.get("/login/2fa")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_logout_and_heartbeat(client):
    assert client.get("/api/session/heartbeat").status_code == 401
    r = client.get("/logout")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_require_page_unauthenticated(client):
    r = client.get("/probe/dashboard")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")
    r = client.get("/probe/dashboard", headers={"Accept": "application/json"})
    assert r.status_code == 401


def test_require_page_rbac(client):
    login_as(client, "network_admin")
    assert client.get("/probe/dashboard").data == b"dashboard-ok"
    r = client.get("/probe/backups")  # superadmin-only page
    assert r.status_code == 302 and r.headers["Location"].endswith("/")
    login_as(client, "superadmin")
    assert client.get("/probe/backups").data == b"backups-ok"


def test_csrf_required_for_post(client):
    tok = login_as(client, "superadmin")
    r = client.post("/probe/backups", headers={"Accept": "application/json"})
    assert r.status_code == 400
    r = client.post("/probe/backups", data={"_csrf_token": "wrong"})
    assert r.status_code == 302
    assert client.post("/probe/backups", data={"_csrf_token": tok}).data == b"backups-ok"
    assert client.post("/probe/backups", headers={"X-CSRF-Token": tok}).data == b"backups-ok"


def test_read_only_role_cannot_post(client):
    tok = login_as(client, "auditor")
    r = client.post("/probe/dashboard", headers={"X-CSRF-Token": tok, "Accept": "application/json"})
    assert r.status_code == 403
    assert client.get("/probe/dashboard").data == b"dashboard-ok"


def test_nms_api_requires_session(client):
    assert client.get("/api/tacacs/devices").status_code == 401
    login_as(client, "helpdesk")
    assert client.get("/api/snmp/devices").status_code == 403


def test_json_404(client):
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404 and r.get_json()["success"] is False


def test_get_setting_degrades_without_db():
    from emredius.core.settings import get_setting, invalidate_settings
    invalidate_settings()
    t = time.monotonic()
    assert get_setting("anything", "dflt") == "dflt"
    assert time.monotonic() - t < 5


def test_legacy_api_token_compared_by_hash_only(monkeypatch):
    """The published default token is recognised by its SHA-256 and replaced; its plain text is not in the code."""
    import hashlib
    import inspect
    from emredius.core import settings as st
    assert "rad_sec_" not in inspect.getsource(st)
    known = "k" * 24
    monkeypatch.setattr(st, "_LEGACY_PUBLIC_API_TOKEN_SHA256", hashlib.sha256(known.encode()).hexdigest())
    store = {"api_token": known}
    monkeypatch.setattr(st, "get_setting", lambda k, d="": store.get(k, d))
    monkeypatch.setattr(st, "set_setting", lambda k, v: store.__setitem__(k, v))
    new = st.get_api_token()
    assert new != known and new.startswith("emr_") and store["api_token"] == new
    assert st.get_api_token() == new  # a non-legacy token is kept
    assert st.is_legacy_public_token(known) and not st.is_legacy_public_token(new)


def test_rbac_role_forms_list_every_assignable_page():
    """Role create/edit forms must offer a checkbox for every assignable (non superadmin-only) page."""
    from pathlib import Path
    from emredius.core import rbac
    html = (Path(__file__).resolve().parent.parent / "emredius" / "templates" / "admins" / "index.html").read_text(encoding="utf-8")
    for key in rbac.VALID_PAGE_KEYS - rbac.SUPERADMIN_ONLY_PAGES:
        assert html.count(f'name="pages" value="{key}"') >= 2, key
