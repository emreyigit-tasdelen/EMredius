# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import admins as admin_svc
from emredius.services import telemetry


def test_telemetry_snapshot_shape(client):
    login_as(client, "helpdesk")
    j = client.get("/api/system/telemetry").get_json()
    assert {"cpu", "ram", "swap", "disk", "net", "radius", "uptime", "os_info", "gpu"} <= set(j)
    assert 0.0 <= j["cpu"]["percent"] <= 100.0
    assert client.get("/api/system/time").get_json()["timestamp"] > 0


def test_telemetry_requires_login(client):
    assert client.get("/api/system/telemetry").status_code in (302, 401)


def test_history_db_down(client):
    login_as(client, "helpdesk")
    r = client.get("/api/system/telemetry/history?range=bogus")
    assert r.status_code == 503 and r.get_json()["points"] == []


def test_history_range_fallback(monkeypatch):
    seen = {}

    class Cur:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, args):
            seen["args"] = args

        def fetchall(self):
            return []

    class Conn:
        def cursor(self):
            return Cur()

        def close(self):
            pass
    monkeypatch.setattr(telemetry, "get_db", lambda: Conn())
    assert telemetry.history("'; DROP TABLE x;--") == ("15m", []) and seen["args"] == (900,)


def test_ca_download_missing(app, client, tmp_path):
    app.config["CA_CERT_PATH"] = str(tmp_path / "none.crt")
    assert client.get("/download/ca.crt").status_code == 404
    (tmp_path / "ca.crt").write_bytes(b"-----BEGIN CERTIFICATE-----")
    app.config["CA_CERT_PATH"] = str(tmp_path / "ca.crt")
    assert client.get("/download/ca.crt").data.startswith(b"-----BEGIN")


def test_security_page(client, monkeypatch):
    monkeypatch.setattr(admin_svc, "security_overview", lambda: {
        "admins": [{"username": "a'<b>", "full_name": None, "role_label": "R", "auth_type": "web", "totp_enabled": 1,
                    "last_login": None, "last_login_ip": None}],
        "total_admins": 1, "totp_enabled_count": 1, "totp_disabled_count": 0})
    login_as(client, "network_admin")
    assert client.get("/security").status_code == 302
    login_as(client, "superadmin")
    body = client.get("/security").get_data(as_text=True)
    assert "a&#39;&lt;b&gt;" in body and "/api/security/2fa/reset/a%27%3Cb%3E" in body and "a\\u0027\\u003cb\\u003e kullanıcısının" in body


def test_password_reset_validation(client):
    tok = login_as(client, "superadmin")
    r = client.post("/api/security/password/reset/bob", data={"_csrf_token": tok, "new_password": "short"})
    assert r.status_code == 302
    with client.session_transaction() as s:
        assert any("en az 8" in m for _, m in s.get("_flashes", []))


def test_security_headers_present(client):
    r = client.get("/login")
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert "camera=()" in r.headers["Permissions-Policy"]


def test_back_ignores_foreign_referer(client):
    login_as(client, "helpdesk")
    r = client.post("/profile/change-password", data={}, headers={"Referer": "https://evil.example/x"})
    assert "evil.example" not in (r.headers.get("Location") or "")


def test_no_inline_event_handlers_in_templates():
    """Zorunlu script-src 'self' için satır içi olay işleyicisi kalmamalı (ntp/snmp başka thread'de, bekliyor)."""
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parent.parent / "emredius" / "templates"
    pat = re.compile(r"\son(click|change|input|submit|keyup|keydown|keypress|mouseover|mouseout|focus|blur)\s*=")
    offenders = [str(p.relative_to(root)) for p in root.rglob("*.html")
                 if pat.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


def test_csp_actions_loaded_in_base(client):
    r = client.get("/login")
    assert r.status_code == 200
    src = (__import__("pathlib").Path(__file__).resolve().parent.parent / "emredius" / "templates" / "base.html").read_text(encoding="utf-8")
    assert "/static/js/csp-actions.js" in src


def test_ca_install_bat(client, app, tmp_path):
    app.config["CA_CERT_PATH"] = str(tmp_path / "none.crt")
    assert client.get("/download/ca-install.bat").status_code == 404
    (tmp_path / "ca.crt").write_bytes(b"-----BEGIN CERTIFICATE-----")
    app.config["CA_CERT_PATH"] = str(tmp_path / "ca.crt")
    r = client.get("/download/ca-install.bat")
    assert b"certutil -user -addstore Root" in r.data
