# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""NAC sayfaları: Kimlik Doğrulama Günlüğü, Anomaliler, Korelasyon, Kara Liste / Karantina / Uygulama Kayıtları."""
import pytest
from conftest import login_as
from emredius.services import anomalies, correlation, nacmarks


def test_pages_open_and_degrade_without_radius_db(client):
    login_as(client, "superadmin")
    for url in ("/authlog", "/anomalies", "/correlation", "/blacklist", "/quarantine", "/enforcement"):
        assert client.get(url).status_code == 200, url
    assert client.get("/authlog/data").get_json()["rows"] == []
    assert client.get("/anomalies/data").get_json()["available"] is False
    assert client.get("/correlation/data?q=bob").get_json()["kind"] == "user"
    assert client.get("/authlog/export.csv").status_code == 200


def test_pages_require_login(client):
    for url in ("/authlog", "/blacklist", "/enforcement"):
        assert client.get(url).status_code in (301, 302, 401)


def test_scripts_are_external_only(client):
    login_as(client, "superadmin")
    for url in ("/authlog", "/anomalies", "/correlation", "/blacklist", "/enforcement"):
        html = client.get(url).get_data(as_text=True)
        assert "<script>" not in html.split("<main")[-1] if "<main" in html else True


def test_anomaly_classify():
    items = anomalies.classify({"bob": 7, "ok": 1}, {"u1": {"a", "b", "c"}}, {"aa:bb": {"x", "y"}}, {"u2": {"1.1.1.1"}})
    kinds = {i["kind"]: i for i in items}
    assert kinds["brute_force"]["subject"] == "bob" and items[0]["kind"] == "brute_force"
    assert "multi_mac_user" in kinds and "shared_mac" in kinds and "multi_nas_user" not in kinds


def test_marks_lifecycle_and_validation(app):
    with app.app_context():
        with pytest.raises(nacmarks.MarkError):
            nacmarks.add_mark("blacklist", mac="zz", actor="t")
        with pytest.raises(nacmarks.MarkError):
            nacmarks.add_mark("blacklist", actor="t")
        with pytest.raises(nacmarks.MarkError):
            nacmarks.add_mark("bogus", mac="aa:bb:cc:dd:ee:ff")
        mid = nacmarks.add_mark("quarantine", mac="AA-BB-CC-DD-EE-FF", reason="test", actor="t")
        with pytest.raises(nacmarks.MarkError):
            nacmarks.add_mark("quarantine", mac="aa:bb:cc:dd:ee:ff", actor="t")
        assert nacmarks.status_of("aabbccddeeff")[0]["kind"] == "quarantine"
        assert nacmarks.list_marks("blacklist") == []
        assert nacmarks.release(mid, "t") and not nacmarks.release(mid, "t")
        assert nacmarks.status_of("aa:bb:cc:dd:ee:ff") == []
        assert [e["action"] for e in nacmarks.list_events()] == ["release", "add"]


def test_mark_expiry_and_tenant_isolation(app):
    with app.app_context():
        nacmarks.add_mark("blacklist", username="eve", hours=1, actor="t", tenant_id=1)
        conn = nacmarks._db()
        conn.execute("UPDATE nac_marks SET expires_at='2000-01-01 00:00:00'")
        conn.commit()
        conn.close()
        assert nacmarks.list_marks("blacklist") == []
        assert any(e["action"] == "expire" for e in nacmarks.list_events())
        nacmarks.add_mark("blacklist", username="eve2", actor="t", tenant_id=1)
        assert nacmarks.list_marks("blacklist", tenant_id=2) == []


def test_mark_routes_and_audit_log(client, app):
    tok = login_as(client, "superadmin")
    h = {"X-CSRF-Token": tok}
    r = client.post("/blacklist/add", data={"mac": "aa:bb:cc:00:00:01", "reason": "r"}, headers=h)
    assert r.status_code == 200 and r.get_json()["success"]
    assert client.post("/blacklist/add", data={}, headers=h).status_code == 400
    marks = client.get("/blacklist/data").get_json()["marks"]
    assert len(marks) == 1 and marks[0]["mac"] == "aa:bb:cc:00:00:01"
    assert client.get("/quarantine/data").get_json()["marks"] == []
    assert client.post(f"/blacklist/{marks[0]['id']}/release", headers=h).status_code == 200
    assert client.post("/blacklist/999/release", headers=h).status_code == 404
    assert len(client.get("/enforcement/data").get_json()["events"]) == 2
    c = client.get("/correlation/data?q=aa:bb:cc:00:00:01").get_json()
    assert c["kind"] == "mac" and c["marks"] == []


def test_correlation_shows_marks(app):
    with app.app_context():
        nacmarks.add_mark("quarantine", mac="aa:bb:cc:00:00:02", actor="t")
        out = correlation.lookup("aa:bb:cc:00:00:02")
        assert out["kind"] == "mac" and out["marks"][0]["kind"] == "quarantine"
        assert correlation.kind_of("10.1.2.3") == "ip" and correlation.kind_of("") == ""


def test_helpdesk_role_denied(client):
    login_as(client, "helpdesk")
    assert client.get("/blacklist").status_code in (302, 403)


def test_regex_marks_import_export_and_rules(client, app):
    import io
    tok = login_as(client, "superadmin")
    h = {"X-CSRF-Token": tok}
    assert client.post("/blacklist/add", data={"username": "(", "match": "regex"}, headers=h).status_code == 400
    assert client.post("/blacklist/add", data={"username": "^test.*", "match": "regex"}, headers=h).status_code == 200
    with app.app_context():
        assert nacmarks.status_of(username="testuser") and not nacmarks.status_of(username="prod")
    csvtxt = chr(10).join(["kind,match,value,reason,expires_at", "mac,exact,aa:bb:cc:00:00:09,x,", "user,exact,bad user!,y,", "foo,exact,z,,"])
    r = client.post("/blacklist/import", data={"file": (io.BytesIO(csvtxt.encode()), "a.csv")}, headers=h,
                    content_type="multipart/form-data").get_json()
    assert r["added"] == 1 and len(r["errors"]) == 2
    assert "aa:bb:cc:00:00:09" in client.get("/blacklist/export.csv").get_data(as_text=True)
    assert client.get("/quarantine/import-template.csv").get_data(as_text=True).startswith("kind,match,value")
    out = client.post("/anomalies/rules", data={"concurrent_sessions": "5", "shared_mac": "1"}, headers=h).get_json()
    assert out["thresholds"]["concurrent_sessions"] == 5 and out["thresholds"]["shared_mac"] == 2
    assert anomalies.classify({}, {}, {}, {}, anomalies.DEFAULTS, {"u": 3})[0]["kind"] == "concurrent_sessions"
