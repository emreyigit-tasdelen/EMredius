# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
import time

from conftest import login_as
from emredius.services import notifications as nt


def _grant(app, role, pages, when):
    with app.app_context():
        conn = nt._db()
        for p in pages:
            conn.execute("INSERT OR REPLACE INTO notif_access (role_key, page_key, since_ts) VALUES (?,?,?)", (role, p, when))
        conn.commit()
        conn.close()


def _add(app, page, title, ts, target=""):
    with app.app_context():
        conn = nt._db()
        conn.execute("INSERT INTO notifications (tenant_id,page_key,target_user,title,created_ts) VALUES (1,?,?,?,?)",
                     (page, target, title, ts))
        conn.commit()
        conn.close()


def test_only_events_after_grant_are_visible(app):
    now = time.time()
    _add(app, "ipscan", "eski", now - 100)
    _grant(app, "network_admin", ["ipscan"], now - 50)       # yetki eski olaydan SONRA verildi
    _add(app, "ipscan", "yeni", now - 10)
    _add(app, "snmp", "yetkisiz sayfa", now - 5)
    with app.app_context():
        titles = [i["title"] for i in nt.inbox("ali", "network_admin", tenant_id=1)["items"]]
    assert titles == ["yeni"]


def test_target_user_and_read_state_are_per_user(app):
    now = time.time()
    _grant(app, "network_admin", ["ipscan"], now - 50)
    _add(app, "ipscan", "genel", now - 10)
    _add(app, "", "sadece ali", now - 9, target="ali")
    with app.app_context():
        ali, veli = nt.inbox("ali", "network_admin", tenant_id=1), nt.inbox("veli", "network_admin", tenant_id=1)
        assert {i["title"] for i in ali["items"]} == {"genel", "sadece ali"} and ali["unread"] == 2
        assert {i["title"] for i in veli["items"]} == {"genel"}
        nt.mark_read("ali", "network_admin", ids=[ali["items"][0]["id"]], tenant_id=1)
        assert nt.inbox("ali", "network_admin", tenant_id=1)["unread"] == 1
        assert nt.inbox("veli", "network_admin", tenant_id=1)["unread"] == 1
        nt.mark_read("ali", "network_admin", everything=True, tenant_id=1)
        assert nt.inbox("ali", "network_admin", tenant_id=1)["unread"] == 0


def test_cannot_mark_invisible_notification_and_revoked_page_hides(app):
    now = time.time()
    _grant(app, "helpdesk", ["dashboard"], now - 50)
    _add(app, "snmp", "gizli", now - 10)
    with app.app_context():
        assert nt.inbox("h", "helpdesk", tenant_id=1)["items"] == []
        nt.mark_read("h", "helpdesk", ids=[1], tenant_id=1)
        conn = nt._db()
        assert conn.execute("SELECT COUNT(*) FROM notif_read").fetchone()[0] == 0
        conn.close()


def test_sync_role_records_grant_time_and_revocation(app):
    with app.app_context():
        conn = nt._db()
        nt.sync_role(conn, "r1", {"ipscan"}, now=100.0)
        nt.sync_role(conn, "r1", {"ipscan", "snmp"}, now=200.0)
        got = dict(conn.execute("SELECT page_key, since_ts FROM notif_access WHERE role_key='r1'").fetchall())
        assert got == {"ipscan": 100.0, "snmp": 200.0}
        nt.sync_role(conn, "r1", {"snmp"}, now=300.0)
        assert [r[0] for r in conn.execute("SELECT page_key FROM notif_access WHERE role_key='r1'")] == ["snmp"]
        conn.close()


def test_publish_dedupes_and_api_routes(app, client):
    with app.app_context():
        assert nt.publish("ipscan", "Yeni cihaz", dedupe_key="k1", tenant_id=1)
        assert nt.publish("ipscan", "Yeni cihaz", dedupe_key="k1", tenant_id=1) is None
    assert client.get("/api/notifications").status_code == 401
    tok = login_as(client, "superadmin", "root")
    with app.app_context():
        nt.publish("ipscan", "Sonraki", link="/ip-scan", tenant_id=1)
    data = client.get("/api/notifications").get_json()
    assert data["success"] and any(i["title"] == "Sonraki" for i in data["items"]) and data["unread"] >= 1
    assert client.post("/api/notifications/read", json={"all": True}, headers={"X-CSRF-Token": tok}).get_json()["success"]
    assert client.get("/api/notifications").get_json()["unread"] == 0
    login_as(client, "auditor", "denetci")   # salt okunur rol da kendi bildirimini okundu yapabilmeli
    assert client.post("/api/notifications/read", json={"all": True}, headers={"X-CSRF-Token": "tok"}).status_code == 200


def test_status_filter_pagination_and_page(app, client):
    now = time.time()
    _grant(app, "network_admin", ["ipscan"], now - 100)
    for i in range(5):
        _add(app, "ipscan", f"n{i}", now - 50 + i)
    with app.app_context():
        allv = nt.inbox("ali", "network_admin", tenant_id=1, status="all")
        assert allv["total"] == 5 and allv["unread"] == 5
        nt.mark_read("ali", "network_admin", ids=[allv["items"][0]["id"], allv["items"][1]["id"]], tenant_id=1)
        un = nt.inbox("ali", "network_admin", tenant_id=1, status="unread")
        rd = nt.inbox("ali", "network_admin", tenant_id=1, status="read")
        assert un["total"] == 3 and rd["total"] == 2 and all(i["read"] for i in rd["items"]) and not any(i["read"] for i in un["items"])
        page2 = nt.inbox("ali", "network_admin", tenant_id=1, status="all", limit=2, offset=2)
        assert len(page2["items"]) == 2 and page2["total"] == 5
    login_as(client, "network_admin", "ali")
    body = client.get("/notifications").get_data(as_text=True)
    assert "Bildirimlerim" in body and "notifications-page.js" in body and 'href="/notifications"' in body
    data = client.get("/api/notifications?status=unread&limit=10").get_json()
    assert data["success"] and data["total"] == 3
