# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from decimal import Decimal

from conftest import login_as
from emredius.services import dashboard as dashboard_service

XSS = "<script>alert(1)</script>"


def _summary(**overrides):
    data = {
        "total_users": 12,
        "active_sessions": 1,
        "total_nas": 3,
        "total_bytes": 5 * 1024 * 1024,
        "active_list": [{
            "radacctid": 42, "username": XSS, "framedipaddress": "10.0.0.5", "callingstationid": "aa:bb",
            "nasipaddress": "10.0.0.1", "acctstarttime": None, "acctsessiontime": 65,
            "acctinputoctets": 1024, "acctoutputoctets": None,
        }],
        "top_users": [{"username": "</script><b>", "total_bytes": Decimal(3 * 1024 * 1024)}],
        "db_error": False,
    }
    data.update(overrides)
    return data


class FakeCursor:
    def __init__(self, results):
        self._results = list(results)
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.queries.append((sql, params))

    def fetchone(self):
        return self._results.pop(0)

    def fetchall(self):
        return self._results.pop(0)


class FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor
        self.closed = False

    def cursor(self):
        return self._cursor

    def close(self):
        self.closed = True


def test_dashboard_requires_login(client):
    r = client.get("/")
    assert r.status_code == 302 and r.headers["Location"].endswith("/login")


def test_dashboard_renders_without_db(client):
    login_as(client, "network_admin")
    r = client.get("/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Veritabanına ulaşılamadı" in body
    assert 'id="statTotalUsers">0<' in body
    assert "/static/js/dashboard.js" in body and 'id="dashboardTrafficChart"' in body
    assert "Şu an aktif bağlı cihaz yok." in body


def test_dashboard_escapes_and_disconnect_permission(client, monkeypatch):
    monkeypatch.setattr(dashboard_service, "get_summary", lambda: _summary())
    login_as(client, "superadmin")
    body = client.get("/").get_data(as_text=True)
    assert XSS not in body and "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "</script><b>" not in body  # chart labels stay inside the JSON block
    assert 'href="/session/disconnect/42"' in body
    assert 'id="statTotalUsers">12<' in body and "Veritabanına ulaşılamadı" not in body

    login_as(client, "auditor")  # read-only role: no disconnect button
    body = client.get("/").get_data(as_text=True)
    assert "/session/disconnect/" not in body


def test_top_traffic_chart():
    chart = dashboard_service.top_traffic_chart([{"username": None, "total_bytes": Decimal(1048576)}])
    assert chart == {"labels": ["-"], "data": [1.0]}
    assert dashboard_service.top_traffic_chart([]) == {"labels": ["Veri Yok"], "data": [0]}


def test_get_summary_queries(monkeypatch):
    session_row = {"radacctid": 1, "username": "u"}
    cur = FakeCursor([
        {"total": 7}, {"active": 2}, {"total": 1}, {"up": Decimal(10), "down": None},
        [session_row], [{"username": "u", "total_bytes": Decimal(10)}],
    ])
    conn = FakeConn(cur)
    monkeypatch.setattr(dashboard_service, "get_db", lambda: conn)
    s = dashboard_service.get_summary()
    assert (s["total_users"], s["active_sessions"], s["total_nas"], s["total_bytes"]) == (7, 2, 1, 10)
    assert s["active_list"] == [session_row] and not s["db_error"] and conn.closed
    assert all("%s" in sql for sql, params in cur.queries if params)  # LIMITs are parameterised


def test_dashboard_stats_api_requires_login(client):
    r = client.get("/api/dashboard/stats")
    assert r.status_code in (302, 401)


def test_dashboard_stats_api_hides_missing_data(client):
    login_as(client, "auditor")
    r = client.get("/api/dashboard/stats?range=bogus")
    assert r.status_code == 200 and r.headers["Cache-Control"] == "no-store"
    d = r.get_json()
    assert d["range"] == "24h" and d["auth_result"] is None and d["trend"] is None and d["endpoint_dist"] is None


def test_dashboard_page_has_kpi_panel_without_inline_script(client):
    login_as(client, "superadmin")
    body = client.get("/").get_data(as_text=True)
    assert "/static/js/dashboard-stats.js" in body and 'id="kpiPanel"' in body and 'data-range="7d"' in body


def test_stats_build_omits_unavailable_cards():
    from emredius.services import dashboard_stats as ds
    d = ds.build({}, "24h")
    assert d["cards"] == [] and d["trend"] is None and d["alarms"] is None
    raw = {"auth": {"accept": 3, "reject": 1, "rate": 75.0, "trend": {"labels": ["t"], "accept": [3], "reject": [1]}},
           "alarms": {"count": 0, "list": []}, "devices": {"total": 4, "online": 3}}
    d = ds.build(raw, "7d")
    keys = [c["key"] for c in d["cards"]]
    assert keys == ["auth_count", "rate", "devices", "alarms"] and d["auth_result"]["data"] == [3, 1] and d["alarms"] is None
    assert ds.normalize_range("30d") == "30d" and ds.normalize_range("x") == "24h"
