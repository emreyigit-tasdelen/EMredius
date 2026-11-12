# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import flows, reports as rp

FAKE = {"window": "24h", "total_bytes": 3 * 1024 ** 3, "total_pkts": 10, "total_flows": 42,
        "talkers_src": [{"ip": "10.0.0.5", "bytes": 2048, "pkts": 3, "flows": 4}],
        "talkers_dst": [{"ip": "8.8.8.8", "bytes": 1024, "pkts": 2, "flows": 1}],
        "conversations": [{"src": "10.0.0.5", "dst": "8.8.8.8", "bytes": 1024, "pkts": 2, "flows": 1}],
        "applications": [{"proto_name": "UDP", "service": "DNS (53)", "bytes": 512, "pkts": 1, "flows": 1}]}


def _fake(monkeypatch, err=None):
    monkeypatch.setattr(flows, "report_overview", lambda *a, **k: (None, err) if err else (dict(FAKE), None))


def test_csv_and_pdf(monkeypatch):
    _fake(monkeypatch)
    csv_b, title = rp.build("24h", "csv")
    assert b"10.0.0.5" in csv_b and "toplam 3.0 GB" in title
    pdf = rp.build("24h", "pdf")[0]
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF") and b"10.0.0.5" in pdf


def test_pdf_multipage_and_escape():
    pdf = rp.make_pdf([f"satir (ç) \\ {i}" for i in range(130)])
    assert pdf.count(b"/Type /Page ") == 3 and b"/Count 3" in pdf


def test_generate_and_schedule(app, monkeypatch):
    _fake(monkeypatch)
    with app.app_context():
        rid, err = rp.generate("t", "24h", "pdf")
        assert rid and not err and rp.get_run(rid)[1] == "pdf"
        assert rp.add_schedule("Gunluk", "24h", "csv", "daily", "x@y.z") == ""
        assert rp.add_schedule("", "24h", "csv", "daily") and rp.add_schedule("a", "9y", "csv", "daily")
        assert rp.add_schedule("a", "24h", "csv", "daily", "bad mail")
        assert rp.run_due() == 1 and rp.run_due() == 0  # ikincide zamanı gelmedi
        assert len(rp.list_runs()) == 2
        sid = rp.list_schedules()[0]["id"]
        assert rp.schedule_action(sid, "toggle") and rp.list_schedules()[0]["enabled"] == 0
        assert rp.run_due(now=2 ** 31) == 0  # kapalı
        # e-posta varsayılan kapalı: gönderilmedi
        assert not rp.mail_enabled() and all(r["mailed"] == 0 for r in rp.list_runs())
        assert rp.schedule_action(sid, "delete") and rp.list_schedules() == []


def test_generate_without_flow_data(app, monkeypatch):
    _fake(monkeypatch, err="toplayıcı yok")
    with app.app_context():
        assert rp.generate() == (0, "toplayıcı yok")


def test_reports_pages(client, monkeypatch):
    _fake(monkeypatch)
    login_as(client, "superadmin")
    assert client.get("/reports").status_code == 200
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "tok"
    assert client.post("/reports/generate", data={"window": "24h", "fmt": "csv", "_csrf_token": "tok"}).status_code == 302
    page = client.get("/reports").get_data(as_text=True)
    assert "/reports/download/1" in page
    r = client.get("/reports/download/1")
    assert r.status_code == 200 and b"10.0.0.5" in r.data
    assert client.get("/reports/download/999").status_code == 404
