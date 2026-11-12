# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import machist as mh


def _row(mac, dev, port, vlan=10, uplink=False):
    return {"mac": mac, "device_ip": dev, "port": port, "vlan": vlan, "uplink": uplink}


def test_record_history_move_and_new(app):
    with app.app_context():
        # ilk çalışma: geçmiş boş -> yeni MAC olayı yok
        assert mh.record(rows=[_row("aa:bb:cc:00:00:01", "10.0.0.1", "Gi1/0/1")]) == {"seen": 1, "moves": 0, "new": 0}
        # aynı yer: olay yok; uplink satırı yok sayılır
        assert mh.record(rows=[_row("aa:bb:cc:00:00:01", "10.0.0.1", "Gi1/0/1"),
                               _row("aa:bb:cc:00:00:09", "10.0.0.1", "Gi1/0/48", uplink=True)])["seen"] == 1
        # başka porta geçti + yepyeni MAC
        r = mh.record(rows=[_row("aa:bb:cc:00:00:01", "10.0.0.2", "Gi1/0/5"), _row("aa:bb:cc:00:00:02", "10.0.0.2", "Gi1/0/6")])
        assert (r["moves"], r["new"]) == (1, 1)
        ch = {c["kind"]: c for c in mh.pending_changes()}
        assert ch["move"]["prev_device_ip"] == "10.0.0.1" and ch["move"]["port"] == "Gi1/0/5"
        assert ch["new"]["mac"] == "aa:bb:cc:00:00:02"
        h = mh.history(q="AA-BB-CC-00-00-01", days=30)
        assert {(p["device_ip"], p["port"]) for p in h["ports"]} == {("10.0.0.1", "Gi1/0/1"), ("10.0.0.2", "Gi1/0/5")}
        assert mh.history(q="10.0.0.2")["ports"] and mh.history(q="")["ports"] == []
        mh.mark_handled([c["id"] for c in mh.pending_changes()])
        assert mh.pending_changes() == []


def test_history_tenant_isolated(app):
    with app.app_context():
        mh.record(tenant_id=1, rows=[_row("aa:bb:cc:00:00:07", "10.0.0.1", "Gi1/0/1")])
        assert mh.history(tenant_id=2, q="aa:bb:cc:00:00:07")["ports"] == []


def test_user_lookup_without_radius_db(app):
    with app.app_context():
        mh.record(rows=[_row("aa:bb:cc:00:00:01", "10.0.0.1", "Gi1/0/1")])
        h = mh.history(q="olmayankullanici")
        assert h["ports"] == [] and h["sessions"] == []


def test_machist_pages(client):
    login_as(client, "superadmin")
    assert client.get("/machist").status_code == 200
    j = client.get("/machist/data?q=aa:bb:cc:00:00:01&days=7").get_json()
    assert j["success"] and "ports" in j and "sessions" in j
    assert client.get("/machist/export.csv?q=x").status_code == 200
