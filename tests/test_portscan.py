# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import socket
import threading

from conftest import login_as
from emredius.services import portscan as svc


def _listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    return s


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _no_audit(monkeypatch):
    monkeypatch.setattr(svc, "log_admin_action", lambda *a, **k: None)


def test_parse_ports():
    assert svc.parse_ports("443") == [443]
    assert svc.parse_ports("22, 80,8000-8002,80") == [22, 80, 8000, 8001, 8002]
    assert svc.parse_ports("0-65535") == list(range(1, 65536))
    assert svc.parse_ports("", "all") == list(range(1, 65536))
    assert svc.parse_ports("", "network") == svc.PRESETS["network"]
    for bad in ("0", "65536", "10-5", "a", "22;rm", "1-2-3", "000000001"):
        try:
            svc.parse_ports(bad)
        except svc.ScanError:
            continue
        raise AssertionError(bad)


def test_resolve_target_limits():
    assert svc.resolve_target("10.1.2.3") == "10.1.2.3"
    assert svc.resolve_target("127.0.0.1") == "127.0.0.1"
    assert svc.resolve_target("8.8.8.8", allow_public=True) == "8.8.8.8"
    for bad, public in (("8.8.8.8", False), ("224.0.0.1", True), ("0.0.0.0", True), ("10.0.0.0/24", True),
                        ("-oX", True), ("", True)):
        try:
            svc.resolve_target(bad, allow_public=public)
        except svc.ScanError:
            continue
        raise AssertionError(bad)


def test_scan_job_finds_open_port(monkeypatch):
    _no_audit(monkeypatch)
    lst = _listener()
    try:
        open_port, closed_port = lst.getsockname()[1], _free_port()
        jid = svc.start_scan("127.0.0.1", sorted([open_port, closed_port]), 0.5, user="scan-unit")
        svc.wait(jid)
    finally:
        lst.close()
    job = svc.get_job(jid, "scan-unit")
    assert job["status"] == "done" and [p["port"] for p in job["open"]] == [open_port]
    assert job["done"] == job["total"] == 2 and job["closed"] == 1
    assert svc.get_job(jid, "someone-else") is None and svc.get_job(jid, "x", is_superadmin=True)


def test_scan_cooldown_and_cancel(monkeypatch):
    _no_audit(monkeypatch)
    jid = svc.start_scan("127.0.0.1", list(range(1, 65536)), 0.3, user="cancel-user")
    try:
        svc.start_scan("127.0.0.1", [1], 0.3, user="cancel-user")
        raise AssertionError("second running scan allowed")
    except svc.ScanError:
        pass
    assert svc.cancel_job(jid, "cancel-user")
    svc.wait(jid, 60)
    assert svc.get_job(jid, "cancel-user")["status"] in ("cancelled", "done")


def test_portscan_page_flow(client, monkeypatch):
    _no_audit(monkeypatch)
    lst = _listener()
    try:
        port = lst.getsockname()[1]
        tok = login_as(client, "superadmin", user="page-user")
        resp = client.post("/portscan", data={"_csrf_token": tok, "target": "127.0.0.1", "ports": str(port),
                                               "timeout": "0.5"})
        assert resp.status_code == 302 and "job=" in resp.headers["Location"]
        jid = resp.headers["Location"].split("job=")[1]
        svc.wait(jid)
    finally:
        lst.close()
    assert client.get(f"/portscan?job={jid}").headers["Location"].endswith("/ip-scan")   # birleşik ekran
    data = client.get(f"/portscan/job/{jid}").get_json()
    assert data["success"] and data["job"]["open"][0]["port"] == port
    login_as(client, "network_admin", user="other-user")
    assert client.get(f"/portscan/job/{jid}").status_code == 404


def test_portscan_rbac(client):
    login_as(client, "superadmin")
    assert client.get("/portscan").headers["Location"].endswith("/ip-scan")
    assert "Taramayı Başlat" in client.get("/ip-scan").get_data(as_text=True) and "Port taraması" in client.get("/ip-scan").get_data(as_text=True)
    login_as(client, "helpdesk")
    assert client.get("/portscan").status_code == 302


def test_portscan_public_needs_superadmin(client):
    tok = login_as(client, "network_admin", user="na-user")
    body = client.post("/portscan", data={"_csrf_token": tok, "target": "8.8.8.8", "ports": "53"},
                       follow_redirects=True).get_data(as_text=True)
    assert "Süper Yönetici" in body and "data-job-id" not in body


def test_portscan_requires_csrf(client):
    login_as(client, "superadmin")
    assert client.post("/portscan", data={"target": "127.0.0.1", "ports": "22"}).status_code in (302, 400)
    assert client.post("/portscan/job/x/cancel").status_code in (302, 400)


def _fresh(monkeypatch):
    _no_audit(monkeypatch)
    monkeypatch.setattr(svc, "_jobs", {})
    monkeypatch.setattr(svc, "_last_start", {})


def test_concurrency_limit_and_visibility(monkeypatch):
    _fresh(monkeypatch)
    gate = threading.Event()
    monkeypatch.setattr(svc, "_probe", lambda ip, port, t: gate.wait(5) and "closed")
    monkeypatch.setattr(svc, "USER_COOLDOWN_SECONDS", 0)
    a = svc.start_scan("10.0.0.1", [22, 80], user="a", max_concurrent=3)
    a2 = svc.start_scan("10.0.0.4", [22, 80], user="a", max_concurrent=3)  # same account, second scan
    b = svc.start_scan("10.0.0.2", [22, 80], user="b", max_concurrent=3)  # another administrator at once
    for user in ("a", "c"):
        try:
            svc.start_scan("10.0.0.3", [22], user=user, max_concurrent=3)
            raise AssertionError("expected ScanError")
        except svc.ScanError as e:
            assert "en fazla 3" in str(e)
    assert svc.running_job_id("a") in (a, a2) and svc.running_job_id("c") is None
    assert sorted(j["user"] for j in svc.running_jobs()) == ["a", "a", "b"]
    assert {j["id"] for j in svc.recent_jobs("a")} == {a, a2}
    assert {j["id"] for j in svc.recent_jobs("x", is_superadmin=True)} == {a, a2, b}
    assert svc.cancel_job(a2, "a")
    assert not svc.cancel_job(a, "b") and svc.cancel_job(b, "x", is_superadmin=True)
    gate.set()
    svc.wait(a)
    svc.wait(a2)
    svc.wait(b)
    c = svc.start_scan("10.0.0.3", [22], user="c", max_concurrent=3)  # slot freed
    svc.wait(c)
    assert svc.get_job(c, "c")["status"] == "done"


def test_keeps_last_20(monkeypatch):
    _fresh(monkeypatch)
    monkeypatch.setattr(svc, "USER_COOLDOWN_SECONDS", 0)
    monkeypatch.setattr(svc, "_probe", lambda ip, port, t: "closed")
    ids = []
    for _ in range(svc.MAX_KEPT_JOBS + 3):
        ids.append(svc.start_scan("10.0.0.1", [22], user="u", max_concurrent=2))
        svc.wait(ids[-1])
    svc.start_scan("10.0.0.1", [22], user="u", max_concurrent=2)
    kept = [j["id"] for j in svc.recent_jobs("u") if j["status"] != "running"]
    assert len(kept) == svc.MAX_KEPT_JOBS and ids[0] not in kept and ids[-1] in kept


def test_max_concurrent_setting(monkeypatch):
    store = {}
    monkeypatch.setattr(svc, "get_setting", lambda k, d="": store.get(k, d))
    monkeypatch.setattr(svc, "set_setting", lambda k, v: store.__setitem__(k, v))
    assert svc.get_max_concurrent() == svc.DEFAULT_MAX_CONCURRENT
    assert svc.set_max_concurrent("5") is None and svc.get_max_concurrent() == 5
    for bad in ("0", "abc", str(svc.MAX_CONCURRENT_LIMIT + 1)):
        assert svc.set_max_concurrent(bad)
    assert svc.get_max_concurrent() == 5


def test_settings_route_superadmin_only(client, monkeypatch):
    store = {}
    monkeypatch.setattr(svc, "get_setting", lambda k, d="": store.get(k, d))
    monkeypatch.setattr(svc, "set_setting", lambda k, v: store.__setitem__(k, v))
    from emredius.blueprints.portscan import routes
    monkeypatch.setattr(routes, "log_admin_action", lambda *a, **k: None)
    tok = login_as(client, "network_admin")
    client.post("/portscan/settings", data={"_csrf_token": tok, "max_concurrent": "4"})
    assert "portscan_max_concurrent" not in store
    tok = login_as(client, "superadmin")
    assert client.post("/portscan/settings", data={"_csrf_token": tok, "max_concurrent": "4"}).status_code == 302
    assert store["portscan_max_concurrent"] == "4"
