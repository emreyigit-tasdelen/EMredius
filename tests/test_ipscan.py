# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
import ipaddress
import threading

from conftest import login_as
from emredius.services import ipscan as svc


def test_parse_target_accepts_any_network():
    assert str(svc.parse_target("192.168.1.77/24")[0]) == "192.168.1.0/24"
    assert str(svc.parse_target("10.0.0.5")[0]) == "10.0.0.5/32"
    for ok in ("8.8.8.0/24", "10.0.0.0/8", "127.0.0.0/24", "fd00::/120", "0.0.0.0/0"):
        assert svc.parse_target(ok)[1] is None, ok
    for bad in ("", "abc", "-x", "10.0.0.0/33"):
        assert svc.parse_target(bad)[1], bad


def test_host_count_and_lazy_iter():
    assert svc.host_count(ipaddress.ip_network("10.1.1.0/24")) == 254
    assert svc.host_count(ipaddress.ip_network("10.0.0.0/8")) == 2 ** 24 - 2
    assert list(svc.iter_hosts(ipaddress.ip_network("10.1.1.9/32"))) == ["10.1.1.9"]
    assert next(svc.iter_hosts(ipaddress.ip_network("::/0"))) == "::1"  # never materialised


def _fake_cmd(cmd, timeout):
    if cmd[0] == "ping":
        ip = cmd[-1]
        if ip == "10.9.9.1":
            return 0, "64 bytes from 10.9.9.1: icmp_seq=1 ttl=64 time=0.42 ms", ""
        return 1, "", ""
    if cmd[:2] == ["ip", "neigh"]:
        return 0, ("10.9.9.1 dev eth0 lladdr b8:27:eb:00:00:01 REACHABLE\n"
                   "10.9.9.2 dev eth0 lladdr 00:0c:29:aa:bb:cc STALE\n"
                   "10.9.9.3 dev eth0  FAILED\n"
                   "192.168.5.5 dev eth1 lladdr 00:0c:29:00:00:01 STALE"), ""
    raise AssertionError(cmd)


def _no_socket(version):
    raise PermissionError("ICMP socket not allowed")


def _quiet(monkeypatch):
    """`ping`-process fallback with a fake run_cmd (the ICMP socket path is covered in test_icmp.py)."""
    monkeypatch.setattr(svc, "run_cmd", _fake_cmd)
    monkeypatch.setattr(svc.icmp, "open_socket", _no_socket)
    monkeypatch.setattr(svc, "log_admin_action", lambda *a, **k: None)
    svc._jobs.clear()


def test_scan_merges_ping_and_arp(monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.setattr(svc, "_reverse_dns", lambda ip: "gw.local" if ip == "10.9.9.1" else "")
    job_id = svc.start_scan(ipaddress.ip_network("10.9.9.0/29"), "unit")
    svc.wait(job_id)
    job = svc.get_job(job_id, "unit")
    assert job["status"] == "done" and job["total"] == 6 and job["done"] == 6
    by_ip = {h["ip"]: h for h in job["alive"]}
    assert list(by_ip) == ["10.9.9.1", "10.9.9.2"]  # ARP entry outside the network is ignored
    assert by_ip["10.9.9.1"]["rtt_ms"] == 0.42 and by_ip["10.9.9.1"]["vendor"] == "Raspberry Pi"
    assert by_ip["10.9.9.1"]["hostname"] == "gw.local"
    assert by_ip["10.9.9.2"]["rtt_ms"] is None and by_ip["10.9.9.2"]["vendor"] == "VMware"
    assert svc.get_job(job_id, "someone-else") is None
    assert svc.get_job(job_id, "someone-else", is_superadmin=True)


def test_per_user_limit_and_visibility(monkeypatch):
    _quiet(monkeypatch)
    gate = threading.Event()
    monkeypatch.setattr(svc, "_ping", lambda ip: gate.wait(5) and None)
    net = ipaddress.ip_network("10.0.0.0/16")
    a1 = svc.start_scan(net, "a", max_concurrent=2)
    a2 = svc.start_scan(net, "a", max_concurrent=2)  # the same user may run N scans at once
    b1 = svc.start_scan(net, "b", max_concurrent=2)  # other users have their own allowance
    try:
        svc.start_scan(net, "a", max_concurrent=2)
        raise AssertionError("expected ScanError")
    except svc.ScanError as e:
        assert "en fazla 2" in str(e)
    assert {j["id"] for j in svc.running_jobs("a")} == {a1, a2}
    assert {j["id"] for j in svc.running_jobs()} == {a1, a2, b1}  # superadmin overview
    assert svc.get_job(a1, "b") is None and svc.get_job(a1, "b", is_superadmin=True)
    assert not svc.cancel_job(a1, "b")
    assert svc.cancel_job(a1, "a")
    gate.set()
    for j in (a1, a2, b1):
        svc.wait(j)
    assert svc.get_job(a1, "a")["status"] == "cancelled"
    c = svc.start_scan(ipaddress.ip_network("10.9.9.0/30"), "a", max_concurrent=2)  # slot freed
    svc.wait(c)
    assert svc.get_job(c, "a")["status"] == "done"


def test_history_keeps_last_20_per_user_and_survives_restart(monkeypatch, tmp_path):
    _quiet(monkeypatch)
    monkeypatch.setattr(svc, "_reverse_dns", lambda ip: "")
    path = str(tmp_path / "hist.json")
    ids = []
    for i in range(22):
        jid = svc.start_scan(ipaddress.ip_network("10.9.9.0/30"), "a", max_concurrent=5, history_path=path)
        svc.wait(jid)
        ids.append(jid)
    svc.wait(svc.start_scan(ipaddress.ip_network("10.9.9.0/30"), "b", max_concurrent=5, history_path=path))
    hist = svc.list_history("a", path)
    assert len(hist) == 20 and hist[0]["id"] == ids[-1] and ids[0] not in {h["id"] for h in hist}
    assert "alive" not in hist[0] and len(svc.list_history("b", path)) == 1
    svc._jobs.clear()  # panel restart: finished scans come back from the file
    job = svc.get_job(ids[-1], "a", history_path=path)
    assert job["status"] == "done" and job["alive"] and job["alive_count"] == len(job["alive"])
    assert svc.get_job(ids[-1], "b", history_path=path) is None
    assert svc.get_job(ids[-1], "b", is_superadmin=True, history_path=path)
    assert svc.get_job(ids[0], "a", history_path=path) is None  # older than the last 20


def test_history_unwritable_does_not_break_scan(monkeypatch, tmp_path):
    _quiet(monkeypatch)
    blocker = tmp_path / "file"
    blocker.write_text("x")
    jid = svc.start_scan(ipaddress.ip_network("10.9.9.0/30"), "a", history_path=str(blocker / "h.json"))
    svc.wait(jid)
    assert svc.get_job(jid, "a")["status"] == "done"


def test_max_concurrent_setting(monkeypatch):
    store = {}
    monkeypatch.setattr(svc, "get_setting", lambda k, d="": store.get(k, d))
    monkeypatch.setattr(svc, "set_setting", lambda k, v: store.__setitem__(k, v))
    assert svc.get_max_concurrent() == svc.DEFAULT_MAX_CONCURRENT
    assert svc.set_max_concurrent("7") is None and svc.get_max_concurrent() == 7
    for bad in ("0", "abc", str(svc.MAX_CONCURRENT_LIMIT + 1)):
        assert svc.set_max_concurrent(bad)
    assert svc.get_max_concurrent() == 7


def test_settings_route_superadmin_only(client, monkeypatch):
    store = {}
    monkeypatch.setattr(svc, "get_setting", lambda k, d="": store.get(k, d))
    monkeypatch.setattr(svc, "set_setting", lambda k, v: store.__setitem__(k, v))
    tok = login_as(client, "network_admin")
    body = client.get("/ip-scan").get_data(as_text=True)
    assert 'name="max_concurrent"' not in body and "yalnızca Süper Yönetici" in body
    client.post("/ip-scan/settings", data={"_csrf_token": tok, "max_concurrent": "9"})
    assert "ipscan_max_concurrent" not in store
    tok = login_as(client, "superadmin")
    assert 'name="max_concurrent"' in client.get("/ip-scan").get_data(as_text=True)
    assert client.post("/ip-scan/settings", data={"_csrf_token": tok, "max_concurrent": "9"}).status_code == 200
    assert store["ipscan_max_concurrent"] == "9"
    assert "0 / 9" in client.get("/ip-scan").get_data(as_text=True)  # own scans / per-user limit


def test_ipscan_page_job_and_cancel_routes(client, monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.setattr(svc, "_reverse_dns", lambda ip: "<b>evil</b>")
    tok = login_as(client, "superadmin")
    assert "Taramayı Başlat" in client.get("/ip-scan").get_data(as_text=True)
    resp = client.post("/ip-scan", data={"_csrf_token": tok, "target": "10.9.9.0/29", "resolve_names": "1"})
    assert resp.status_code == 302 and "job=" in resp.headers["Location"]
    job_id = resp.headers["Location"].split("job=")[1]
    svc.wait(job_id)
    data = client.get(f"/ip-scan/job/{job_id}", headers={"Accept": "application/json"}).get_json()
    assert data["job"]["alive"][0]["hostname"] == "<b>evil</b>"  # JSON; the page renders it with textContent
    assert 'data-job-id="' + job_id in client.get(f"/ip-scan?job={job_id}").get_data(as_text=True)
    assert client.post(f"/ip-scan/job/{job_id}/cancel", headers={"X-CSRF-Token": tok}).get_json()["success"]
    assert client.get("/ip-scan/job/nope").status_code == 404
    # a public network is allowed and a new scan starts right after the previous one finished
    resp = client.post("/ip-scan", data={"_csrf_token": tok, "target": "8.8.8.8"})
    assert resp.status_code == 302 and "job=" in resp.headers["Location"]
    svc.wait(resp.headers["Location"].split("job=")[1])


def test_ipscan_rejects_invalid_and_csrf(client, monkeypatch):
    _quiet(monkeypatch)
    tok = login_as(client, "superadmin")
    body = client.post("/ip-scan", data={"_csrf_token": tok, "target": "999.1.1.1"}).get_data(as_text=True)
    assert "Geçersiz" in body and not svc._jobs
    assert client.post("/ip-scan", data={"target": "10.9.9.0/29"}).status_code == 302  # CSRF gate
    assert not svc._jobs


def test_ipscan_rbac(client):
    login_as(client, "helpdesk")
    assert client.get("/ip-scan").status_code == 302
    login_as(client, "network_admin")
    assert client.get("/ip-scan").status_code == 200
    login_as(client, "auditor")
    assert client.get("/ip-scan").status_code == 302


def test_scan_uses_icmp_socket_when_available(monkeypatch):
    from test_icmp import FakeIcmpSocket
    _quiet(monkeypatch)
    monkeypatch.setattr(svc, "_reverse_dns", lambda ip: "")
    fake = FakeIcmpSocket(alive={"10.9.9.1", "10.9.9.4"})
    monkeypatch.setattr(svc.icmp, "open_socket", lambda version: (fake, False))
    job_id = svc.start_scan(ipaddress.ip_network("10.9.9.0/29"), "unit")
    svc.wait(job_id)
    job = svc.get_job(job_id, "unit")
    assert job["method"] == "icmp-socket" and job["done"] == 6
    assert [h["ip"] for h in job["alive"]] == ["10.9.9.1", "10.9.9.2", "10.9.9.4"]  # .2 via ARP only
    assert job["alive"][0]["rtt_ms"] is not None and job["alive"][1]["rtt_ms"] is None
    assert len(fake.sent) == 6


def test_page_visibility_and_history_routes(client, monkeypatch):
    _quiet(monkeypatch)
    gate = threading.Event()
    monkeypatch.setattr(svc, "_ping", lambda ip: gate.wait(5) and None)
    monkeypatch.setattr(svc, "_reverse_dns", lambda ip: "")
    tok = login_as(client, "network_admin", user="ali")
    resp = client.post("/ip-scan", data={"_csrf_token": tok, "target": "10.0.0.0/20"})
    ali_job = resp.headers["Location"].split("job=")[1]
    # another administrator cannot see ali's running scan, the superadmin can
    tok = login_as(client, "network_admin", user="veli")
    page = client.get("/ip-scan").get_data(as_text=True)
    assert "10.0.0.0/20" not in page and "Tüm Aktif Taramalar" not in page
    assert client.get(f"/ip-scan/job/{ali_job}").status_code == 404
    assert client.post(f"/ip-scan/job/{ali_job}/cancel", headers={"X-CSRF-Token": tok}).status_code == 404
    tok = login_as(client, "superadmin", user="root")
    page = client.get("/ip-scan").get_data(as_text=True)
    assert "Tüm Aktif Taramalar" in page and "10.0.0.0/20" in page and "ali" in page
    assert client.get(f"/ip-scan/job/{ali_job}").status_code == 200
    gate.set()
    assert client.post(f"/ip-scan/job/{ali_job}/cancel", headers={"X-CSRF-Token": tok}).get_json()["success"]
    svc.wait(ali_job)
    # ali's finished scan is listed in ali's history only
    login_as(client, "network_admin", user="ali")
    page = client.get("/ip-scan").get_data(as_text=True)
    assert "Son Taramalarınız" in page and "Durduruldu" in page and f"/ip-scan?job={ali_job}\"" in page
    login_as(client, "network_admin", user="veli")
    assert f"/ip-scan?job={ali_job}\"" not in client.get("/ip-scan").get_data(as_text=True)


def test_scan_with_ports_finds_open_ports(monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.setattr(svc, "_reverse_dns", lambda ip: "")
    monkeypatch.setattr(svc.portscan, "_probe", lambda ip, port, t: "open" if (ip, port) == ("10.9.9.1", 22) else "closed")
    job_id = svc.start_scan(ipaddress.ip_network("10.9.9.0/29"), "unit", ports=[22, 80], allow_public=False)
    svc.wait(job_id)
    job = svc.get_job(job_id, "unit")
    by_ip = {h["ip"]: h for h in job["alive"]}
    assert [p["port"] for p in by_ip["10.9.9.1"]["ports"]] == [22] and by_ip["10.9.9.2"]["ports"] == []
    assert job["port_total"] == 4 and job["port_done"] == 4 and job["ports_scanned"] == 2


def test_port_scan_of_public_net_needs_superadmin(monkeypatch):
    _quiet(monkeypatch)
    import pytest
    with pytest.raises(svc.ScanError):
        svc.start_scan(ipaddress.ip_network("8.8.8.0/30"), "unit", ports=[80])


def test_start_route_returns_redirect_and_validates(client, monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.setattr(svc, "_reverse_dns", lambda ip: "")
    monkeypatch.setattr(svc.portscan, "_probe", lambda ip, port, t: "closed")
    tok = login_as(client, "superadmin")
    bad = client.post("/ip-scan/start", data={"_csrf_token": tok, "target": "nope"})
    assert bad.status_code == 400 and bad.get_json()["success"] is False
    bad = client.post("/ip-scan/start", data={"_csrf_token": tok, "target": "10.9.9.0/29", "port_mode": "custom", "ports": "x"})
    assert bad.status_code == 400
    ok = client.post("/ip-scan/start", data={"_csrf_token": tok, "target": "10.9.9.0/29", "port_mode": "common"})
    j = ok.get_json()
    assert j["success"] and j["redirect"].startswith("/ip-scan?job=") and "port_mode=common" in j["redirect"]
    svc.wait(j["job_id"])
    page = client.get(j["redirect"]).get_data(as_text=True)
    assert 'id="ipscanResult"' in page and "Açık Portlar" in page
