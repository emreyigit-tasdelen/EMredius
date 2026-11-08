# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import socket
import time
import struct

from conftest import login_as
from emredius.services import flows as fl


def ipb(s):
    return socket.inet_aton(s)


def v5_packet(src, dst, dport, proto, pkts, octets):
    hdr = struct.pack("!HHIIIIBBH", 5, 1, 0, int(time.time()), 0, 0, 0, 0, 0)
    rec = ipb(src) + ipb(dst) + b"\0" * 4 + struct.pack("!HH", 1, 2) + struct.pack("!II", pkts, octets) + b"\0" * 8 + \
        struct.pack("!HH", 1234, dport) + b"\0" + b"\0" + bytes([proto]) + b"\0" * 9
    assert len(rec) == 48
    return hdr + rec


def v9_template_and_data(ipfix):
    fields = [(8, 4), (12, 4), (4, 1), (11, 2), (1, 4), (2, 4)]
    tpl = struct.pack("!HH", 300, len(fields)) + b"".join(struct.pack("!HH", a, b) for a, b in fields)
    data = ipb("10.0.0.1") + ipb("8.8.8.8") + bytes([17]) + struct.pack("!H", 53) + struct.pack("!II", 1000, 10)
    ts, ds = (2, 0) if ipfix else (0, 0)
    tset = struct.pack("!HH", ts, 4 + len(tpl)) + tpl
    dset = struct.pack("!HH", 300, 4 + len(data)) + data
    body = tset + dset
    if ipfix:
        return struct.pack("!HHIII", 10, 16 + len(body), 0, 0, 7) + body
    return struct.pack("!HHIIII", 9, 2, 0, 0, 0, 7) + body


def test_collectors_and_queries(app):
    fl._buf.clear(); fl._templates.clear()
    assert fl.handle_packet(v5_packet("10.0.0.2", "1.1.1.1", 443, 6, 5, 4000), "192.0.2.1") == 1
    assert fl.handle_packet(v9_template_and_data(False), "192.0.2.2") == 1
    assert fl.handle_packet(v9_template_and_data(True), "192.0.2.3") == 1
    assert fl.handle_packet(b"\x00\x05junk", "192.0.2.1") == 0 and fl.handle_packet(b"", "x") == 0
    assert fl.handle_packet(struct.pack("!HH", 9, 99) + b"\0" * 30, "192.0.2.9") == 0
    with app.app_context():
        assert fl.flush() == 3 and fl.flush() == 0
        t = fl.top("src")
        assert t[0]["key"] == "10.0.0.2" and t[0]["bytes"] == 4000
        assert {r["name"] for r in fl.top("app")} >= {"HTTPS", "DNS"}
        assert fl.top("exporter") and fl.top("dst", q="8.8.8.8")[0]["key"] == "8.8.8.8"
        assert fl.top("src", tenant_id=2) == [] and len(fl.timeline()) == 1
        assert fl.overview()["exporters"] == 3 and "10.0.0.2" in fl.to_csv(t)


def test_pages_rbac(client):
    login_as(client, "superadmin")
    assert client.get("/flows").status_code == 200
    assert client.get("/flows/data?group=app&range=24h").get_json()["success"]
    assert client.get("/flows/data?group=zz&range=zz").get_json()["success"]
    assert client.get("/flows/export.csv").status_code == 200 and client.get("/flows/export.json").status_code == 200
    assert client.get("/flows/export.xml").status_code == 404
    login_as(client, "helpdesk")
    assert client.get("/flows").status_code in (302, 403)


def sflow_datagram(expanded=False):
    eth = b"\0" * 12 + b"\x08\x00"
    ip = bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0]) + ipb("10.1.1.1") + ipb("10.2.2.2")
    hdr = eth + ip + struct.pack("!HH", 40000, 443) + b"\0" * 16
    hdr += b"\0" * (-len(hdr) % 4)
    rec = struct.pack("!IIII", 1, 1500, 0, len(hdr)) + hdr
    rec = struct.pack("!II", 1, len(rec)) + rec
    if expanded:
        body = struct.pack("!IIIIIIIIIII", 1, 0, 1, 512, 0, 0, 0, 0, 0, 0, 1) + rec
        stype = 3
    else:
        body = struct.pack("!IIIIIIII", 1, 1, 512, 0, 0, 0, 0, 1) + rec
        stype = 1
    sample = struct.pack("!II", stype, len(body)) + body
    return struct.pack("!IIIIIII", 5, 1, 0x0A000001, 0, 1, 1000, 1) + sample


def test_sflow(app):
    fl._buf.clear()
    assert fl.handle_packet(sflow_datagram(), "192.0.2.50") == 1
    assert fl.handle_packet(sflow_datagram(True), "192.0.2.51") == 1
    assert fl.handle_packet(sflow_datagram()[:30], "192.0.2.52") == 0          # kısa/bozuk paket istisna fırlatmaz
    assert fl.overview()["sflow_packets"] >= 3
    with app.app_context():
        assert fl.flush() == 2
        t = fl.top("src")
        assert t[0]["key"] == "10.1.1.1" and t[0]["bytes"] == 2 * 1500 * 512     # iki ihracatçı, örnekleme oranı 512
        assert {r["name"] for r in fl.top("app")} == {"HTTPS"}


def test_extra_port_and_report_overview(app):
    import socket as so
    s = so.socket(so.AF_INET, so.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    fl._listen_extra("127.0.0.1", port)
    c = so.socket(so.AF_INET, so.SOCK_DGRAM)
    before = fl._stats["packets"]
    c.sendto(v5_packet("10.1.1.1", "10.2.2.2", 443, 6, 3, 900), ("127.0.0.1", port))
    for _ in range(40):
        if fl._stats["packets"] > before:
            break
        time.sleep(0.05)
    assert fl._stats["packets"] > before
    with app.app_context():
        fl.flush()
        data, err = fl.report_overview("15m")
    assert err is None and data["window"] == "15m" and "talkers_src" in data
