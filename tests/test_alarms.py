# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.core import get_nms_db
from emredius.services import alarms as al, inventory as inv, watch


def tlv(tag, body):
    return bytes([tag, len(body)]) + body


def trap_v2(trap_oid_bytes, community=b"public"):
    def vb(oid, tag, val):
        return tlv(0x30, tlv(0x06, oid) + tlv(tag, val))
    snmptrap0 = bytes([0x2b, 6, 1, 6, 3, 1, 1, 4, 1, 0])
    vbs = tlv(0x30, vb(snmptrap0, 0x06, trap_oid_bytes) + vb(bytes([0x2b, 6, 1, 2, 1, 1, 5, 0]), 0x04, b"sw1"))
    pdu = tlv(0xA7, tlv(2, b"\x01") + tlv(2, b"\x00") + tlv(2, b"\x00") + vbs)
    return tlv(0x30, tlv(2, b"\x01") + tlv(4, community) + pdu)


def test_trap_parse_and_handle(app):
    link_down = bytes([0x2b, 6, 1, 6, 3, 1, 1, 5, 3])
    p = al.parse_trap(trap_v2(link_down))
    assert p["trap_oid"] == "1.3.6.1.6.3.1.1.5.3" and p["version"] == "v2c" and p["varbinds"][0][1] == "sw1"
    assert al.parse_trap(b"junk") is None and al.parse_trap(b"") is None
    with app.app_context():
        c = inv._db()
        c.execute("INSERT INTO inv_devices (tenant_id,ip,sys_name,status) VALUES (1,'10.0.0.1','sw1','ONLINE')")
        c.commit(); c.close()
        assert not al.handle_trap(trap_v2(link_down), "9.9.9.9")      # bilinmeyen kaynak
        assert al.handle_trap(trap_v2(link_down), "10.0.0.1") and al.handle_trap(trap_v2(link_down), "10.0.0.1")
        ev = al.list_events(source="trap")
        assert len(ev) == 1 and ev[0]["count"] == 2 and ev[0]["severity"] == "CRITICAL"


def test_rules_eval_ack_mail_off(app, monkeypatch):
    with app.app_context():
        c = inv._db()
        c.execute("INSERT INTO inv_devices (tenant_id,ip,sys_name,status) VALUES (1,'10.0.0.1','sw1','ONLINE')")
        c.commit(); c.close()
        n = get_nms_db()
        n.executescript(
            "CREATE TABLE IF NOT EXISTS snmp_devices (id INTEGER PRIMARY KEY, ip TEXT, sys_name TEXT, vendor TEXT);"
            "CREATE TABLE IF NOT EXISTS snmp_health (id INTEGER PRIMARY KEY, timestamp TEXT, device_id INT, cpu_percent REAL,"
            " memory_percent REAL, temperature_c REAL, uptime_seconds INT);"
            "INSERT INTO snmp_devices VALUES (1,'10.0.0.1','sw1','Cisco');"
            "INSERT INTO snmp_health VALUES (1,'2099-01-01 00:00:00',1,95,40,50,100);")
        n.commit(); n.close()
        assert al.add_rule("", "cpu", 80) and al.add_rule("x", "zzz", 1) and al.add_rule("x", "cpu", "abc")
        assert al.add_rule("x", "cpu", 80, "WARNING", "bad mail")
        assert al.add_rule("CPU yüksek", "cpu", 90, "CRITICAL", "ops@example.com") == ""
        assert al.add_rule("Bellek", "ram", 90) == "" and al.add_rule("Kapalı IP", "host_down", 0) == ""
        sent, orig = [], al.send_mail
        monkeypatch.setattr(al, "send_mail", lambda *a: sent.append(a) or True)
        assert al.evaluate() == 1 and len(sent) == 1
        assert al.evaluate() == 0 and al.list_events()[0]["count"] == 2    # tekrar: yeni olay yok, sayaç artar
        eid = al.list_events()[0]["id"]
        assert al.ack(eid, "emre") and not al.ack(eid, "emre")
        assert al.overview()["active"] == 0 and al.overview()["ack"] == 1
        n = get_nms_db(); n.execute("UPDATE snmp_health SET cpu_percent=10"); n.commit(); n.close()
        al.evaluate()
        assert al.list_events(status="resolved") and al.list_events(tenant_id=2) == []
        assert not al.mail_enabled() and orig("a@b.c", "s", "b") is False   # varsayılan kapalı
        watch.add_target("10.0.0.9", "gw")
        c = watch._db(); c.execute("UPDATE watch_targets SET status='DOWN'"); c.commit(); c.close()
        assert al.evaluate() == 1
        rid = al.list_rules()[0]["id"]
        assert al.toggle_rule(rid) and al.delete_rule(rid) and not al.delete_rule(rid, tenant_id=2)
        assert "10.0.0.9" in al.events_csv(al.list_events())


def test_pages_rbac(client):
    login_as(client, "superadmin")
    assert client.get("/alarms").status_code == 200
    assert client.get("/alarms/data?status=active&severity=CRITICAL").get_json()["success"]
    assert client.get("/alarms/data?status=zz").get_json()["success"]
    assert client.get("/alarms/export.csv").status_code == 200 and client.get("/alarms/export.json").status_code == 200
    assert client.get("/alarms/export.xml").status_code == 404
    assert client.post("/alarms/abc/ack", data={"_csrf_token": "tok"}).status_code in (200, 302, 400, 403)
    login_as(client, "helpdesk")
    assert client.get("/alarms").status_code in (302, 403)


def test_ssh_log_scan(app, monkeypatch):
    from emredius.services import configs as cf, vendors
    assert al.classify_log_line("%SYS-1-CPUHOG: critical task") == "CRITICAL" and al.classify_log_line("Power supply 2 failed") == "CRITICAL"
    assert al.classify_log_line("login ok for user x") is None and al.classify_log_line("authentication failure from 1.1.1.1") == "WARNING"
    assert vendors.log_commands("Cisco")[-1] == "show logging" and vendors.log_commands("MikroTik") == ["/log print"] and vendors.log_commands("zzz")
    with app.app_context():
        c = inv._db()
        c.execute("INSERT INTO inv_devices (tenant_id,ip,sys_name,vendor,status,ssh_ok) VALUES (1,'10.0.0.1','sw','Cisco','ONLINE',1)")
        c.commit(); c.close()
        assert cf.add_cred("k", "lab", "u", "p") == ""
        cid = cf.list_creds()[0]["id"]
        monkeypatch.setattr(cf, "ssh_available", lambda: True)
        monkeypatch.setattr(cf, "_ssh_run", lambda *a, **k: "ok line here\nFan fail on slot 3\nFan fail on slot 4\nuser admin logged in\n")
        assert al.scan_ssh_logs("k", cid) == (1, 0)          # rakamlar normalize edilir: iki satır tek olay
        assert al.scan_ssh_logs("k", cid) == (0, 0)          # tekrar: yeni olay yok
        ev = al.list_events(source="ssh")
        assert len(ev) == 1 and ev[0]["severity"] == "CRITICAL" and ev[0]["count"] == 4
        assert not al.ssh_settings()["enabled"]              # varsayılan kapalı
        assert al.scan_ssh_logs("k", 9999) == (0, 1)
