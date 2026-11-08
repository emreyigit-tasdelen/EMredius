# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import sqlite3

from conftest import login_as


def _seed(path):
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE daemon_status (daemon_name TEXT, status TEXT, last_heartbeat TEXT, metrics_json TEXT, pid INT);
        CREATE TABLE snmp_devices (id INTEGER PRIMARY KEY, ip TEXT, port INT, version TEXT, community TEXT, v3_auth_key TEXT,
                                   vendor TEXT, sys_name TEXT, status TEXT);
        CREATE TABLE snmp_interfaces (id INTEGER PRIMARY KEY, device_id INT);
        CREATE TABLE snmp_health (id INTEGER PRIMARY KEY, device_id INT, cpu_percent REAL, memory_percent REAL, uptime_seconds INT);
        CREATE TABLE alarms (id INTEGER PRIMARY KEY, device_id INT, timestamp TEXT, alarm_type TEXT, severity TEXT, message TEXT,
                             resolved INT);
    """)
    c.execute("INSERT INTO snmp_devices VALUES (1, '10.0.0.9', 161, 'v2c', 'S3cretComm', 'AuthKey99', 'cisco', "
              "'</script><script>alert(1)</script>', 'ONLINE')")
    c.execute("INSERT INTO snmp_interfaces VALUES (1, 1), (2, 1)")
    c.execute("INSERT INTO snmp_health VALUES (1, 1, 91.25, 10, 100)")
    c.execute("INSERT INTO alarms VALUES (1, 1, 't', 'CPU', 'critical', '<b>hot</b>', 0)")
    c.commit()
    c.close()


def test_snmp_page(app, client):
    _seed(app.config["NMS_DB_PATH"])
    login_as(client, "helpdesk")
    assert client.get("/snmp").status_code == 302
    login_as(client, "network_admin")
    body = client.get("/snmp").get_data(as_text=True)
    assert "S3cretComm" not in body and "AuthKey99" not in body
    assert "</script><script>alert(1)" not in body and "&lt;b&gt;hot&lt;/b&gt;" in body
    assert "91.2%" in body and "2 Port" in body and "ackAlarm(1)" in body
    assert 'id="snmpTopology"' in body and "/static/js/snmp.js" in body


def test_snmp_topology_json(app, client, monkeypatch):
    from emredius.core import net
    monkeypatch.setattr(net, "ping_host", lambda host, *a, **k: True)
    _seed(app.config["NMS_DB_PATH"])
    sqlite3.connect(app.config["NMS_DB_PATH"]).execute("UPDATE snmp_devices SET status='OFFLINE'").connection.commit()
    login_as(client, "helpdesk")
    assert client.get("/snmp/topology.json").status_code == 302
    login_as(client, "network_admin")
    r = client.get("/snmp/topology.json")
    body = r.get_data(as_text=True)
    assert r.status_code == 200 and "S3cretComm" not in body and "AuthKey99" not in body
    d = r.get_json()["devices"][0]
    assert d["ping"] is True and d["live_status"] == "ONLINE" and d["snmp_ok"] is False and "community" not in d and "v3_auth_key" not in d


def test_lang_button_single_toggle():
    js = open("emredius/static/js/app.js", encoding="utf-8").read()
    assert "langBtn.addEventListener" not in js


def test_topology_live_cache_and_force(app, client, monkeypatch):
    from emredius.core import net
    from emredius.services import snmp as svc
    monkeypatch.setattr(svc, "_LIVE_TTL", 3600)
    calls = []
    monkeypatch.setattr(net, "ping_host", lambda host, *a, **k: calls.append(host) or True)
    _seed(app.config["NMS_DB_PATH"])
    login_as(client, "network_admin")
    client.get("/snmp/topology.json?force=1")
    n = len(calls)
    client.get("/snmp/topology.json")
    assert len(calls) == n  # served from the short cache
    client.get("/snmp/topology.json?force=1")
    assert len(calls) == n * 2


def test_topology_stream(app, client, monkeypatch):
    from emredius.core import net
    from emredius.services import snmp_live
    monkeypatch.setattr(net, "ping_host", lambda host, *a, **k: True)
    monkeypatch.setattr(snmp_live, "INTERVAL", 0.05)
    monkeypatch.setattr(snmp_live, "KEEPALIVE", 0.2)
    monkeypatch.setattr(snmp_live, "MAX_LIFETIME", 1.0)
    snmp_live._state["subs"] = 0  # other tests (route crawlers) may leave an unclosed stream behind
    _seed(app.config["NMS_DB_PATH"])
    login_as(client, "helpdesk")
    assert client.get("/snmp/topology/stream").status_code == 302
    login_as(client, "network_admin")
    r = client.get("/snmp/topology/stream")
    body = r.get_data(as_text=True)
    assert r.status_code == 200 and r.mimetype == "text/event-stream" and r.headers["X-Accel-Buffering"] == "no"
    assert "data: " in body and "S3cretComm" not in body and "AuthKey99" not in body and "v3_auth_key" not in body
    r.close()  # werkzeug closes the iterable at request end; the test client needs it explicitly
    assert snmp_live._state["subs"] == 0
    monkeypatch.setattr(snmp_live, "MAX_STREAMS", 0)
    assert client.get("/snmp/topology/stream").status_code == 503


def test_snmp_js_no_broken_string_literals():
    js = open("emredius/static/js/snmp.js", encoding="utf-8").read().replace("\r\n", "\n")
    assert "+ '\n(' +" not in js  # raw newline inside a string literal is a JS syntax error
