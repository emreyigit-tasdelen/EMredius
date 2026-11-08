# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import json
import sqlite3
import time

from conftest import login_as


def _seed(path):
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE daemon_status (daemon_name TEXT, status TEXT, last_heartbeat TEXT, metrics_json TEXT);
        CREATE TABLE tacacs_clients (id INTEGER PRIMARY KEY, name TEXT, ip_cidr TEXT, shared_secret TEXT, vendor TEXT, is_active INT);
        CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT, priv_lvl INT);
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, priv_lvl INT, group_id INT, enable_password_hash TEXT,
                            chap_secret TEXT, enabled INT);
        CREATE TABLE tacacs_rules (id INTEGER PRIMARY KEY, group_id INT, priority INT, pattern TEXT, action TEXT, description TEXT);
        CREATE TABLE tacacs_accounting (id INTEGER PRIMARY KEY, timestamp TEXT, device_ip TEXT, client_ip TEXT, username TEXT,
                                        priv_lvl INT, cmd TEXT, status TEXT);
    """)
    c.execute("INSERT INTO daemon_status VALUES ('tacacs_daemon', 'RUNNING', '2026-10-10 10:00:00', ?)",
              (json.dumps({"heartbeat_epoch": time.time(), "port": 49, "uptime_seconds": 3600, "active_sessions": 2}),))
    c.execute("INSERT INTO tacacs_clients VALUES (1, 'sw''1<x>', '10.0.0.0/24', 's\"ec', 'cisco', 1)")
    c.execute("INSERT INTO groups VALUES (1, 'admins', 15)")
    c.execute("INSERT INTO users VALUES (1, 'admin', 15, 1, 'h', NULL, 1), (2, 'bob', 1, 1, NULL, NULL, 0)")
    c.execute("INSERT INTO tacacs_rules VALUES (1, 1, 10, '^show <.*>', 'permit', NULL)")
    c.execute("INSERT INTO tacacs_accounting VALUES (1, 't', '10.0.0.1', '10.0.0.2', '<img src=x>', 15, 'conf t', 'DENIED')")
    c.commit()
    c.close()


def test_tacacs_page(app, client, tmp_path):
    _seed(app.config["NMS_DB_PATH"])
    login_as(client, "auditor")
    assert client.get("/tacacs").status_code == 302
    login_as(client, "network_admin")
    body = client.get("/tacacs").get_data(as_text=True)
    assert "ÇALIŞIYOR (Port 49)" in body and "&lt;img src=x&gt;" in body and "<img src=x>" not in body
    assert "sw&#39;1&lt;x&gt;" in body and "deleteClient(1, 'sw\\u00271\\u003cx\\u003e')" in body
    assert "deleteUser(2, 'bob')" in body and "deleteUser(1," not in body
    assert body.count('<option value="1"') == 2


def test_tacacs_page_without_nms_db(client):
    login_as(client, "network_admin")
    body = client.get("/tacacs").get_data(as_text=True)
    assert "DURDURULDU" in body and "veritabanı okuma hatası" in body


def test_daemon_alive_falls_back_to_last_heartbeat_column():
    """NMS daemons do not write metrics_json.heartbeat_epoch; the last_heartbeat column must be used."""
    import json as _json
    from datetime import datetime, timedelta, timezone
    from emredius.core.system import daemon_alive
    now = datetime.now(timezone.utc)
    iso = now.isoformat()
    sqlite_fmt = now.strftime("%Y-%m-%d %H:%M:%S")
    for fresh in (iso, sqlite_fmt):
        assert daemon_alive({"status": "RUNNING", "metrics_json": _json.dumps({}), "last_heartbeat": fresh})
    old = (now - timedelta(minutes=5)).isoformat()
    assert not daemon_alive({"status": "RUNNING", "metrics_json": "{}", "last_heartbeat": old})
    assert not daemon_alive({"status": "RUNNING", "metrics_json": "{}", "last_heartbeat": None})
    assert not daemon_alive({"status": "STOPPED", "metrics_json": "{}", "last_heartbeat": iso})
