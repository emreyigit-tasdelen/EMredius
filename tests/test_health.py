# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.core import get_nms_db
from emredius.services import health as h, inventory as inv


def test_health_service_and_pages(app, client):
    with app.app_context():
        c = inv._db()
        c.execute("INSERT INTO inv_devices (tenant_id,ip,sys_name,status) VALUES (1,'10.0.0.1','sw1','ONLINE')")
        c.commit(); c.close()
        n = get_nms_db()
        n.executescript(
            "CREATE TABLE IF NOT EXISTS snmp_devices (id INTEGER PRIMARY KEY, ip TEXT, sys_name TEXT, vendor TEXT);"
            "CREATE TABLE IF NOT EXISTS snmp_health (id INTEGER PRIMARY KEY, timestamp TEXT, device_id INT, cpu_percent REAL,"
            " memory_percent REAL, temperature_c REAL, uptime_seconds INT);"
            "CREATE TABLE IF NOT EXISTS snmp_telemetry (id INTEGER PRIMARY KEY, timestamp TEXT, device_id INT, if_index INT,"
            " in_bps REAL, out_bps REAL);"
            "INSERT INTO snmp_devices VALUES (1,'10.0.0.1','sw1','Cisco'),(2,'9.9.9.9','other','X');"
            "INSERT INTO snmp_health VALUES (1,'2099-01-01 00:00:00',1,90,40,50,100),(2,'2099-01-01 00:00:00',2,10,10,10,1);"
            "INSERT INTO snmp_telemetry VALUES (1,'t',1,3,5000,7000),(2,'t',2,1,1,1);")
        n.commit(); n.close()
        r = h.health_rows()
        assert len(r) == 1 and r[0]["state"] == "warn" and r[0]["cpu"] == 90  # başka kiracı/envanter dışı cihaz elenir
        assert len(h.traffic_rows()) == 1 and h.overview()["warn"] == 1
        assert len(h.health_rows(q="zzz")) == 0
        assert "'=x" in h.to_csv("health", [dict(r[0], name="=x")])
    login_as(client, "superadmin")
    assert client.get("/health").status_code == 200
    for k in ("health", "traffic", "history"):
        assert client.get(f"/health/data/{k}").get_json()["success"]
    assert client.get("/health/data/zz").status_code == 404
    assert client.get("/health/export/health.csv").status_code == 200
    assert client.get("/health/export/traffic.json").status_code == 200
    assert client.get("/health/export/x.csv").status_code == 404
    login_as(client, "helpdesk")
    assert client.get("/health").status_code in (302, 403)
