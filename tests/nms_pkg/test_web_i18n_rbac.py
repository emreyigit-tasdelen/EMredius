# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Comprehensive Unit & Integration Tests for Web APIs, RBAC, and Telemetry."""

import json
import os
import tempfile
import unittest

from nms.common.db import get_db_connection, init_db
from flask import Flask

from nms.web.routes_snmp import snmp_bp
from nms.web.routes_tacacs import tacacs_bp


def create_app(db_path):
    """Bare app with the NMS API blueprints (the panel adds auth/RBAC in front of them)."""
    app = Flask(__name__)
    app.register_blueprint(tacacs_bp)
    app.register_blueprint(snmp_bp)
    return app


class TestEnterpriseWebAPIs(unittest.TestCase):
    """Test suite covering TACACS+ and SNMP NMS REST APIs."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_nms.db")
        init_db(self.db_path)
        self._old_env = os.environ.get("NMS_DB_PATH")
        os.environ["NMS_DB_PATH"] = self.db_path  # the APIs only read the DB path from the environment

        self.app = create_app(db_path=self.db_path)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop("NMS_DB_PATH", None)
        else:
            os.environ["NMS_DB_PATH"] = self._old_env
        self.temp_dir.cleanup()

    # ---------------------------------------------------------
    # 1. TACACS+ Web API Tests
    # ---------------------------------------------------------
    def test_tacacs_status_stopped_and_running(self):
        # When stopped
        res = self.client.get(f"/api/tacacs/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["running"])
        self.assertIn("summary", data)

        # Inject running status into daemon_status
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO daemon_status (daemon_name, last_heartbeat, pid, status, metrics_json)
                VALUES ('tacacs_daemon', CURRENT_TIMESTAMP, 1234, 'RUNNING', '{"port": 49, "active_sessions": 2}')
                """
            )
            conn.commit()

        res2 = self.client.get(f"/api/tacacs/status")
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()
        self.assertTrue(data2["running"])
        self.assertEqual(data2["port"], 49)
        self.assertEqual(data2["active_sessions"], 2)

    def test_tacacs_clients_crud(self):
        # 1. Add client
        payload = {
            "name": "Core-Switch-01",
            "ip_cidr": "10.0.0.1/32",
            "shared_secret": "CiscoSecret2026!",
            "vendor": "cisco",
            "description": "Building A Core",
            "is_active": "1",
        }
        res = self.client.post(f"/api/tacacs/clients", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])

        # 2. List clients
        res2 = self.client.get(f"/api/tacacs/clients")
        self.assertEqual(res2.status_code, 200)
        clients = res2.get_json()
        self.assertTrue(any(c["ip_cidr"] == "10.0.0.1/32" for c in clients))
        target = [c for c in clients if c["ip_cidr"] == "10.0.0.1/32"][0]

        # 3. Delete client
        res3 = self.client.delete(f"/api/tacacs/clients/{target['id']}")
        self.assertEqual(res3.status_code, 200)

        # Verify deleted
        res4 = self.client.get(f"/api/tacacs/clients")
        clients_after = res4.get_json()
        self.assertFalse(any(c["ip_cidr"] == "10.0.0.1/32" for c in clients_after))

    def test_tacacs_users_crud(self):
        # 1. Add user
        payload = {
            "username": "netsec_engineer",
            "password": "SecurePass123!",
            "enable_password": "EnablePass123!",
            "chap_secret": "ChapSecret123!",
            "priv_lvl": 15,
            "group_id": 1,
            "enabled": "1",
        }
        res = self.client.post(f"/api/tacacs/users", json=payload)
        self.assertEqual(res.status_code, 200)

        # 2. List users
        res2 = self.client.get(f"/api/tacacs/users")
        self.assertEqual(res2.status_code, 200)
        users = res2.get_json()
        self.assertTrue(any(u["username"] == "netsec_engineer" for u in users))
        target = [u for u in users if u["username"] == "netsec_engineer"][0]
        self.assertEqual(target["priv_lvl"], 15)

        # 3. Delete user
        res3 = self.client.delete(f"/api/tacacs/users/{target['id']}")
        self.assertEqual(res3.status_code, 200)

    def test_tacacs_rules_and_live_tester(self):
        # Test default seeded rules for operator
        # Operator has permit "^show.*", deny "^reload.*"
        res_show = self.client.post(
            f"/api/tacacs/rules/test",
            json={"username": "operator", "command": "show ip interface brief", "priv_lvl": 7},
        )
        self.assertEqual(res_show.status_code, 200)
        data_show = res_show.get_json()
        self.assertTrue(data_show["permitted"])
        self.assertEqual(data_show["action"], "PERMITTED")

        res_reload = self.client.post(
            f"/api/tacacs/rules/test",
            json={"username": "operator", "command": "reload", "priv_lvl": 7},
        )
        self.assertEqual(res_reload.status_code, 200)
        data_reload = res_reload.get_json()
        self.assertFalse(data_reload["permitted"])
        self.assertEqual(data_reload["action"], "DENIED")

    def test_tacacs_accounting_query_and_export(self):
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO tacacs_accounting (device_ip, client_ip, username, priv_lvl, cmd, status)
                VALUES ('10.0.0.1', '192.168.1.50', 'operator', 7, 'show running-config', 'PERMITTED'),
                       ('10.0.0.1', '192.168.1.50', 'operator', 7, 'reload', 'DENIED')
                """
            )
            conn.commit()

        # Query all
        res = self.client.get(f"/api/tacacs/accounting")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["records"]), 2)

        # Filter by status
        res_filter = self.client.get(f"/api/tacacs/accounting?status=DENIED")
        self.assertEqual(res_filter.status_code, 200)
        data_filter = res_filter.get_json()
        self.assertEqual(data_filter["total"], 1)
        self.assertEqual(data_filter["records"][0]["cmd"], "reload")

        # CSV Export
        res_csv = self.client.get(f"/api/tacacs/accounting/export")
        self.assertEqual(res_csv.status_code, 200)
        self.assertIn("text/csv", res_csv.content_type)
        csv_text = res_csv.data.decode("utf-8")
        self.assertIn("Timestamp,Device IP", csv_text)
        self.assertIn("reload", csv_text)

    # ---------------------------------------------------------
    # 2. SNMP NMS Web API Tests
    # ---------------------------------------------------------
    def test_snmp_status_and_device_crud(self):
        # 1. Check status
        res = self.client.get(f"/api/snmp/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["running"])

        # 2. Add device
        dev_payload = {
            "ip": "10.10.10.1",
            "port": 161,
            "version": "v2c",
            "community": "public",
            "vendor": "Cisco",
            "sys_name": "Edge-Router-01",
            "sys_descr": "Cisco IOS-XE 17.6.3",
        }
        res_add = self.client.post(f"/api/snmp/devices", json=dev_payload)
        self.assertEqual(res_add.status_code, 200)

        # 3. List devices
        res_list = self.client.get(f"/api/snmp/devices")
        self.assertEqual(res_list.status_code, 200)
        devices = res_list.get_json()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["ip"], "10.10.10.1")
        self.assertEqual(devices[0]["vendor"], "Cisco")
        dev_id = devices[0]["id"]

        # 4. Delete device
        res_del = self.client.delete(f"/api/snmp/devices/{dev_id}")
        self.assertEqual(res_del.status_code, 200)

    def test_snmp_interfaces_and_telemetry_chart(self):
        with get_db_connection(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO snmp_devices (ip, port, version, community, vendor, sys_name)
                VALUES ('10.20.30.1', 161, 'v2c', 'public', 'MikroTik', 'Mikrotik-CCR')
                """
            )
            dev_id = cur.lastrowid
            cur.execute(
                """
                INSERT INTO snmp_interfaces (device_id, if_index, if_descr, if_name, if_speed, if_oper_status)
                VALUES (?, 1, 'GigabitEthernet0/1', 'ether1', 1000000000, 1)
                """,
                (dev_id,),
            )
            cur.execute(
                """
                INSERT INTO snmp_telemetry (device_id, if_index, in_bps, out_bps, in_pps, out_pps)
                VALUES (?, 1, 1500000.0, 3200000.0, 1200.0, 2400.0),
                       (?, 1, 1600000.0, 3400000.0, 1300.0, 2500.0)
                """,
                (dev_id, dev_id),
            )
            conn.commit()

        # Query interfaces
        res_if = self.client.get(f"/api/snmp/devices/{dev_id}/interfaces")
        self.assertEqual(res_if.status_code, 200)
        ifs = res_if.get_json()
        self.assertEqual(len(ifs), 1)
        self.assertEqual(ifs[0]["if_name"], "ether1")

        # Query telemetry time-series points for Chart.js
        res_telemetry = self.client.get(f"/api/snmp/telemetry/{dev_id}/1")
        self.assertEqual(res_telemetry.status_code, 200)
        tdata = res_telemetry.get_json()
        self.assertEqual(len(tdata["points"]), 2)
        self.assertEqual(tdata["points"][0]["in_bps"], 1500000.0)

    def test_snmp_alarms_lifecycle(self):
        with get_db_connection(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO snmp_devices (ip, vendor, sys_name)
                VALUES ('10.30.40.1', 'Huawei', 'Huawei-S5700')
                """
            )
            dev_id = cur.lastrowid
            cur.execute(
                """
                INSERT INTO alarms (device_id, if_index, alarm_type, severity, message, resolved)
                VALUES (?, 2, 'LINK_DOWN', 'CRITICAL', 'Interface GE0/0/2 link down', 0)
                """,
                (dev_id,),
            )
            alarm_id = cur.lastrowid
            conn.commit()

        # List active alarms
        res = self.client.get(f"/api/snmp/alarms?active_only=1")
        self.assertEqual(res.status_code, 200)
        alarms = res.get_json()
        self.assertEqual(len(alarms), 1)
        self.assertEqual(alarms[0]["severity"], "CRITICAL")

        # Acknowledge alarm
        res_ack = self.client.post(f"/api/snmp/alarms/{alarm_id}/ack")
        self.assertEqual(res_ack.status_code, 200)

        # Verify resolved
        res_after = self.client.get(f"/api/snmp/alarms?active_only=1")
        self.assertEqual(len(res_after.get_json()), 0)


if __name__ == "__main__":
    unittest.main()
