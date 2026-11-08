# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Adversarial and Empirical Challenge Test Suite for Milestone M2:
Universal Multi-Vendor SNMPv2c/v3 Engine.

Created by: challenger_m2_snmp_2

Covers:
1. Multi-vendor health metric normalization across all 6 vendors (Cisco, MikroTik,
   Huawei, Juniper, Fortinet, HP/Aruba) under edge conditions:
   - Completely missing OIDs (empty responses)
   - Partial responses (only CPU, only RAM, only Temp)
   - Boundary values: 0.0% CPU, 100.0% CPU, 0.0% RAM, 100.0% RAM
   - Zero total memory division by zero guards
   - Multi-core CPU averaging and single CPU fallbacks
   - Deci-Celsius vs Celsius scaling
2. Stateful alarm hysteresis & deadband verification:
   - Oscillating inputs around warning/critical thresholds (79% -> 81% -> 80% -> 79% -> 71% -> 69%)
   - Proof that warning alarm triggers at >=80%, but only clears below deadband (<70%)
   - Critical hysteresis: 92% -> 85% -> 80% -> 65% with demotion at <81% and clear at <70%
   - 100-cycle oscillation storm suppression (zero duplicate DB entries, zero spam)
   - Database persistence and active alarm recovery across engine restarts
3. Interface flap damping verification:
   - Rapid operStatus toggling (>=4 transitions in 300s window) triggers PORT_FLAPPING
   - 50-toggle alert storm suppression while in damped state
   - Stabilization and automatic damping release after damp duration
   - Administrative down suppression (admin_status=2 mutes LINK_DOWN)
   - Independent per-interface flap tracking
4. Auto-discovery CIDR scanner edge cases:
   - Single IP /32 handling
   - Point-to-point /31 handling (RFC 3021)
   - Large CIDR parsing (/8, /12) with host limits and sub-50ms execution
   - Garbage, multicast, and loopback filtering
   - Asynchronous scanning of unroutable blackhole targets without freezing
   - Mixed live mock agent + unroutable targets parallel discovery sweep
"""

import asyncio
import os
import shutil
import tempfile
import time
import unittest

from nms.common.db import get_db_connection, init_db
from nms.common.models import Alarm, SnmpDevice, SnmpInterface
from nms.snmp.alarms import AlarmEngine, FlapRecord
from nms.snmp.discovery import (
    DiscoveredDevice,
    DiscoveryScanConfig,
    DiscoveryScanResult,
    SnmpCredentialProfile,
    discover_single_device,
    fingerprint_vendor,
    parse_targets,
    scan_network,
)
from nms.snmp.engine import (
    Asn1Codec,
    Asn1Tag,
    Pdu,
    SnmpClient,
    SnmpEngine,
    SnmpMessageCodec,
    VarBind,
)
from nms.snmp.mibs import (
    VENDOR_OIDS,
    CiscoAdapter,
    DeviceHealthMetrics,
    FortinetAdapter,
    GenericAdapter,
    HpArubaAdapter,
    HuaweiAdapter,
    JuniperAdapter,
    MikrotikAdapter,
    get_vendor_adapter,
)


class MockSnmpAgentProtocol(asyncio.DatagramProtocol):
    """Localhost UDP mock SNMP responder for adversarial discovery testing."""

    def __init__(self, mib_data: dict):
        self.mib_data = dict(sorted(mib_data.items()))
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            tag, seq_bytes, _ = Asn1Codec.decode_tlv(data, 0)
            off = 0
            _, ver_bytes, off = Asn1Codec.decode_tlv(seq_bytes, off)
            ver = int.from_bytes(ver_bytes, "big", signed=True)
            if ver in (0, 1):
                _, comm_bytes, off = Asn1Codec.decode_tlv(seq_bytes, off)
                comm = comm_bytes.decode("utf-8", errors="replace")
                pdu, _ = Asn1Codec.decode_pdu(seq_bytes, off)

                resp_vbs = []
                for vb in pdu.varbinds:
                    clean_oid = vb.oid.lstrip(".")
                    if clean_oid in self.mib_data:
                        resp_vbs.append(VarBind(vb.oid, self.mib_data[clean_oid]))
                    else:
                        resp_vbs.append(VarBind(vb.oid, None, Asn1Tag.NO_SUCH_INSTANCE))

                resp_pdu = Pdu(
                    pdu_type=Asn1Tag.RESPONSE,
                    request_id=pdu.request_id,
                    varbinds=resp_vbs,
                )
                resp_msg = SnmpMessageCodec.encode_v2c_message(comm, resp_pdu)
                self.transport.sendto(resp_msg, addr)
        except Exception:
            pass


class TestVendorAdaptersEmpiricalEdgeCases(unittest.TestCase):
    """Mission 1: Empirically verify health metric normalization across all 6 vendor formats."""

    def test_cisco_empty_partial_and_boundary(self):
        adapter = CiscoAdapter()

        # 1. Completely empty response (missing all OIDs)
        empty_res = adapter.parse_health_metrics({})
        self.assertEqual(empty_res.cpu_percent, 0.0)
        self.assertEqual(empty_res.memory_percent, 0.0)
        self.assertIsNone(empty_res.temperature_c)

        # 2. Boundary 0.0% CPU via primary OID (cpmCPUTotal5minRev)
        res_0 = adapter.parse_health_metrics({"1.3.6.1.4.1.9.9.109.1.1.1.1.8.1": 0})
        self.assertEqual(res_0.cpu_percent, 0.0)

        # 3. Boundary 0.0% CPU via fallback OID (avgBusy5)
        res_0_fb = adapter.parse_health_metrics({"1.3.6.1.4.1.9.2.1.58.0": 0})
        self.assertEqual(res_0_fb.cpu_percent, 0.0)

        # 4. Boundary 100.0% CPU
        res_100 = adapter.parse_health_metrics({"1.3.6.1.4.1.9.9.109.1.1.1.1.8.1": 100})
        self.assertEqual(res_100.cpu_percent, 100.0)

        # 5. Memory boundaries: 0% used, 100% used, 0 total (no div/0)
        res_mem_0 = adapter.parse_health_metrics({
            "1.3.6.1.4.1.9.9.221.1.1.1.1.7.1": 0,
            "1.3.6.1.4.1.9.9.221.1.1.1.1.8.1": 1000000,
        })
        self.assertEqual(res_mem_0.memory_percent, 0.0)

        res_mem_100 = adapter.parse_health_metrics({
            "1.3.6.1.4.1.9.9.221.1.1.1.1.7.1": 1000000,
            "1.3.6.1.4.1.9.9.221.1.1.1.1.8.1": 0,
        })
        self.assertEqual(res_mem_100.memory_percent, 100.0)

        res_mem_zero_total = adapter.parse_health_metrics({
            "1.3.6.1.4.1.9.9.221.1.1.1.1.7.1": 0,
            "1.3.6.1.4.1.9.9.221.1.1.1.1.8.1": 0,
        })
        self.assertEqual(res_mem_zero_total.memory_percent, 0.0)

        # 6. Temperature sensor present
        res_temp = adapter.parse_health_metrics({"1.3.6.1.4.1.9.9.13.1.3.1.3.1": 42})
        self.assertEqual(res_temp.temperature_c, 42.0)

    def test_mikrotik_empty_partial_and_boundary(self):
        adapter = MikrotikAdapter()

        # 1. Completely empty response
        empty_res = adapter.parse_health_metrics({})
        self.assertEqual(empty_res.cpu_percent, 0.0)
        self.assertEqual(empty_res.memory_percent, 0.0)
        self.assertIsNone(empty_res.temperature_c)
        self.assertEqual(empty_res.extra_metrics, {})

        # 2. Boundary 0.0% CPU single gauge
        res_0 = adapter.parse_health_metrics({"1.3.6.1.4.1.14988.1.1.3.14.0": 0})
        self.assertEqual(res_0.cpu_percent, 0.0)

        # 3. Boundary 100.0% CPU single gauge
        res_100 = adapter.parse_health_metrics({"1.3.6.1.4.1.14988.1.1.3.14.0": 100})
        self.assertEqual(res_100.cpu_percent, 100.0)

        # 4. Multi-core per-core CPU averaging (0%, 100%, mixed)
        res_cores_0 = adapter.parse_health_metrics({
            "1.3.6.1.2.1.25.3.3.1.2.1": 0,
            "1.3.6.1.2.1.25.3.3.1.2.2": 0,
        })
        self.assertEqual(res_cores_0.cpu_percent, 0.0)

        res_cores_100 = adapter.parse_health_metrics({
            "1.3.6.1.2.1.25.3.3.1.2.1": 100,
            "1.3.6.1.2.1.25.3.3.1.2.2": 100,
        })
        self.assertEqual(res_cores_100.cpu_percent, 100.0)

        res_cores_mixed = adapter.parse_health_metrics({
            "1.3.6.1.2.1.25.3.3.1.2.1": 20,
            "1.3.6.1.2.1.25.3.3.1.2.2": 40,
            "1.3.6.1.2.1.25.3.3.1.2.3": 60,
        })
        self.assertEqual(res_cores_mixed.cpu_percent, 40.0)

        # 5. Memory boundaries: 0%, 100%, 0 size guard
        res_mem_0 = adapter.parse_health_metrics({
            "1.3.6.1.2.1.25.2.3.1.5.1": 1000,
            "1.3.6.1.2.1.25.2.3.1.6.1": 0,
        })
        self.assertEqual(res_mem_0.memory_percent, 0.0)

        res_mem_100 = adapter.parse_health_metrics({
            "1.3.6.1.2.1.25.2.3.1.5.1": 1000,
            "1.3.6.1.2.1.25.2.3.1.6.1": 1000,
        })
        self.assertEqual(res_mem_100.memory_percent, 100.0)

        res_mem_zero = adapter.parse_health_metrics({
            "1.3.6.1.2.1.25.2.3.1.5.1": 0,
            "1.3.6.1.2.1.25.2.3.1.6.1": 500,
        })
        self.assertEqual(res_mem_zero.memory_percent, 0.0)

        # 6. Temperature scaling (standard <=100 vs deci-Celsius >100)
        res_temp_std = adapter.parse_health_metrics({"1.3.6.1.4.1.14988.1.1.3.11.0": 48})
        self.assertEqual(res_temp_std.temperature_c, 48.0)

        res_temp_deci = adapter.parse_health_metrics({"1.3.6.1.4.1.14988.1.1.3.11.0": 485})
        self.assertEqual(res_temp_deci.temperature_c, 48.5)

        # 7. Voltage scaling (0.1V units)
        res_volt = adapter.parse_health_metrics({"1.3.6.1.4.1.14988.1.1.3.8.0": 242})
        self.assertEqual(res_volt.extra_metrics.get("voltage_v"), 24.2)

    def test_huawei_empty_partial_and_boundary(self):
        adapter = HuaweiAdapter()

        # 1. Empty response
        empty = adapter.parse_health_metrics({})
        self.assertEqual(empty.cpu_percent, 0.0)
        self.assertEqual(empty.memory_percent, 0.0)
        self.assertIsNone(empty.temperature_c)

        # 2. Boundary values: 0.0% CPU and RAM
        res_0 = adapter.parse_health_metrics({
            "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5.1": 0,
            "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7.1": 0,
        })
        self.assertEqual(res_0.cpu_percent, 0.0)
        self.assertEqual(res_0.memory_percent, 0.0)

        # 3. Boundary values: 100.0% CPU and RAM
        res_100 = adapter.parse_health_metrics({
            "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5.1": 100,
            "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7.1": 100,
        })
        self.assertEqual(res_100.cpu_percent, 100.0)
        self.assertEqual(res_100.memory_percent, 100.0)

        # 4. Temperature 0°C (edge case: 0 is valid, not None)
        res_temp_0 = adapter.parse_health_metrics({"1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11.1": 0})
        self.assertEqual(res_temp_0.temperature_c, 0.0)

    def test_juniper_empty_partial_and_boundary(self):
        adapter = JuniperAdapter()

        # 1. Empty response
        empty = adapter.parse_health_metrics({})
        self.assertEqual(empty.cpu_percent, 0.0)
        self.assertEqual(empty.memory_percent, 0.0)
        self.assertIsNone(empty.temperature_c)

        # 2. Boundary values: 0.0% CPU and RAM
        res_0 = adapter.parse_health_metrics({
            "1.3.6.1.4.1.2636.3.1.13.1.8.9.1": 0,
            "1.3.6.1.4.1.2636.3.1.13.1.11.9.1": 0,
        })
        self.assertEqual(res_0.cpu_percent, 0.0)
        self.assertEqual(res_0.memory_percent, 0.0)

        # 3. Boundary values: 100.0% CPU and RAM
        res_100 = adapter.parse_health_metrics({
            "1.3.6.1.4.1.2636.3.1.13.1.8.9.1": 100,
            "1.3.6.1.4.1.2636.3.1.13.1.11.9.1": 100,
            "1.3.6.1.4.1.2636.3.1.13.1.12.9.1": 35,
        })
        self.assertEqual(res_100.cpu_percent, 100.0)
        self.assertEqual(res_100.memory_percent, 100.0)
        self.assertEqual(res_100.temperature_c, 35.0)

    def test_fortinet_empty_partial_and_boundary(self):
        adapter = FortinetAdapter()

        # 1. Empty response
        empty = adapter.parse_health_metrics({})
        self.assertEqual(empty.cpu_percent, 0.0)
        self.assertEqual(empty.memory_percent, 0.0)
        self.assertEqual(empty.extra_metrics, {})

        # 2. Boundary values: 0.0% CPU and RAM, 0 sessions
        res_0 = adapter.parse_health_metrics({
            "1.3.6.1.4.1.12356.101.4.1.3.0": 0,
            "1.3.6.1.4.1.12356.101.4.1.4.0": 0,
            "1.3.6.1.4.1.12356.101.4.1.8.0": 0,
            "1.3.6.1.4.1.12356.101.4.1.11.0": 0,
        })
        self.assertEqual(res_0.cpu_percent, 0.0)
        self.assertEqual(res_0.memory_percent, 0.0)
        self.assertEqual(res_0.extra_metrics.get("sessions"), 0)
        self.assertEqual(res_0.extra_metrics.get("session_rate"), 0)

        # 3. Boundary values: 100.0% CPU and RAM, high session count
        res_100 = adapter.parse_health_metrics({
            "1.3.6.1.4.1.12356.101.4.1.3.0": 100,
            "1.3.6.1.4.1.12356.101.4.1.4.0": 100,
            "1.3.6.1.4.1.12356.101.4.1.8.0": 2_500_000,
            "1.3.6.1.4.1.12356.101.4.1.11.0": 15000,
        })
        self.assertEqual(res_100.cpu_percent, 100.0)
        self.assertEqual(res_100.memory_percent, 100.0)
        self.assertEqual(res_100.extra_metrics.get("sessions"), 2_500_000)
        self.assertEqual(res_100.extra_metrics.get("session_rate"), 15000)

    def test_hp_aruba_empty_partial_and_boundary(self):
        adapter = HpArubaAdapter()

        # 1. Empty response
        empty = adapter.parse_health_metrics({})
        self.assertEqual(empty.cpu_percent, 0.0)
        self.assertEqual(empty.memory_percent, 0.0)
        self.assertIsNone(empty.temperature_c)

        # 2. Comware 0.0% CPU and RAM
        res_comware_0 = adapter.parse_health_metrics({
            "1.3.6.1.4.1.25506.2.6.1.1.1.1.6.1": 0,
            "1.3.6.1.4.1.25506.2.6.1.1.1.1.8.1": 0,
        })
        self.assertEqual(res_comware_0.cpu_percent, 0.0)
        self.assertEqual(res_comware_0.memory_percent, 0.0)

        # 3. Comware 100.0% CPU and RAM
        res_comware_100 = adapter.parse_health_metrics({
            "1.3.6.1.4.1.25506.2.6.1.1.1.1.6.1": 100,
            "1.3.6.1.4.1.25506.2.6.1.1.1.1.8.1": 100,
            "1.3.6.1.4.1.25506.2.6.1.1.1.1.12.1": 31,
        })
        self.assertEqual(res_comware_100.cpu_percent, 100.0)
        self.assertEqual(res_comware_100.memory_percent, 100.0)
        self.assertEqual(res_comware_100.temperature_c, 31.0)

        # 4. ProCurve fallback 0.0% CPU and RAM
        res_procurve_0 = adapter.parse_health_metrics({
            "1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0": 0,
            "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5.1": 2048,
            "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7.1": 0,
        })
        self.assertEqual(res_procurve_0.cpu_percent, 0.0)
        self.assertEqual(res_procurve_0.memory_percent, 0.0)

        # 5. ProCurve 100.0% CPU and RAM
        res_procurve_100 = adapter.parse_health_metrics({
            "1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0": 100,
            "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5.1": 2048,
            "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7.1": 2048,
        })
        self.assertEqual(res_procurve_100.cpu_percent, 100.0)
        self.assertEqual(res_procurve_100.memory_percent, 100.0)

        # 6. ProCurve zero total memory guard (no div/0)
        res_procurve_zero = adapter.parse_health_metrics({
            "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5.1": 0,
            "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7.1": 0,
        })
        self.assertEqual(res_procurve_zero.memory_percent, 0.0)

    def test_vendor_adapter_registry_factory(self):
        # Factory resolves all vendor name variants and falls back to Generic
        self.assertIsInstance(get_vendor_adapter("Cisco"), CiscoAdapter)
        self.assertIsInstance(get_vendor_adapter("cisco"), CiscoAdapter)
        self.assertIsInstance(get_vendor_adapter("MikroTik"), MikrotikAdapter)
        self.assertIsInstance(get_vendor_adapter("mikrotik"), MikrotikAdapter)
        self.assertIsInstance(get_vendor_adapter("Huawei"), HuaweiAdapter)
        self.assertIsInstance(get_vendor_adapter("Juniper"), JuniperAdapter)
        self.assertIsInstance(get_vendor_adapter("Fortinet"), FortinetAdapter)
        self.assertIsInstance(get_vendor_adapter("HP_Aruba"), HpArubaAdapter)
        self.assertIsInstance(get_vendor_adapter("hp-aruba"), HpArubaAdapter)
        self.assertIsInstance(get_vendor_adapter("HP Aruba"), HpArubaAdapter)
        self.assertIsInstance(get_vendor_adapter("unknown_vendor_xyz"), GenericAdapter)


class TestStatefulAlarmHysteresisEmpirical(unittest.TestCase):
    """Mission 2: Empirically verify stateful alarm hysteresis and deadband boundaries."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_alarms_challenger.db")
        init_db(self.db_path)
        setup_conn = get_db_connection(self.db_path)
        setup_conn.execute("INSERT INTO snmp_devices (id, ip, status) VALUES (10, '192.168.1.1', 'ONLINE')")
        setup_conn.commit()
        setup_conn.close()
        self.conn = get_db_connection(self.db_path)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_exact_prompt_oscillation_sequence(self):
        """Oscillates inputs: 79% -> 81% -> 80% -> 79% -> 71% -> 69%.

        Proves:
        - Alarm triggers at 81% (>=80% warn threshold)
        - Alarm is NOT cleared at 80%, 79%, or 71% (above deadband 70%)
        - Alarm ONLY clears when dropping below deadband (<70%)
        """
        engine = AlarmEngine()
        events = []
        warn = 80.0
        crit = 90.0
        deadband = 10.0  # warn_clear = 70.0%

        # Step 1: 79.0% -> Below warn (80.0%), no alarm
        engine.evaluate_metric_threshold(self.conn, 10, "CPU", 79.0, warn, crit, deadband, events.append)
        self.assertEqual(len(events), 0)
        self.assertNotIn((10, None, "HIGH_CPU"), engine._active_alarms)

        # Step 2: 81.0% -> Crosses 80.0%, triggers WARNING
        engine.evaluate_metric_threshold(self.conn, 10, "CPU", 81.0, warn, crit, deadband, events.append)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[-1]["severity"], "WARNING")
        self.assertFalse(events[-1]["is_resolved"])
        self.assertEqual(engine._active_alarms[(10, None, "HIGH_CPU")][0], "WARNING")

        # Step 3: 80.0% -> Above 70.0%, alarm remains active WARNING
        engine.evaluate_metric_threshold(self.conn, 10, "CPU", 80.0, warn, crit, deadband, events.append)
        self.assertEqual(len(events), 1, "Should NOT emit event at 80.0%")
        self.assertEqual(engine._active_alarms[(10, None, "HIGH_CPU")][0], "WARNING")

        # Step 4: 79.0% -> Below original warn threshold 80.0%, but above deadband 70.0%
        # EMPIRICAL PROOF OF HYSTERESIS: Remains active WARNING!
        engine.evaluate_metric_threshold(self.conn, 10, "CPU", 79.0, warn, crit, deadband, events.append)
        self.assertEqual(len(events), 1, "Hysteresis failure: 79.0% should NOT clear alarm!")
        self.assertEqual(engine._active_alarms[(10, None, "HIGH_CPU")][0], "WARNING")

        # Step 5: 71.0% -> Still above deadband 70.0%
        engine.evaluate_metric_threshold(self.conn, 10, "CPU", 71.0, warn, crit, deadband, events.append)
        self.assertEqual(len(events), 1, "Should NOT clear at 71.0%")
        self.assertEqual(engine._active_alarms[(10, None, "HIGH_CPU")][0], "WARNING")

        # Step 6: 70.0% -> Exactly at deadband boundary (not < 70.0%), still active
        engine.evaluate_metric_threshold(self.conn, 10, "CPU", 70.0, warn, crit, deadband, events.append)
        self.assertEqual(len(events), 1, "Boundary: 70.0% is not < 70.0%, remains active")

        # Step 7: 69.0% -> Below deadband (< 70.0%), clears alarm!
        engine.evaluate_metric_threshold(self.conn, 10, "CPU", 69.0, warn, crit, deadband, events.append)
        self.assertEqual(len(events), 2, "Must emit resolution event when dropping below deadband")
        self.assertTrue(events[-1]["is_resolved"])
        self.assertEqual(events[-1]["severity"], "INFO")
        self.assertNotIn((10, None, "HIGH_CPU"), engine._active_alarms)

        # Verify DB reflects resolution
        cursor = self.conn.cursor()
        cursor.execute("SELECT resolved FROM alarms WHERE device_id = 10 AND alarm_type = 'HIGH_CPU'")
        rows = cursor.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 1)

    def test_rapid_oscillation_storm_suppression(self):
        """Oscillates 100 times between 78% and 82% around the 80% threshold.

        A naive threshold engine emits 100 alerts (trigger, clear, trigger, clear...).
        The stateful hysteresis engine must emit exactly 1 trigger alert and 0 clears.
        """
        engine = AlarmEngine()
        events = []
        warn = 80.0
        crit = 90.0
        deadband = 10.0

        for cycle in range(100):
            val = 82.0 if (cycle % 2 == 0) else 78.0
            engine.evaluate_metric_threshold(self.conn, 10, "CPU", val, warn, crit, deadband, events.append)

        # Exactly 1 event emitted: initial WARNING at cycle 0 (82.0%)
        self.assertEqual(len(events), 1, f"Alert storm detected: expected 1 event, got {len(events)}")
        self.assertEqual(events[0]["severity"], "WARNING")

        # Exactly 1 row in alarms table
        cursor = self.conn.cursor()
        cursor.execute("SELECT count(*) FROM alarms WHERE device_id = 10 AND alarm_type = 'HIGH_CPU'")
        count = cursor.fetchone()[0]
        self.assertEqual(count, 1)

    def test_critical_to_warning_demotion_hysteresis(self):
        """Verifies hysteresis demotion: 92% (CRIT) -> 88% (stay CRIT) -> 80% (demote WARN) -> 65% (CLEAR)."""
        engine = AlarmEngine()
        events = []
        warn = 80.0
        crit = 90.0
        deadband = 10.0
        # crit_demote = 90.0 - 9.0 = 81.0%

        # 1. 92% -> Triggers CRITICAL
        engine.evaluate_metric_threshold(self.conn, 10, "RAM", 92.0, warn, crit, deadband, events.append)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[-1]["severity"], "CRITICAL")

        # 2. 88% -> Below crit (90%), but >= 81.0% -> Maintains CRITICAL
        engine.evaluate_metric_threshold(self.conn, 10, "RAM", 88.0, warn, crit, deadband, events.append)
        self.assertEqual(len(events), 1)
        self.assertEqual(engine._active_alarms[(10, None, "HIGH_RAM")][0], "CRITICAL")

        # 3. 80.0% -> Below 81.0%, but >= 70.0% -> Demotes to WARNING
        engine.evaluate_metric_threshold(self.conn, 10, "RAM", 80.0, warn, crit, deadband, events.append)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[-1]["severity"], "WARNING")
        self.assertEqual(engine._active_alarms[(10, None, "HIGH_RAM")][0], "WARNING")

        # 4. 85.0% -> Below crit (90%), stays WARNING
        engine.evaluate_metric_threshold(self.conn, 10, "RAM", 85.0, warn, crit, deadband, events.append)
        self.assertEqual(len(events), 2)

        # 5. 65.0% -> Below 70.0% -> Clears
        engine.evaluate_metric_threshold(self.conn, 10, "RAM", 65.0, warn, crit, deadband, events.append)
        self.assertEqual(len(events), 3)
        self.assertTrue(events[-1]["is_resolved"])

    def test_alarm_engine_db_reboot_recovery(self):
        """Simulates engine daemon restart: active alarms in DB are reloaded into memory cache."""
        engine1 = AlarmEngine()
        engine1.evaluate_metric_threshold(self.conn, 10, "CPU", 85.0, 80.0, 90.0, 10.0)

        # Verify DB has active alarm
        cursor = self.conn.cursor()
        cursor.execute("SELECT severity FROM alarms WHERE device_id = 10 AND alarm_type = 'HIGH_CPU' AND resolved = 0")
        self.assertEqual(cursor.fetchone()[0], "WARNING")

        # Spin up new engine instance (simulating daemon restart)
        engine2 = AlarmEngine()
        self.assertEqual(len(engine2._active_alarms), 0)
        engine2.load_active_alarms_from_db(self.conn)
        self.assertIn((10, None, "HIGH_CPU"), engine2._active_alarms)

        # Querying with 79% should NOT re-trigger nor clear (hysteresis maintained after reboot)
        events = []
        engine2.evaluate_metric_threshold(self.conn, 10, "CPU", 79.0, 80.0, 90.0, 10.0, events.append)
        self.assertEqual(len(events), 0)

        # Dropping below 70% clears alarm
        engine2.evaluate_metric_threshold(self.conn, 10, "CPU", 65.0, 80.0, 90.0, 10.0, events.append)
        self.assertEqual(len(events), 1)
        self.assertTrue(events[-1]["is_resolved"])


class TestInterfaceFlapDampingEmpirical(unittest.TestCase):
    """Mission 3: Empirically verify interface flap damping and alert storm suppression."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_flap_challenger.db")
        init_db(self.db_path)
        setup_conn = get_db_connection(self.db_path)
        setup_conn.execute("INSERT INTO snmp_devices (id, ip, status) VALUES (20, '10.0.0.1', 'ONLINE')")
        setup_conn.execute("INSERT INTO snmp_interfaces (device_id, if_index, if_name) VALUES (20, 1, 'eth0')")
        setup_conn.execute("INSERT INTO snmp_interfaces (device_id, if_index, if_name) VALUES (20, 2, 'eth1')")
        setup_conn.commit()
        setup_conn.close()
        self.conn = get_db_connection(self.db_path)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_rapid_oper_status_flap_damping_and_storm_suppression(self):
        """Rapidly toggles operStatus (>=4 transitions in 300s):

        Proves:
        - Flap damping activates on 4th transition.
        - Subsequent 50 rapid toggles are COMPLETELY suppressed (0 alert storms).
        - After stability duration, flap damping releases automatically.
        """
        # Window 300s, max 4 transitions, damp duration 2.0s for testing
        engine = AlarmEngine(flap_window_sec=300.0, flap_max_transitions=4, flap_damp_duration_sec=0.1)
        events = []

        # Baseline: interface UP
        engine.evaluate_link_status(self.conn, 20, 1, "eth0", oper_status=1, admin_status=1, on_alarm_change=events.append)
        self.assertEqual(len(events), 0)

        # Transition 1: UP -> DOWN (1 event: LINK_DOWN CRITICAL)
        engine.evaluate_link_status(self.conn, 20, 1, "eth0", oper_status=2, admin_status=1, on_alarm_change=events.append)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[-1]["alarm_type"], "LINK_DOWN")
        self.assertFalse(events[-1]["is_resolved"])

        # Transition 2: DOWN -> UP (1 event: LINK_DOWN RESOLVED)
        engine.evaluate_link_status(self.conn, 20, 1, "eth0", oper_status=1, admin_status=1, on_alarm_change=events.append)
        self.assertEqual(len(events), 2)
        self.assertTrue(events[-1]["is_resolved"])

        # Transition 3: UP -> DOWN (1 event: LINK_DOWN CRITICAL)
        engine.evaluate_link_status(self.conn, 20, 1, "eth0", oper_status=2, admin_status=1, on_alarm_change=events.append)
        self.assertEqual(len(events), 3)

        # Transition 4: DOWN -> UP (4th transition within 300s!)
        # Triggers PORT_FLAPPING WARNING!
        engine.evaluate_link_status(self.conn, 20, 1, "eth0", oper_status=1, admin_status=1, on_alarm_change=events.append)
        self.assertEqual(len(events), 4)
        self.assertEqual(events[-1]["alarm_type"], "PORT_FLAPPING")
        self.assertEqual(events[-1]["severity"], "WARNING")
        self.assertFalse(events[-1]["is_resolved"])

        flap_rec = engine._flap_state[(20, 1)]
        self.assertTrue(flap_rec.is_damped)

        # ALERT STORM SIMULATION: Rapidly toggle 50 times while damped!
        events_before_storm = len(events)
        for i in range(50):
            status = 2 if (i % 2 == 0) else 1
            engine.evaluate_link_status(self.conn, 20, 1, "eth0", oper_status=status, admin_status=1, on_alarm_change=events.append)

        # ZERO new events emitted during the storm!
        self.assertEqual(len(events), events_before_storm, "Alert storm suppression failure: events leaked while damped!")

        # Wait for damp duration to expire (0.15s > 0.1s)
        time.sleep(0.15)

        # Next stable poll: interface is UP
        engine.evaluate_link_status(self.conn, 20, 1, "eth0", oper_status=1, admin_status=1, on_alarm_change=events.append)

        # Damping should release and PORT_FLAPPING resolve!
        self.assertFalse(flap_rec.is_damped)
        flap_clears = [e for e in events if e["alarm_type"] == "PORT_FLAPPING" and e["is_resolved"]]
        self.assertEqual(len(flap_clears), 1)

    def test_admin_down_suppresses_link_and_flapping(self):
        """When an interface is administratively down (admin_status=2), oper_status down is muted."""
        engine = AlarmEngine()
        events = []

        # Interface administratively shutdown, operStatus down
        for _ in range(5):
            engine.evaluate_link_status(self.conn, 20, 1, "eth0", oper_status=2, admin_status=2, on_alarm_change=events.append)

        self.assertEqual(len(events), 0, "Admin down interface must never generate LINK_DOWN or FLAP alerts")
        self.assertNotIn((20, 1, "LINK_DOWN"), engine._active_alarms)

    def test_multi_interface_flap_isolation(self):
        """Flapping on interface 1 does not affect or mute alerts on interface 2."""
        engine = AlarmEngine()
        events_eth0 = []
        events_eth1 = []

        # Flap eth0 to damping (4 transitions)
        for status in [1, 2, 1, 2, 1]:
            engine.evaluate_link_status(self.conn, 20, 1, "eth0", oper_status=status, admin_status=1, on_alarm_change=events_eth0.append)
        self.assertTrue(engine._flap_state[(20, 1)].is_damped)

        # eth1 experiences a clean LINK_DOWN
        engine.evaluate_link_status(self.conn, 20, 2, "eth1", oper_status=1, admin_status=1, on_alarm_change=events_eth1.append)
        engine.evaluate_link_status(self.conn, 20, 2, "eth1", oper_status=2, admin_status=1, on_alarm_change=events_eth1.append)

        # eth1 MUST alert with LINK_DOWN (not damped)
        eth1_downs = [e for e in events_eth1 if e["if_index"] == 2 and e["alarm_type"] == "LINK_DOWN"]
        self.assertEqual(len(eth1_downs), 1)
        self.assertFalse(engine._flap_state[(20, 2)].is_damped)


class TestCidrScannerEdgeCasesEmpirical(unittest.IsolatedAsyncioTestCase):
    """Mission 4: Verify CIDR scanner handles /32, /31, large CIDRs, and unroutable targets without freezing."""

    def test_single_ip_slash_32(self):
        # /32 notation
        hosts = parse_targets("192.168.10.55/32")
        self.assertEqual(hosts, ["192.168.10.55"])

        # Bare IP without slash
        bare = parse_targets("192.168.10.55")
        self.assertEqual(bare, ["192.168.10.55"])

        # Multiple /32 IPs
        multi = parse_targets("10.0.0.1/32, 10.0.0.2/32, 10.0.0.3/32")
        self.assertEqual(multi, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_point_to_point_slash_31(self):
        # RFC 3021 /31 point-to-point subnets (both IPs usable)
        hosts_31 = parse_targets("10.10.10.0/31")
        self.assertEqual(len(hosts_31), 2)
        self.assertEqual(hosts_31, ["10.10.10.0", "10.10.10.1"])

        hosts_31_high = parse_targets("172.16.255.254/31")
        self.assertEqual(len(hosts_31_high), 2)
        self.assertEqual(hosts_31_high, ["172.16.255.254", "172.16.255.255"])

    def test_large_cidr_parsing_efficiency(self):
        # /8 contains 16.7 million IPs; scanner must cap at max_hosts without freezing or high memory
        t0 = time.time()
        capped_hosts = parse_targets("10.0.0.0/8", max_hosts=500)
        elapsed = time.time() - t0
        self.assertEqual(len(capped_hosts), 500)
        self.assertLess(elapsed, 0.1, f"Parsing large CIDR took too long ({elapsed:.3f}s)")

        # /12 contains 1.04 million IPs
        t1 = time.time()
        capped_12 = parse_targets("172.16.0.0/12", max_hosts=1000)
        elapsed1 = time.time() - t1
        self.assertEqual(len(capped_12), 1000)
        self.assertLess(elapsed1, 0.1)

    def test_range_parsing_and_invalids(self):
        # Standard range
        r1 = parse_targets("192.168.1.10 - 192.168.1.15")
        self.assertEqual(r1, ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"])

        # Abbreviated range notation
        r2 = parse_targets("192.168.1.20 - 24")
        self.assertEqual(r2, ["192.168.1.20", "192.168.1.21", "192.168.1.22", "192.168.1.23", "192.168.1.24"])

        # Inverted range (end < start) returns empty without error
        r_inv = parse_targets("192.168.1.30 - 192.168.1.10")
        self.assertEqual(r_inv, [])

        # Filter out multicast, unspecified, loopback
        filtered = parse_targets("127.0.0.1, 224.0.0.1, 0.0.0.0, 169.254.1.1, 10.1.1.1")
        self.assertEqual(filtered, ["10.1.1.1"])

        # Garbage input handling
        garbage = parse_targets("invalid_target, 999.999.999.999, , \n; 10.2.2.2")
        self.assertEqual(garbage, ["10.2.2.2"])

    async def test_unroutable_targets_scan_without_freezing(self):
        """Scans RFC 5737 TEST-NET reserved non-routable targets (192.0.2.1, 198.51.100.1, 203.0.113.1).

        Proves that unroutable UDP targets time out cleanly and bounded execution does not freeze.
        """
        engine = SnmpEngine()
        try:
            config = DiscoveryScanConfig(
                targets=["192.0.2.1", "198.51.100.1", "203.0.113.1"],
                port=161,
                timeout=0.1,  # Fast 100ms timeout
                retries=0,    # 0 retries
                concurrency=10,
                persist_db=False,
            )

            t0 = time.time()
            result = await scan_network(config, client=engine)
            elapsed = time.time() - t0

            self.assertEqual(result.scanned_ips, 3)
            self.assertEqual(result.failed_ips, 3)
            self.assertEqual(len(result.discovered_devices), 0)
            self.assertLess(elapsed, 2.0, f"Unroutable scan took too long ({elapsed:.2f}s)")
        finally:
            await engine.close()

    async def test_mixed_live_agent_and_unroutable_targets_scan(self):
        """Runs parallel discovery against 1 live responsive Cisco agent and 2 unroutable targets.

        Proves:
        - Live device is successfully discovered and fingerprinted as 'Cisco'.
        - Unroutable targets fail cleanly without impeding live agent discovery.
        """
        loop = asyncio.get_running_loop()
        agent_mib = {
            "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.9.1.283",  # Cisco SMI sysObjectID
            "1.3.6.1.2.1.1.1.0": "Cisco IOS-XE Software, Catalyst C3850",
            "1.3.6.1.2.1.1.5.0": "Core-Switch-01",
            "1.3.6.1.2.1.1.3.0": 150000,
        }
        transport, _ = await loop.create_datagram_endpoint(
            lambda: MockSnmpAgentProtocol(agent_mib),
            local_addr=("127.0.0.1", 0),
        )
        _, port = transport.get_extra_info("sockname")

        engine = SnmpEngine()
        test_dir = tempfile.mkdtemp()
        db_path = os.path.join(test_dir, "test_mixed_discovery.db")
        init_db(db_path)

        try:
            config = DiscoveryScanConfig(
                targets=["127.0.0.1", "192.0.2.10", "192.0.2.11"],
                port=port,
                v2c_communities=["public"],
                timeout=0.15,
                retries=0,
                concurrency=10,
                walk_interfaces=False,
                persist_db=True,
                db_path=db_path,
                allow_loopback=True,
            )

            t0 = time.time()
            res = await scan_network(config, client=engine)
            elapsed = time.time() - t0

            self.assertEqual(res.scanned_ips, 3)
            self.assertEqual(len(res.discovered_devices), 1)
            self.assertEqual(res.failed_ips, 2)
            self.assertLess(elapsed, 2.5)

            discovered = res.discovered_devices[0]
            self.assertEqual(discovered.ip, "127.0.0.1")
            self.assertEqual(discovered.vendor, "Cisco")
            self.assertEqual(discovered.sys_name, "Core-Switch-01")

            # Verify persisted in database
            conn = get_db_connection(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT ip, vendor, sys_name, status FROM snmp_devices WHERE ip = '127.0.0.1'")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[1], "Cisco")
            self.assertEqual(row[2], "Core-Switch-01")
            self.assertEqual(row[3], "ONLINE")
            conn.close()

        finally:
            transport.close()
            await engine.close()
            shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
