# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Comprehensive Test Suite for Milestone M2: Universal Multi-Vendor SNMPv2c/v3 Engine.

Covers:
- Pure-Python ASN.1 BER codec (integers, unsigned, OIDs, strings, PDUs, exceptions)
- SNMPv2c protocol codec and client/server UDP roundtrips (Get, GetNext, GetBulk, Walk)
- SNMPv3 USM security model: noAuthNoPriv, authNoPriv, authPriv (MD5, SHA1, SHA224, SHA256, DES, AES128/192/256)
- RFC 3414 password localization and dynamic EngineID discovery & time synchronization
- All 6 vendor MIB parsers & adapters (Cisco, MikroTik, Huawei, Juniper, Fortinet, HP/Aruba)
- Auto-discovery CIDR scanner, vendor fingerprinting, interface walk, and waterfall auth
- Telemetry math engine: 32-bit and 64-bit counter wraps, reboot spike suppression, delta rates
- Stateful alarm engine: 10% hysteresis deadband, flap damping storm suppression, reachability
- Webhook dispatchers: Telegram Bot Markdown & Slack Block Kit attachments
- SQLite WAL persistence and SnmpPollerDaemon lifecycle
"""

import asyncio
import os
import shutil
import tempfile
import time
import unittest

from nms.common.db import DEFAULT_DB_PATH, get_db_connection, init_db
from nms.common.models import (
    Alarm,
    SnmpDevice,
    SnmpHealth,
    SnmpInterface,
    SnmpTelemetry,
)
from nms.snmp.alarms import AlarmEngine, FlapRecord
from nms.snmp.discovery import (
    DiscoveredDevice,
    DiscoveredInterface,
    DiscoveryScanConfig,
    DiscoveryScanResult,
    SnmpCredentialProfile,
    discover_interfaces,
    discover_single_device,
    fingerprint_vendor,
    format_mac_address,
    parse_targets,
    persist_discovered_device,
    probe_credentials,
    scan_network,
)
from nms.snmp.engine import (
    Asn1Codec,
    Asn1Tag,
    EngineCache,
    Pdu,
    SnmpClient,
    SnmpEngine,
    SnmpMessageCodec,
    SnmpResponse,
    SnmpV3Credentials,
    UsmCrypto,
    VarBind,
)
from nms.snmp.mibs import (
    IF_TABLE_COLUMNS,
    IF_X_TABLE_COLUMNS,
    RFC1213_SYS_GROUP,
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
from nms.snmp.poller import PollerDaemonMetrics, SnmpPollerDaemon
from nms.snmp.telemetry import (
    WRAP_32,
    WRAP_64,
    InterfaceRates,
    InterfaceSample,
    TelemetryEngine,
    calculate_counter_delta,
)
from nms.snmp.webhooks import (
    SlackDispatcher,
    TelegramDispatcher,
    WebhookManager,
)


class MockSnmpAgentProtocol(asyncio.DatagramProtocol):
    """Localhost Mock SNMP Agent for genuine end-to-end UDP network testing."""

    def __init__(self, mib_data: dict, v3_creds: SnmpV3Credentials = None, engine_id: bytes = b"mock_engine_01"):
        self.mib_data = dict(sorted(mib_data.items()))
        self.v3_creds = v3_creds
        self.engine_id = engine_id
        self.boots = 1
        self.engine_time = 500
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            tag, seq_bytes, _ = Asn1Codec.decode_tlv(data, 0)
            off = 0
            _, ver_bytes, off = Asn1Codec.decode_tlv(seq_bytes, off)
            ver = int.from_bytes(ver_bytes, "big", signed=True)

            if ver in (0, 1):  # SNMPv1 / SNMPv2c
                _, comm_bytes, off = Asn1Codec.decode_tlv(seq_bytes, off)
                comm = comm_bytes.decode("utf-8", errors="replace")
                pdu, _ = Asn1Codec.decode_pdu(seq_bytes, off)
                resp_pdu = self._handle_pdu(pdu)
                resp_msg = SnmpMessageCodec.encode_v2c_message(comm, resp_pdu)
                self.transport.sendto(resp_msg, addr)

            elif ver == 3:  # SNMPv3
                # Check for discovery probe or regular request
                _, header_bytes, off = Asn1Codec.decode_tlv(seq_bytes, off)
                h_off = 0
                _, msg_id_bytes, h_off = Asn1Codec.decode_tlv(header_bytes, h_off)
                msg_id = int.from_bytes(msg_id_bytes, "big", signed=True)

                _, sec_param_raw, _ = Asn1Codec.decode_tlv(seq_bytes, off)
                _, sec_param_bytes, _ = Asn1Codec.decode_tlv(sec_param_raw, 0)
                _, req_engine_id, _ = Asn1Codec.decode_tlv(sec_param_bytes, 0)

                if req_engine_id == b"":
                    # RFC 3414 Discovery Probe -> Reply with Report PDU
                    report_pdu = Pdu(
                        pdu_type=Asn1Tag.REPORT,
                        request_id=msg_id,
                        varbinds=[VarBind("1.3.6.1.6.3.15.1.1.4.0", 1, Asn1Tag.COUNTER32)],
                    )
                    resp_msg = SnmpMessageCodec.encode_v3_message(
                        msg_id=msg_id,
                        pdu=report_pdu,
                        creds=None,
                        engine_id=self.engine_id,
                        engine_boots=self.boots,
                        engine_time=self.engine_time,
                    )
                    self.transport.sendto(resp_msg, addr)
                    return

                # Normal SNMPv3 request
                _, pdu, _, _, _ = SnmpMessageCodec.decode_v3_message(data, self.v3_creds)
                resp_pdu = self._handle_pdu(pdu)
                resp_msg = SnmpMessageCodec.encode_v3_message(
                    msg_id=msg_id,
                    pdu=resp_pdu,
                    creds=self.v3_creds,
                    engine_id=self.engine_id,
                    engine_boots=self.boots,
                    engine_time=self.engine_time,
                )
                self.transport.sendto(resp_msg, addr)

        except Exception as exc:
            pass

    def _handle_pdu(self, pdu: Pdu) -> Pdu:
        resp_vbs = []
        if pdu.pdu_type in (Asn1Tag.GET_REQUEST, Asn1Tag.SET_REQUEST):
            for vb in pdu.varbinds:
                clean_oid = vb.oid.lstrip(".")
                val = self.mib_data.get(clean_oid)
                if val is not None:
                    resp_vbs.append(VarBind(vb.oid, val))
                else:
                    resp_vbs.append(VarBind(vb.oid, None, Asn1Tag.NO_SUCH_INSTANCE))

        elif pdu.pdu_type == Asn1Tag.GET_NEXT_REQUEST:
            for vb in pdu.varbinds:
                clean_oid = vb.oid.lstrip(".")
                found = False
                for m_oid, m_val in self.mib_data.items():
                    if m_oid > clean_oid:
                        resp_vbs.append(VarBind(m_oid, m_val))
                        found = True
                        break
                if not found:
                    resp_vbs.append(VarBind(vb.oid, None, Asn1Tag.END_OF_MIB_VIEW))

        elif pdu.pdu_type == Asn1Tag.GET_BULK_REQUEST:
            # Handle repetitions
            for vb in pdu.varbinds:
                clean_oid = vb.oid.lstrip(".")
                curr = clean_oid
                for _ in range(pdu.max_repetitions or 10):
                    found = False
                    for m_oid, m_val in self.mib_data.items():
                        if m_oid > curr:
                            resp_vbs.append(VarBind(m_oid, m_val))
                            curr = m_oid
                            found = True
                            break
                    if not found:
                        resp_vbs.append(VarBind(curr, None, Asn1Tag.END_OF_MIB_VIEW))
                        break

        return Pdu(
            pdu_type=Asn1Tag.RESPONSE,
            request_id=pdu.request_id,
            error_status=0,
            error_index=0,
            varbinds=resp_vbs,
        )


class TestSnmpAsn1Codec(unittest.TestCase):
    """Unit tests for pure-Python ASN.1 BER Codec."""

    def test_integer_codec_boundary_values(self):
        test_values = [
            0, 1, 127, 128, 255, 256, 32767, 32768, 65535, 65536,
            -1, -128, -129, -32768, -32769, 2**31 - 1, -(2**31),
        ]
        for val in test_values:
            encoded = Asn1Codec.encode_integer(val)
            tag, val_bytes, next_off = Asn1Codec.decode_tlv(encoded)
            self.assertEqual(tag, Asn1Tag.INTEGER)
            self.assertEqual(next_off, len(encoded))
            decoded = Asn1Codec.decode_value(tag, val_bytes)
            self.assertEqual(decoded, val)

    def test_unsigned_integers_codec(self):
        # 32-bit Counter32, Gauge32, TimeTicks
        for tag in (Asn1Tag.COUNTER32, Asn1Tag.GAUGE32, Asn1Tag.TIMETICKS):
            val = 4_294_967_295  # 2^32 - 1
            encoded = Asn1Codec.encode_unsigned(val, tag)
            d_tag, val_bytes, _ = Asn1Codec.decode_tlv(encoded)
            self.assertEqual(d_tag, tag)
            self.assertEqual(Asn1Codec.decode_value(d_tag, val_bytes), val)

        # 64-bit Counter64
        val64 = 18_446_744_073_709_551_615  # 2^64 - 1
        encoded = Asn1Codec.encode_unsigned(val64, Asn1Tag.COUNTER64)
        d_tag, val_bytes, _ = Asn1Codec.decode_tlv(encoded)
        self.assertEqual(d_tag, Asn1Tag.COUNTER64)
        self.assertEqual(Asn1Codec.decode_value(d_tag, val_bytes), val64)

    def test_oid_encoding_and_decoding(self):
        test_oids = [
            "1.3.6.1.2.1.1.1.0",
            "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1",
            "1.3.6.1.4.1.14988.1.1.3.14.0",
            "2.5.4.3",
        ]
        for oid in test_oids:
            encoded = Asn1Codec.encode_oid(oid)
            tag, val_bytes, _ = Asn1Codec.decode_tlv(encoded)
            self.assertEqual(tag, Asn1Tag.OBJECT_IDENTIFIER)
            decoded = Asn1Codec.decode_oid(val_bytes)
            self.assertEqual(decoded, oid)

    def test_octet_string_and_null_codec(self):
        text = "Enterprise-NMS-SNMP-Engine"
        encoded = Asn1Codec.encode_octet_string(text)
        tag, val_bytes, _ = Asn1Codec.decode_tlv(encoded)
        self.assertEqual(tag, Asn1Tag.OCTET_STRING)
        self.assertEqual(Asn1Codec.decode_value(tag, val_bytes), text)

        null_enc = Asn1Codec.encode_null()
        tag, val_bytes, _ = Asn1Codec.decode_tlv(null_enc)
        self.assertEqual(tag, Asn1Tag.NULL)
        self.assertIsNone(Asn1Codec.decode_value(tag, val_bytes))

    def test_varbind_and_pdu_serialization(self):
        vbs = [
            VarBind("1.3.6.1.2.1.1.1.0", "Cisco Catalyst 3850"),
            VarBind("1.3.6.1.2.1.1.3.0", 8640000, Asn1Tag.TIMETICKS),
            VarBind("1.3.6.1.2.1.2.2.1.10.1", 1000000, Asn1Tag.COUNTER32),
            VarBind("1.3.6.1.2.1.31.1.1.1.6.1", 5000000000, Asn1Tag.COUNTER64),
        ]
        pdu = Pdu(pdu_type=Asn1Tag.RESPONSE, request_id=42, varbinds=vbs)
        encoded = Asn1Codec.encode_pdu(pdu)

        dec_pdu, _ = Asn1Codec.decode_pdu(encoded)
        self.assertEqual(dec_pdu.pdu_type, Asn1Tag.RESPONSE)
        self.assertEqual(dec_pdu.request_id, 42)
        self.assertEqual(len(dec_pdu.varbinds), 4)
        self.assertEqual(dec_pdu.varbinds[0].value, "Cisco Catalyst 3850")
        self.assertEqual(dec_pdu.varbinds[1].value, 8640000)
        self.assertEqual(dec_pdu.varbinds[2].value, 1000000)
        self.assertEqual(dec_pdu.varbinds[3].value, 5000000000)


class TestSnmpV3CryptoAndUSM(unittest.TestCase):
    """Unit tests for SNMPv3 USM Cryptography, Key Localization, and Authentication."""

    def test_rfc3414_sha1_key_localization_test_vector(self):
        """Validates exact RFC 3414 Appendix A.1 test vector for SHA-1 key localization."""
        password = "maplesyrup"
        engine_id = bytes.fromhex("000000000000000000000002")
        master_key = UsmCrypto.password_to_key(password, "SHA1")
        localized_key = UsmCrypto.localize_key(master_key, engine_id, "SHA1")
        self.assertEqual(localized_key.hex(), "6695febc9288e36282235fc7151f128497b38f3f")

    def test_hmac_digest_truncation_lengths(self):
        msg = b"SNMPv3 Authenticated Message Digest Payload"
        key = b"12345678901234567890"

        # MD5: 12 bytes (96 bits)
        self.assertEqual(len(UsmCrypto.compute_hmac(msg, key, "MD5")), 12)
        # SHA1: 12 bytes (96 bits)
        self.assertEqual(len(UsmCrypto.compute_hmac(msg, key, "SHA1")), 12)
        # SHA224: 16 bytes (128 bits)
        self.assertEqual(len(UsmCrypto.compute_hmac(msg, key, "SHA224")), 16)
        # SHA256: 24 bytes (192 bits)
        self.assertEqual(len(UsmCrypto.compute_hmac(msg, key, "SHA256")), 24)

    def test_privacy_des_cbc_roundtrip(self):
        priv_key = os.urandom(16)
        payload = b"ScopedPDU Secret Hardware Configuration String"
        boots = 1
        etime = 100

        salt, ciphertext = UsmCrypto.encrypt_scoped_pdu(payload, priv_key, "DES", boots, etime)
        decrypted = UsmCrypto.decrypt_scoped_pdu(ciphertext, priv_key, "DES", boots, etime, salt)
        # DES CBC has padding; verify original string is intact prefix
        self.assertTrue(decrypted.startswith(payload))

    def test_privacy_aes_cfb_roundtrips(self):
        payload = b"ScopedPDU High-Security Cryptographic Secret VarBind Data"
        boots = 3
        etime = 950

        for algo, k_len in [("AES128", 16), ("AES192", 24), ("AES256", 32)]:
            priv_key = os.urandom(k_len)
            salt, ciphertext = UsmCrypto.encrypt_scoped_pdu(payload, priv_key, algo, boots, etime)
            decrypted = UsmCrypto.decrypt_scoped_pdu(ciphertext, priv_key, algo, boots, etime, salt)
            self.assertEqual(decrypted, payload)

    def test_snmpv3_message_roundtrip_all_security_levels(self):
        engine_id = b"test_engine_id_99"

        # 1. noAuthNoPriv
        creds_noauth = SnmpV3Credentials(username="viewer")
        pdu = Pdu(pdu_type=Asn1Tag.RESPONSE, request_id=101, varbinds=[VarBind("1.3.6.1.2.1.1.1.0", "Generic Router")])
        raw = SnmpMessageCodec.encode_v3_message(101, pdu, creds_noauth, engine_id, 1, 10)
        msg_id, dec_pdu, r_eng, _, _ = SnmpMessageCodec.decode_v3_message(raw, creds_noauth)
        self.assertEqual(msg_id, 101)
        self.assertEqual(dec_pdu.varbinds[0].value, "Generic Router")

        # 2. authNoPriv (SHA256)
        creds_auth = SnmpV3Credentials(username="operator", auth_protocol="SHA256", auth_password="AuthPassword123")
        raw = SnmpMessageCodec.encode_v3_message(102, pdu, creds_auth, engine_id, 1, 20)
        msg_id, dec_pdu, r_eng, _, _ = SnmpMessageCodec.decode_v3_message(raw, creds_auth)
        self.assertEqual(msg_id, 102)
        self.assertEqual(dec_pdu.varbinds[0].value, "Generic Router")

        # 3. authPriv (SHA1 + AES128)
        creds_priv = SnmpV3Credentials(
            username="admin",
            auth_protocol="SHA1",
            auth_password="AuthPassword123",
            priv_protocol="AES128",
            priv_password="PrivPassword123",
        )
        raw = SnmpMessageCodec.encode_v3_message(103, pdu, creds_priv, engine_id, 1, 30)
        msg_id, dec_pdu, r_eng, _, _ = SnmpMessageCodec.decode_v3_message(raw, creds_priv)
        self.assertEqual(msg_id, 103)
        self.assertEqual(dec_pdu.varbinds[0].value, "Generic Router")

    def test_snmpv3_auth_with_zeroed_engine_id_placeholder_collision_avoidance(self):
        """Verifies HMAC placeholder replacement does not collide with zeroed octets in RFC 3411 IPv6 EngineID."""
        # RFC 3411 Format 2 (IPv6 address containing >= 12 consecutive zero octets)
        engine_id = bytes.fromhex("8000000902fe800000000000000000000000000001")
        creds = SnmpV3Credentials("admin", auth_protocol="SHA1", auth_password="password123", engine_id=engine_id)
        pdu = Pdu(pdu_type=Asn1Tag.GET_REQUEST, request_id=201, varbinds=[VarBind("1.3.6.1.2.1.1.1.0", None)])
        raw = SnmpMessageCodec.encode_v3_message(201, pdu, creds, engine_id, 1, 100)
        msg_id, dec_pdu, r_eng, boots, etime = SnmpMessageCodec.decode_v3_message(raw, creds)
        self.assertEqual(msg_id, 201)
        self.assertEqual(r_eng, engine_id)
        self.assertEqual(boots, 1)
        self.assertEqual(etime, 100)

    def test_engine_cache_time_window_verification(self):
        """Validates EngineCache.is_in_time_window logic according to RFC 3414."""
        cache = EngineCache()
        # Not cached -> returns True
        self.assertTrue(cache.is_in_time_window("192.168.1.1", 161, 1, 100))

        # Cache initial state
        cache.update("192.168.1.1", 161, b"eng1", boots=1, engine_time=1000)

        # Within 150s window -> True
        self.assertTrue(cache.is_in_time_window("192.168.1.1", 161, 1, 1000))
        self.assertTrue(cache.is_in_time_window("192.168.1.1", 161, 1, 1149))
        self.assertTrue(cache.is_in_time_window("192.168.1.1", 161, 1, 851))

        # Outside 150s window -> False
        self.assertFalse(cache.is_in_time_window("192.168.1.1", 161, 1, 100))
        self.assertFalse(cache.is_in_time_window("192.168.1.1", 161, 1, 1200))

        # Mismatched boots -> False
        self.assertFalse(cache.is_in_time_window("192.168.1.1", 161, 2, 1000))

    def test_snmpv3_engine_id_mismatch_validation(self):
        """Validates SnmpMessageCodec.decode_v3_message rejects packets with mismatched engineID."""
        creds = SnmpV3Credentials("admin", auth_protocol="SHA1", auth_password="password123", engine_id=b"expected_engine")
        pdu = Pdu(pdu_type=Asn1Tag.GET_REQUEST, request_id=301, varbinds=[VarBind("1.3.6.1.2.1.1.1.0", None)])
        raw = SnmpMessageCodec.encode_v3_message(301, pdu, creds, b"spoofed_attacker_engine", 1, 100)
        with self.assertRaises(ValueError) as ctx:
            SnmpMessageCodec.decode_v3_message(raw, creds)
        self.assertIn("SNMPv3 EngineID mismatch", str(ctx.exception))


class TestMultiVendorMibAdapters(unittest.TestCase):
    """Unit tests for the 6 vendor MIB catalogs and health metric normalization."""

    def test_cisco_adapter(self):
        adapter = CiscoAdapter()
        varbinds = {
            "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1": 42,           # cpu 5min
            "1.3.6.1.4.1.9.9.221.1.1.1.1.7.1.1": 350000000,  # used mem
            "1.3.6.1.4.1.9.9.221.1.1.1.1.8.1.1": 650000000,  # free mem
            "1.3.6.1.4.1.9.9.13.1.3.1.3.1": 38,              # temp
        }
        metrics = adapter.parse_health_metrics(varbinds)
        self.assertEqual(metrics.cpu_percent, 42.0)
        self.assertEqual(metrics.memory_percent, 35.0)
        self.assertEqual(metrics.temperature_c, 38.0)

    def test_mikrotik_adapter(self):
        adapter = MikrotikAdapter()
        # Per-core average load and deci-Celsius temperature conversion
        varbinds = {
            "1.3.6.1.2.1.25.3.3.1.2.1": 20,
            "1.3.6.1.2.1.25.3.3.1.2.2": 30,
            "1.3.6.1.2.1.25.2.3.1.5.1": 2048,
            "1.3.6.1.2.1.25.2.3.1.6.1": 1024,
            "1.3.6.1.4.1.14988.1.1.3.10.0": 450,  # 45.0 °C
            "1.3.6.1.4.1.14988.1.1.3.8.0": 240,   # 24.0 V
        }
        metrics = adapter.parse_health_metrics(varbinds)
        self.assertEqual(metrics.cpu_percent, 25.0)
        self.assertEqual(metrics.memory_percent, 50.0)
        self.assertEqual(metrics.temperature_c, 45.0)
        self.assertEqual(metrics.extra_metrics.get("voltage_v"), 24.0)

    def test_huawei_adapter(self):
        adapter = HuaweiAdapter()
        varbinds = {
            "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5.1": 18,
            "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7.1": 62,
            "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11.1": 36,
        }
        metrics = adapter.parse_health_metrics(varbinds)
        self.assertEqual(metrics.cpu_percent, 18.0)
        self.assertEqual(metrics.memory_percent, 62.0)
        self.assertEqual(metrics.temperature_c, 36.0)

    def test_juniper_adapter(self):
        adapter = JuniperAdapter()
        varbinds = {
            "1.3.6.1.4.1.2636.3.1.13.1.8.9.1": 12,
            "1.3.6.1.4.1.2636.3.1.13.1.11.9.1": 48,
            "1.3.6.1.4.1.2636.3.1.13.1.12.9.1": 32,
        }
        metrics = adapter.parse_health_metrics(varbinds)
        self.assertEqual(metrics.cpu_percent, 12.0)
        self.assertEqual(metrics.memory_percent, 48.0)
        self.assertEqual(metrics.temperature_c, 32.0)

    def test_fortinet_adapter(self):
        adapter = FortinetAdapter()
        varbinds = {
            "1.3.6.1.4.1.12356.101.4.1.3.0": 24,
            "1.3.6.1.4.1.12356.101.4.1.4.0": 55,
            "1.3.6.1.4.1.12356.101.4.1.8.0": 45000,
            "1.3.6.1.4.1.12356.101.4.1.11.0": 120,
        }
        metrics = adapter.parse_health_metrics(varbinds)
        self.assertEqual(metrics.cpu_percent, 24.0)
        self.assertEqual(metrics.memory_percent, 55.0)
        self.assertEqual(metrics.extra_metrics.get("sessions"), 45000)
        self.assertEqual(metrics.extra_metrics.get("session_rate"), 120)

    def test_hp_aruba_adapter(self):
        adapter = HpArubaAdapter()
        # Comware
        varbinds_comware = {
            "1.3.6.1.4.1.25506.2.6.1.1.1.1.6.1": 15,
            "1.3.6.1.4.1.25506.2.6.1.1.1.1.8.1": 40,
            "1.3.6.1.4.1.25506.2.6.1.1.1.1.12.1": 29,
        }
        m1 = adapter.parse_health_metrics(varbinds_comware)
        self.assertEqual(m1.cpu_percent, 15.0)
        self.assertEqual(m1.memory_percent, 40.0)
        self.assertEqual(m1.temperature_c, 29.0)

        # ProCurve fallback
        varbinds_procurve = {
            "1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0": 28,
            "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5.1": 1000,
            "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7.1": 350,
        }
        m2 = adapter.parse_health_metrics(varbinds_procurve)
        self.assertEqual(m2.cpu_percent, 28.0)
        self.assertEqual(m2.memory_percent, 35.0)


class TestSnmpAutoDiscoveryAndFingerprinting(unittest.TestCase):
    """Unit tests for CIDR scanning, IP parsing, vendor fingerprinting, and waterfall auth."""

    def test_parse_targets_cidr_and_ranges(self):
        # /24 returns 254 hosts
        hosts_24 = parse_targets("192.168.10.0/24")
        self.assertEqual(len(hosts_24), 254)
        self.assertNotIn("192.168.10.0", hosts_24)
        self.assertNotIn("192.168.10.255", hosts_24)
        self.assertIn("192.168.10.1", hosts_24)
        self.assertIn("192.168.10.254", hosts_24)

        # /32 single host
        host_32 = parse_targets("10.0.0.5/32")
        self.assertEqual(host_32, ["10.0.0.5"])

        # /31 point-to-point link
        hosts_31 = parse_targets("10.0.0.0/31")
        self.assertEqual(hosts_31, ["10.0.0.0", "10.0.0.1"])

        # Range notation
        hosts_range = parse_targets("172.16.0.1-172.16.0.10")
        self.assertEqual(len(hosts_range), 10)
        self.assertEqual(hosts_range[0], "172.16.0.1")
        self.assertEqual(hosts_range[-1], "172.16.0.10")

        # Exclusions: loopback & multicast
        exclusions = parse_targets("127.0.0.1, 224.0.0.1, 10.1.1.1")
        self.assertEqual(exclusions, ["10.1.1.1"])

    def test_vendor_fingerprinting_smi_and_sysdescr(self):
        # SMI Enterprise OID Prefixes
        self.assertEqual(fingerprint_vendor("1.3.6.1.4.1.9.1.283"), "Cisco")
        self.assertEqual(fingerprint_vendor("1.3.6.1.4.1.14988.1"), "MikroTik")
        self.assertEqual(fingerprint_vendor("1.3.6.1.4.1.2011.2.239"), "Huawei")
        self.assertEqual(fingerprint_vendor("1.3.6.1.4.1.2636.1.1.1.2.31"), "Juniper")
        self.assertEqual(fingerprint_vendor("1.3.6.1.4.1.12356.101.1"), "Fortinet")
        self.assertEqual(fingerprint_vendor("1.3.6.1.4.1.25506.2.6"), "HP_Aruba")
        self.assertEqual(fingerprint_vendor("1.3.6.1.4.1.11.2.14"), "HP_Aruba")

        # Fallback to sysDescr regex
        self.assertEqual(
            fingerprint_vendor("1.3.6.1.4.1.8072.3.2.10", "Cisco IOS-XE Software, Catalyst L3 Switch"),
            "Cisco",
        )
        self.assertEqual(
            fingerprint_vendor("1.3.6.1.2.1.1.2.0", "RouterOS v7.14 on Cloud Core Router"),
            "MikroTik",
        )
        self.assertEqual(
            fingerprint_vendor("", "Huawei Versatile Routing Platform VRP software"),
            "Huawei",
        )
        self.assertEqual(
            fingerprint_vendor("", "Juniper Networks JunOS 21.4R3"),
            "Juniper",
        )
        self.assertEqual(
            fingerprint_vendor("", "FortiGate-60F v7.2.4 build1396"),
            "Fortinet",
        )
        self.assertEqual(
            fingerprint_vendor("", "ArubaOS-Switch ProCurve J9773A 2530-24G"),
            "HP_Aruba",
        )

    def test_mac_address_formatter(self):
        raw_bytes = bytes([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])
        self.assertEqual(format_mac_address(raw_bytes), "00:1A:2B:3C:4D:5E")
        self.assertEqual(format_mac_address("001a2b3c4d5e"), "00:1A:2B:3C:4D:5E")
        self.assertEqual(format_mac_address("00-1A-2B-3C-4D-5E"), "00:1A:2B:3C:4D:5E")


class TestTelemetryMathEngine(unittest.TestCase):
    """Unit tests for telemetry delta math, 32/64-bit wraps, and reboot spike suppression."""

    def test_monotonic_counter_delta(self):
        delta, wrapped, rebooted = calculate_counter_delta(15000, 10000)
        self.assertEqual(delta, 5000)
        self.assertFalse(wrapped)
        self.assertFalse(rebooted)

    def test_32bit_counter_rollover_wrap(self):
        # prev near 2^32, curr wrapped to 10,000,000
        prev = 4_290_000_000
        curr = 10_000_000
        delta, wrapped, rebooted = calculate_counter_delta(curr, prev, is_64bit=False)
        expected = (WRAP_32 - prev) + curr  # 4,967,296 + 10,000,000 = 14,967,296
        self.assertEqual(delta, expected)
        self.assertTrue(wrapped)
        self.assertFalse(rebooted)

    def test_64bit_high_capacity_counter_rollover_wrap(self):
        prev = WRAP_64 - 5000
        curr = 1500
        delta, wrapped, rebooted = calculate_counter_delta(curr, prev, is_64bit=True)
        self.assertEqual(delta, 6500)
        self.assertTrue(wrapped)
        self.assertFalse(rebooted)

    def test_device_reboot_suppression(self):
        # Agent rebooted: sysUpTime drops from 500,000 to 50
        prev_octets = 4_000_000_000
        curr_octets = 5_000
        delta, wrapped, rebooted = calculate_counter_delta(
            curr=curr_octets,
            prev=prev_octets,
            is_64bit=False,
            sys_uptime_curr=50,
            sys_uptime_prev=500_000,
        )
        self.assertEqual(delta, 0)
        self.assertFalse(wrapped)
        self.assertTrue(rebooted)

    def test_telemetry_engine_rate_and_utilization_calc(self):
        engine = TelemetryEngine()
        dev_id = 1
        if_idx = 1

        # First sample establishes baseline
        s1 = InterfaceSample(
            timestamp=100.0,
            sys_uptime=10000,
            in_octets=10_000_000,
            out_octets=20_000_000,
            in_pkts=50000,
            out_pkts=80000,
            if_speed=1_000_000_000,  # 1 Gbps
        )
        rates1 = engine.process_interface_sample(dev_id, if_idx, s1)
        self.assertIsNone(rates1)

        # Second sample after 10 seconds:
        # Ingress: +12,500,000 octets -> 12,500,000 * 8 / 10 = 10,000,000 bps (10 Mbps)
        # Egress: +25,000,000 octets -> 25,000,000 * 8 / 10 = 20,000,000 bps (20 Mbps)
        # Packets: +10,000 in -> 1,000 pps
        s2 = InterfaceSample(
            timestamp=110.0,
            sys_uptime=11000,
            in_octets=22_500_000,
            out_octets=45_000_000,
            in_pkts=60000,
            out_pkts=100000,
            if_speed=1_000_000_000,
        )
        rates2 = engine.process_interface_sample(dev_id, if_idx, s2)
        self.assertIsNotNone(rates2)
        self.assertEqual(rates2.in_bps, 10_000_000.0)
        self.assertEqual(rates2.out_bps, 20_000_000.0)
        self.assertEqual(rates2.in_pps, 1000.0)
        self.assertEqual(rates2.out_pps, 2000.0)
        self.assertEqual(rates2.in_utilization_pct, 1.0)
        self.assertEqual(rates2.out_utilization_pct, 2.0)
        self.assertFalse(rates2.rebooted)


class TestStatefulAlarmEngine(unittest.TestCase):
    """Unit tests for stateful alarm engine, 10% deadband hysteresis, and flap damping."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_alarms.db")
        init_db(self.db_path)
        setup_conn = get_db_connection(self.db_path)
        setup_conn.execute("INSERT INTO snmp_devices (id, ip, status) VALUES (1, '10.10.10.1', 'ONLINE')")
        setup_conn.execute("INSERT INTO snmp_interfaces (device_id, if_index, if_name) VALUES (1, 1, 'GigabitEthernet0/1')")
        setup_conn.commit()
        setup_conn.close()
        self.conn = get_db_connection(self.db_path)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cpu_threshold_hysteresis_deadband(self):
        engine = AlarmEngine()
        events = []
        # warn=80%, crit=90%, deadband=10% (clear warn < 70%, demote crit < 81%)

        # 1. 92% -> Triggers CRITICAL
        engine.evaluate_metric_threshold(self.conn, 1, "CPU", 92.0, 80.0, 90.0, 10.0, events.append)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[-1]["severity"], "CRITICAL")
        self.assertFalse(events[-1]["is_resolved"])

        # 2. Drop to 88% -> Stays CRITICAL (88 >= 81)
        engine.evaluate_metric_threshold(self.conn, 1, "CPU", 88.0, 80.0, 90.0, 10.0, events.append)
        self.assertEqual(len(events), 1)

        # 3. Drop to 75% -> Below 81%, demotes to WARNING
        engine.evaluate_metric_threshold(self.conn, 1, "CPU", 75.0, 80.0, 90.0, 10.0, events.append)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[-1]["severity"], "WARNING")

        # 4. Drop to 65% -> Below 70%, resolves alarm
        engine.evaluate_metric_threshold(self.conn, 1, "CPU", 65.0, 80.0, 90.0, 10.0, events.append)
        self.assertEqual(len(events), 3)
        self.assertTrue(events[-1]["is_resolved"])

    def test_link_down_and_admin_down_suppression(self):
        engine = AlarmEngine()
        events = []

        # 1. Port disabled administratively -> suppressed
        engine.evaluate_link_status(self.conn, 1, 1, "Gi0/1", oper_status=2, admin_status=2, on_alarm_change=events.append)
        self.assertEqual(len(events), 0)

        # 2. Port admin UP, oper DOWN -> Triggers LINK_DOWN CRITICAL
        engine.evaluate_link_status(self.conn, 1, 1, "Gi0/1", oper_status=2, admin_status=1, on_alarm_change=events.append)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[-1]["alarm_type"], "LINK_DOWN")
        self.assertEqual(events[-1]["severity"], "CRITICAL")

        # 3. Port oper UP -> Resolves LINK_DOWN
        engine.evaluate_link_status(self.conn, 1, 1, "Gi0/1", oper_status=1, admin_status=1, on_alarm_change=events.append)
        self.assertEqual(len(events), 2)
        self.assertTrue(events[-1]["is_resolved"])

    def test_interface_flap_damping_suppression(self):
        # 4 transitions in 300s -> DAMPED state, PORT_FLAPPING WARNING
        engine = AlarmEngine(flap_window_sec=300.0, flap_max_transitions=4, flap_damp_duration_sec=300.0)
        events = []

        # Simulate 4 rapid transitions: 1 -> 2 -> 1 -> 2 -> 1
        engine.evaluate_link_status(self.conn, 1, 1, "Gi0/1", oper_status=1, admin_status=1, on_alarm_change=events.append)
        engine.evaluate_link_status(self.conn, 1, 1, "Gi0/1", oper_status=2, admin_status=1, on_alarm_change=events.append)
        engine.evaluate_link_status(self.conn, 1, 1, "Gi0/1", oper_status=1, admin_status=1, on_alarm_change=events.append)
        engine.evaluate_link_status(self.conn, 1, 1, "Gi0/1", oper_status=2, admin_status=1, on_alarm_change=events.append)
        engine.evaluate_link_status(self.conn, 1, 1, "Gi0/1", oper_status=1, admin_status=1, on_alarm_change=events.append)

        # Flapping detected!
        flapping_events = [e for e in events if e["alarm_type"] == "PORT_FLAPPING"]
        self.assertEqual(len(flapping_events), 1)
        self.assertEqual(flapping_events[0]["severity"], "WARNING")


class TestWebhookDispatchers(unittest.TestCase):
    """Unit tests for Telegram Bot Markdown and Slack Block Kit payload formats."""

    def test_telegram_dispatcher_message_format(self):
        tg = TelegramDispatcher("test_token_123", "test_chat_456")
        msg = tg.format_message(
            severity="CRITICAL",
            alarm_type="LINK_DOWN",
            device_name="Core-Switch-01",
            device_ip="192.168.1.1",
            if_name="TenGigabitEthernet1/1",
            message="Interface transitioned to down",
            is_resolved=False,
        )
        self.assertIn("🚨", msg)
        self.assertIn("*[CRITICAL] ALARM TRIGGERED*", msg)
        self.assertIn("Core-Switch-01", msg)
        self.assertIn("TenGigabitEthernet1/1", msg)

        res_msg = tg.format_message(
            severity="CRITICAL",
            alarm_type="LINK_DOWN",
            device_name="Core-Switch-01",
            device_ip="192.168.1.1",
            if_name="TenGigabitEthernet1/1",
            message="Interface restored to operational",
            is_resolved=True,
        )
        self.assertIn("✅", res_msg)
        self.assertIn("*[RESOLVED] ALARM CLEARED*", res_msg)

    def test_slack_dispatcher_payload_format(self):
        slack = SlackDispatcher("https://hooks.slack.com/services/T00/B00/X00")
        payload = slack.format_payload(
            severity="WARNING",
            alarm_type="HIGH_CPU",
            device_name="Border-Router-01",
            device_ip="10.0.0.1",
            if_name=None,
            message="CPU utilization at 84.5%",
            is_resolved=False,
        )
        self.assertIn("attachments", payload)
        self.assertEqual(payload["attachments"][0]["color"], "#FFA000")
        blocks = payload["attachments"][0]["blocks"]
        self.assertEqual(blocks[0]["type"], "header")
        self.assertIn("WARNING: HIGH_CPU", blocks[0]["text"]["text"])


class TestSnmpUdpLocalhostE2E(unittest.IsolatedAsyncioTestCase):
    """Genuine End-to-End integration tests over real UDP loopback sockets."""

    async def asyncSetUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_snmp_e2e.db")
        init_db(self.db_path)

        # Standard MIB-II mock data
        self.mock_mib = {
            "1.3.6.1.2.1.1.1.0": "Cisco IOS-XE Software, Version 17.06.01",
            "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.9.1.516",
            "1.3.6.1.2.1.1.3.0": 1234567,
            "1.3.6.1.2.1.1.5.0": "Core-Switch-A",
            # Interfaces
            "1.3.6.1.2.1.2.2.1.1.1": 1,
            "1.3.6.1.2.1.2.2.1.2.1": "GigabitEthernet0/1",
            "1.3.6.1.2.1.2.2.1.3.1": 6,
            "1.3.6.1.2.1.2.2.1.5.1": 1000000000,
            "1.3.6.1.2.1.2.2.1.7.1": 1,
            "1.3.6.1.2.1.2.2.1.8.1": 1,
            "1.3.6.1.2.1.2.2.1.10.1": 5000000,
            "1.3.6.1.2.1.2.2.1.16.1": 8000000,
            # HC table
            "1.3.6.1.2.1.31.1.1.1.1.1": "Gi0/1",
            "1.3.6.1.2.1.31.1.1.1.6.1": 5000000,
            "1.3.6.1.2.1.31.1.1.1.10.1": 8000000,
            "1.3.6.1.2.1.31.1.1.1.15.1": 1000,
            # Cisco health
            "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1": 25,
            "1.3.6.1.4.1.9.9.221.1.1.1.1.7.1.1": 400000000,
            "1.3.6.1.4.1.9.9.221.1.1.1.1.8.1.1": 600000000,
            "1.3.6.1.4.1.9.9.13.1.3.1.3.1": 35,
        }

        # Start mock SNMPv2c agent on ephemeral port
        loop = asyncio.get_running_loop()
        self.transport_v2c, self.agent_v2c = await loop.create_datagram_endpoint(
            lambda: MockSnmpAgentProtocol(self.mock_mib),
            local_addr=("127.0.0.1", 0),
        )
        self.port_v2c = self.transport_v2c.get_extra_info("sockname")[1]

        # Start mock SNMPv3 agent on ephemeral port
        self.v3_creds = SnmpV3Credentials(
            username="testadmin",
            auth_protocol="SHA1",
            auth_password="authpass12345",
            priv_protocol="AES128",
            priv_password="privpass12345",
        )
        self.transport_v3, self.agent_v3 = await loop.create_datagram_endpoint(
            lambda: MockSnmpAgentProtocol(self.mock_mib, v3_creds=self.v3_creds),
            local_addr=("127.0.0.1", 0),
        )
        self.port_v3 = self.transport_v3.get_extra_info("sockname")[1]

        self.client = SnmpClient()

    async def asyncTearDown(self):
        await self.client.close()
        self.transport_v2c.close()
        self.transport_v3.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    async def test_snmpv2c_get_and_walk_e2e(self):
        # SNMPv2c Get
        res = await self.client.get(
            target="127.0.0.1",
            port=self.port_v2c,
            oids=["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"],
            community="public",
        )
        self.assertFalse(res.is_error)
        self.assertEqual(res.get("1.3.6.1.2.1.1.1.0"), "Cisco IOS-XE Software, Version 17.06.01")
        self.assertEqual(res["1.3.6.1.2.1.1.5.0"], "Core-Switch-A")

        # SNMPv2c Walk
        walk_rows = await self.client.walk(
            target="127.0.0.1",
            port=self.port_v2c,
            root_oid="1.3.6.1.2.1.1",
            community="public",
        )
        self.assertGreaterEqual(len(walk_rows), 4)

    async def test_snmpv3_discovery_and_authpriv_e2e(self):
        # Dynamic EngineID Discovery
        eng_id = await self.client.discover_engine_id("127.0.0.1", port=self.port_v3)
        self.assertEqual(eng_id, b"mock_engine_01")

        # Authenticated & Encrypted Get
        res = await self.client.get(
            target="127.0.0.1",
            port=self.port_v3,
            version="v3",
            v3_creds=self.v3_creds,
            oids=["1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1"],
        )
        self.assertFalse(res.is_error)
        self.assertEqual(res.get("1.3.6.1.2.1.1.1.0"), "Cisco IOS-XE Software, Version 17.06.01")
        self.assertEqual(res.get("1.3.6.1.4.1.9.9.109.1.1.1.1.8.1"), 25)

    async def test_device_discovery_and_persistence_e2e(self):
        config = DiscoveryScanConfig(
            targets=["127.0.0.1/32"],
            port=self.port_v2c,
            v2c_communities=["public"],
            db_path=self.db_path,
            allow_loopback=True,
        )
        result = await scan_network(config, self.client)
        self.assertEqual(result.scanned_ips, 1)
        self.assertEqual(len(result.discovered_devices), 1)

        dev = result.discovered_devices[0]
        self.assertEqual(dev.vendor, "Cisco")
        self.assertEqual(dev.sys_name, "Core-Switch-A")
        self.assertGreaterEqual(len(dev.interfaces), 1)

        # Verify DB persistence
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM snmp_devices WHERE ip = '127.0.0.1'")
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["vendor"], "Cisco")
        self.assertEqual(row["status"], "ONLINE")
        conn.close()

    async def test_poller_daemon_single_cycle_e2e(self):
        # Populate DB with mock device
        conn = get_db_connection(self.db_path)
        with conn:
            conn.execute(
                """
                INSERT INTO snmp_devices (id, ip, port, version, community, vendor, sys_name, status)
                VALUES (1, '127.0.0.1', ?, 'v2c', 'public', 'Cisco', 'Core-Switch-A', 'ONLINE')
                """,
                (self.port_v2c,),
            )
            conn.execute(
                """
                INSERT INTO snmp_interfaces (device_id, if_index, if_name, if_speed)
                VALUES (1, 1, 'Gi0/1', 1000000000)
                """
            )
        conn.close()

        daemon = SnmpPollerDaemon(db_path=self.db_path, client=self.client)
        # Execute single cycle
        await daemon.poll_cycle()
        daemon._update_heartbeat(status="RUNNING")

        # Verify daemon_status table
        conn = get_db_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM daemon_status WHERE daemon_name = 'snmp_daemon'")
        d_row = cursor.fetchone()
        self.assertIsNotNone(d_row)
        self.assertEqual(d_row["status"], "RUNNING")

        # Verify snmp_health table
        cursor.execute("SELECT * FROM snmp_health WHERE device_id = 1")
        h_row = cursor.fetchone()
        self.assertIsNotNone(h_row)
        self.assertEqual(h_row["cpu_percent"], 25.0)
        self.assertEqual(h_row["memory_percent"], 40.0)
        self.assertEqual(h_row["temperature_c"], 35.0)
        conn.close()


if __name__ == "__main__":
    unittest.main()
