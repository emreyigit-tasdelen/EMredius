# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Milestone M2 Challenger Adversarial Stress Test Suite.

Adversarial tests covering:
1. ASN.1 BER codec: corrupted byte streams, truncated lengths, invalid tags, boundary values (0, 2^31-1, 2^32-1, 2^63-1, 2^64-1).
2. SNMPv3 USM: verification and rejection of wrong auth keys, wrong privacy keys, corrupted digests,
   replay attacks with out-of-window timestamps (>150s), and unknown engineIDs.
3. Counter wrap math: exact 32-bit wrap boundary (4294967295 -> 100), 64-bit HC wrap boundary (18446744073709551615 -> 500),
   and device reboot rollback (curr < prev and sysUpTime reset).
"""

from __future__ import annotations

import asyncio
import os
import random
import unittest

from nms.snmp.engine import (
    Asn1Codec,
    Asn1Tag,
    EngineCache,
    Pdu,
    SnmpEngine,
    SnmpMessageCodec,
    SnmpV3Credentials,
    UsmCrypto,
    VarBind,
)
from nms.snmp.telemetry import (
    WRAP_32,
    WRAP_64,
    InterfaceSample,
    TelemetryEngine,
    calculate_counter_delta,
)


class TestAsn1CodecAdversarial(unittest.TestCase):
    """Adversarial stress testing of the pure-Python ASN.1 BER Codec."""

    def test_asn1_boundary_values_signed_integers(self):
        """Test exact boundary values for signed ASN.1 integers: 0, 2^31-1, -2^31, 2^63-1, -2^63."""
        boundaries = [
            0,
            1,
            -1,
            127,
            128,
            255,
            256,
            (1 << 31) - 1,   # 2147483647
            -(1 << 31),       # -2147483648
            (1 << 32) - 1,   # 4294967295
            (1 << 63) - 1,   # 9223372036854775807
            -(1 << 63),      # -9223372036854775808
        ]
        for val in boundaries:
            encoded = Asn1Codec.encode_integer(val)
            tag, val_bytes, next_off = Asn1Codec.decode_tlv(encoded)
            self.assertEqual(tag, Asn1Tag.INTEGER)
            self.assertEqual(next_off, len(encoded))
            decoded = Asn1Codec.decode_value(tag, val_bytes)
            self.assertEqual(decoded, val, f"Integer boundary roundtrip failed for {val}")

    def test_asn1_boundary_values_unsigned_counters(self):
        """Test exact boundary values for unsigned SNMP types: Counter32 (2^32-1) and Counter64 (2^64-1)."""
        # 32-bit boundaries
        c32_boundaries = [0, 1, 2147483647, 4294967295]
        for val in c32_boundaries:
            for tag in (Asn1Tag.COUNTER32, Asn1Tag.GAUGE32, Asn1Tag.TIMETICKS):
                encoded = Asn1Codec.encode_unsigned(val, tag)
                d_tag, val_bytes, next_off = Asn1Codec.decode_tlv(encoded)
                self.assertEqual(d_tag, tag)
                self.assertEqual(next_off, len(encoded))
                decoded = Asn1Codec.decode_value(d_tag, val_bytes)
                self.assertEqual(decoded, val, f"Unsigned 32-bit failed for tag {hex(tag)}, val {val}")

        # 64-bit Counter64 boundaries
        c64_boundaries = [0, 1, 2147483647, 4294967295, 9223372036854775807, 18446744073709551615]
        for val in c64_boundaries:
            encoded = Asn1Codec.encode_unsigned(val, Asn1Tag.COUNTER64)
            d_tag, val_bytes, next_off = Asn1Codec.decode_tlv(encoded)
            self.assertEqual(d_tag, Asn1Tag.COUNTER64)
            self.assertEqual(next_off, len(encoded))
            decoded = Asn1Codec.decode_value(d_tag, val_bytes)
            self.assertEqual(decoded, val, f"Counter64 boundary failed for {val}")

    def test_asn1_truncated_lengths(self):
        """Adversarial testing: truncated lengths must raise ValueError and not read out-of-bounds."""
        truncated_cases = [
            b"\x02\x05\x01\x02",                 # INTEGER with claimed length 5, but only 2 bytes present
            b"\x04\x20\xaa\xbb\xcc",             # OCTET STRING claiming 32 bytes, only 3 bytes present
            b"\x30\x10\x02\x01\x01",             # SEQUENCE claiming 16 bytes, only 3 bytes present
            b"\x06\x08\x2b\x06\x01\x02",         # OID claiming 8 bytes, only 4 bytes present
            b"\x02\x82\x00\x50\x01",             # Multi-byte length (80 bytes), only 1 byte payload
            b"\x02\x84\x7f\xff\xff\xff\x01",     # Massive length 2GB, only 1 byte payload
        ]
        for raw in truncated_cases:
            with self.assertRaises(ValueError):
                Asn1Codec.decode_tlv(raw)

    def test_asn1_corrupted_and_empty_streams(self):
        """Adversarial testing: empty or malformed streams must not hang or cause unhandled fatal crashes."""
        # Empty stream
        with self.assertRaises(ValueError):
            Asn1Codec.decode_tlv(b"")

        # 1-byte stream (tag without length byte)
        with self.assertRaises((ValueError, IndexError)):
            Asn1Codec.decode_tlv(b"\x02")

        # Non-sequence payload passed to decode_varbind
        with self.assertRaises(ValueError):
            Asn1Codec.decode_varbind(b"\x02\x01\x00")  # INTEGER tag instead of SEQUENCE 0x30

        # Corrupted PDU sequence
        with self.assertRaises((ValueError, IndexError)):
            Asn1Codec.decode_pdu(b"\x02\x01\x00")

    def test_asn1_fuzzing_random_corrupted_payloads(self):
        """Fuzz testing ASN.1 codec with 200 randomized corrupted byte payloads."""
        rng = random.Random(42)
        for _ in range(200):
            length = rng.randint(0, 128)
            fuzz_bytes = rng.randbytes(length)
            try:
                tag, val_bytes, next_off = Asn1Codec.decode_tlv(fuzz_bytes)
                Asn1Codec.decode_value(tag, val_bytes)
            except (ValueError, IndexError):
                # Expected safe rejection on malformed inputs
                pass


class TestSnmpUsmSecurityAdversarial(unittest.TestCase):
    """Adversarial stress testing of SNMPv3 USM security model."""

    def setUp(self):
        self.engine_id = b"secure_engine_alpha"
        self.pdu = Pdu(
            pdu_type=Asn1Tag.RESPONSE,
            request_id=4001,
            varbinds=[VarBind("1.3.6.1.2.1.1.1.0", "Core Router Switch")],
        )

    def test_usm_rejection_wrong_auth_key(self):
        """Adversarial testing: wrong auth passwords must be rejected for all supported HMAC algorithms."""
        auth_protocols = ["MD5", "SHA1", "SHA224", "SHA256"]
        for proto in auth_protocols:
            correct_creds = SnmpV3Credentials(
                username="audit_admin",
                auth_protocol=proto,
                auth_password="CorrectAuthPassword!2026",
            )
            wrong_creds = SnmpV3Credentials(
                username="audit_admin",
                auth_protocol=proto,
                auth_password="WrongAuthPassword!Attack",
            )
            raw_msg = SnmpMessageCodec.encode_v3_message(
                msg_id=4001,
                pdu=self.pdu,
                creds=correct_creds,
                engine_id=self.engine_id,
                engine_boots=1,
                engine_time=100,
            )
            with self.assertRaises(ValueError) as ctx:
                SnmpMessageCodec.decode_v3_message(raw_msg, wrong_creds)
            self.assertIn("invalid HMAC digest", str(ctx.exception))

    def test_usm_rejection_corrupted_digest_and_tampered_payload(self):
        """Adversarial testing: single-bit tampering in payload or HMAC must cause digest verification failure."""
        creds = SnmpV3Credentials(
            username="sec_ops",
            auth_protocol="SHA256",
            auth_password="HardenedPassword#99",
        )
        raw_msg = bytearray(
            SnmpMessageCodec.encode_v3_message(
                msg_id=4002,
                pdu=self.pdu,
                creds=creds,
                engine_id=self.engine_id,
                engine_boots=1,
                engine_time=200,
            )
        )

        # Tamper last byte (in ScopedPDU)
        raw_msg[-1] ^= 0x01
        with self.assertRaises(ValueError) as ctx:
            SnmpMessageCodec.decode_v3_message(bytes(raw_msg), creds)
        self.assertIn("invalid HMAC digest", str(ctx.exception))

        # Tamper middle byte (inside header/flags)
        raw_msg = bytearray(
            SnmpMessageCodec.encode_v3_message(
                msg_id=4002,
                pdu=self.pdu,
                creds=creds,
                engine_id=self.engine_id,
                engine_boots=1,
                engine_time=200,
            )
        )
        raw_msg[15] ^= 0xFF
        with self.assertRaises(ValueError):
            SnmpMessageCodec.decode_v3_message(bytes(raw_msg), creds)

    def test_usm_rejection_wrong_privacy_key(self):
        """Adversarial testing: wrong privacy keys must fail decryption for DES and AES-128/192/256."""
        for priv_proto in ["DES", "AES128", "AES192", "AES256"]:
            correct_creds = SnmpV3Credentials(
                username="sec_admin",
                auth_protocol="SHA1",
                auth_password="AuthPasswordGood",
                priv_protocol=priv_proto,
                priv_password="PrivPasswordGood123",
            )
            wrong_creds = SnmpV3Credentials(
                username="sec_admin",
                auth_protocol="SHA1",
                auth_password="AuthPasswordGood",
                priv_protocol=priv_proto,
                priv_password="PrivPasswordWRONG999",
            )
            raw_msg = SnmpMessageCodec.encode_v3_message(
                msg_id=4003,
                pdu=self.pdu,
                creds=correct_creds,
                engine_id=self.engine_id,
                engine_boots=1,
                engine_time=150,
            )
            with self.assertRaises(Exception):
                # Decoding with wrong priv key must fail decryption (invalid plaintext ASN.1)
                SnmpMessageCodec.decode_v3_message(raw_msg, wrong_creds)


class MockAdversarialSnmpAgent(asyncio.DatagramProtocol):
    """Mock SNMP agent simulating adversarial attack scenarios (replay attacks and spoofed engine IDs)."""

    def __init__(self, mode: str, legit_engine: bytes = b"authoritative_engine_01"):
        self.mode = mode
        self.legit_engine = legit_engine
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        _, seq_bytes, _ = Asn1Codec.decode_tlv(data, 0)
        off = 0
        _, ver_bytes, off = Asn1Codec.decode_tlv(seq_bytes, off)
        _, header_bytes, off = Asn1Codec.decode_tlv(seq_bytes, off)
        _, msg_id_bytes, _ = Asn1Codec.decode_tlv(header_bytes, 0)
        msg_id = int.from_bytes(msg_id_bytes, "big", signed=True)

        _, sec_raw, _ = Asn1Codec.decode_tlv(seq_bytes, off)
        _, sec_bytes, _ = Asn1Codec.decode_tlv(sec_raw, 0)
        _, req_eng, _ = Asn1Codec.decode_tlv(sec_bytes, 0)

        creds = SnmpV3Credentials(username="admin", auth_protocol="SHA1", auth_password="AuthPassword123")

        if req_eng == b"":
            # RFC 3414 Discovery Probe -> Return authoritative EngineID, boots=1, time=1000
            rep = Pdu(pdu_type=Asn1Tag.REPORT, request_id=msg_id, varbinds=[VarBind("1.3.6.1.6.3.15.1.1.4.0", 1)])
            msg = SnmpMessageCodec.encode_v3_message(msg_id, rep, None, self.legit_engine, 1, 1000)
            self.transport.sendto(msg, addr)
            return

        # Normal query response
        resp_pdu = Pdu(pdu_type=Asn1Tag.RESPONSE, request_id=msg_id, varbinds=[VarBind("1.3.6.1.2.1.1.1.0", "Injected Attack Payload")])
        if self.mode == "replay_stale_time":
            # Replay attack: send response with time=100 (stale by 900s > 150s window)
            msg = SnmpMessageCodec.encode_v3_message(msg_id, resp_pdu, creds, self.legit_engine, 1, 100)
            self.transport.sendto(msg, addr)
        elif self.mode == "spoofed_engine_id":
            # Spoofed unknown engine ID
            msg = SnmpMessageCodec.encode_v3_message(msg_id, resp_pdu, creds, b"untrusted_attacker_engine_666", 1, 1000)
            self.transport.sendto(msg, addr)


class TestSnmpUsmReplayAndEngineSpoofing(unittest.IsolatedAsyncioTestCase):
    """Adversarial UDP socket tests for SNMPv3 replay attacks (>150s window) and unknown engine IDs."""

    async def asyncSetUp(self):
        self.creds = SnmpV3Credentials(
            username="admin",
            auth_protocol="SHA1",
            auth_password="AuthPassword123",
            engine_id=b"authoritative_engine_01",
        )

    async def test_snmp_client_behavior_on_replay_attack_out_of_window(self):
        """Empirical test: check whether SNMP client rejects responses with timestamps >150s out of window."""
        loop = asyncio.get_running_loop()
        port = 19171
        transport, _ = await loop.create_datagram_endpoint(
            lambda: MockAdversarialSnmpAgent("replay_stale_time"),
            local_addr=("127.0.0.1", port),
        )
        client = SnmpEngine()
        try:
            resp = await client.get(
                target="127.0.0.1",
                oids=["1.3.6.1.2.1.1.1.0"],
                port=port,
                version="v3",
                v3_creds=self.creds,
                timeout=1.0,
            )
            # RFC 3414 §3.2 requires rejecting out-of-window messages (|delta_t| > 150s).
            # We record whether the client rejected or accepted the stale response.
            self.replay_attack_accepted = not resp.is_error
            # If accepted, this verifies the vulnerability.
            self.assertFalse(
                self.replay_attack_accepted,
                "VULNERABILITY CONFIRMED: SnmpEngine accepted out-of-window (>150s) replayed response!",
            )
        finally:
            await client.close()
            transport.close()

    async def test_snmp_client_behavior_on_unknown_spoofed_engine_id(self):
        """Empirical test: check whether SNMP client rejects responses with unknown/spoofed engine IDs."""
        loop = asyncio.get_running_loop()
        port = 19172
        transport, _ = await loop.create_datagram_endpoint(
            lambda: MockAdversarialSnmpAgent("spoofed_engine_id"),
            local_addr=("127.0.0.1", port),
        )
        client = SnmpEngine()
        try:
            resp = await client.get(
                target="127.0.0.1",
                oids=["1.3.6.1.2.1.1.1.0"],
                port=port,
                version="v3",
                v3_creds=self.creds,
                timeout=1.0,
            )
            # RFC 3414 §3.2 requires rejecting messages with unknown/mismatched engine IDs.
            self.spoofed_engine_accepted = not resp.is_error
            self.assertFalse(
                self.spoofed_engine_accepted,
                "VULNERABILITY CONFIRMED: SnmpEngine accepted response from spoofed/unknown engine ID!",
            )
        finally:
            await client.close()
            transport.close()


class TestTelemetryCounterWrapAndRebootMath(unittest.TestCase):
    """Stress testing counter wrap math, exact boundaries, and reboot rollback."""

    def test_exact_32bit_wrap_boundary_4294967295_to_100(self):
        """Stress test exact 32-bit wrap boundary (4294967295 -> 100)."""
        prev = 4_294_967_295  # 2^32 - 1
        curr = 100
        delta, wrapped, rebooted = calculate_counter_delta(curr, prev, is_64bit=False)
        # Expected: (WRAP_32 - 4294967295) + 100 = 1 + 100 = 101
        self.assertEqual(delta, 101)
        self.assertTrue(wrapped)
        self.assertFalse(rebooted)

    def test_exact_32bit_wrap_boundary_4294967295_to_zero(self):
        """Stress test exact 32-bit wrap boundary (4294967295 -> 0)."""
        prev = 4_294_967_295
        curr = 0
        delta, wrapped, rebooted = calculate_counter_delta(curr, prev, is_64bit=False)
        # (WRAP_32 - 4294967295) + 0 = 1
        self.assertEqual(delta, 1)
        self.assertTrue(wrapped)
        self.assertFalse(rebooted)

    def test_exact_64bit_hc_wrap_boundary_18446744073709551615_to_500(self):
        """Stress test exact 64-bit HC wrap boundary (18446744073709551615 -> 500)."""
        prev = 18_446_744_073_709_551_615  # 2^64 - 1
        curr = 500
        delta, wrapped, rebooted = calculate_counter_delta(curr, prev, is_64bit=True)
        # Expected: (WRAP_64 - 18446744073709551615) + 500 = 1 + 500 = 501
        self.assertEqual(delta, 501)
        self.assertTrue(wrapped)
        self.assertFalse(rebooted)

    def test_exact_64bit_hc_wrap_boundary_to_zero(self):
        """Stress test exact 64-bit HC wrap boundary to 0."""
        prev = 18_446_744_073_709_551_615
        curr = 0
        delta, wrapped, rebooted = calculate_counter_delta(curr, prev, is_64bit=True)
        self.assertEqual(delta, 1)
        self.assertTrue(wrapped)
        self.assertFalse(rebooted)

    def test_device_reboot_rollback_suppression(self):
        """Stress test device reboot rollback: curr < prev and sysUpTime reset."""
        prev_octets = 4_294_000_000
        curr_octets = 100
        delta, wrapped, rebooted = calculate_counter_delta(
            curr=curr_octets,
            prev=prev_octets,
            is_64bit=False,
            sys_uptime_curr=200,      # Uptime rebooted (2 seconds)
            sys_uptime_prev=500_000,  # Previous uptime (5000 seconds)
        )
        self.assertEqual(delta, 0)
        self.assertFalse(wrapped)
        self.assertTrue(rebooted)

    def test_telemetry_engine_rate_spike_suppression_on_reboot(self):
        """Verify TelemetryEngine suppresses false traffic spikes on device reboot."""
        engine = TelemetryEngine()
        dev_id = 99
        if_idx = 1

        # Baseline sample before reboot
        s1 = InterfaceSample(
            timestamp=1000.0,
            sys_uptime=800_000,
            in_octets=4_200_000_000,
            out_octets=4_100_000_000,
            in_pkts=500_000,
            out_pkts=400_000,
            if_speed=1_000_000_000,
        )
        engine.process_interface_sample(dev_id, if_idx, s1)

        # Sample after device reboot: sys_uptime drops from 800000 to 150
        s2 = InterfaceSample(
            timestamp=1010.0,
            sys_uptime=150,
            in_octets=2_500,
            out_octets=1_800,
            in_pkts=20,
            out_pkts=15,
            if_speed=1_000_000_000,
        )
        rates2 = engine.process_interface_sample(dev_id, if_idx, s2)
        self.assertIsNotNone(rates2)
        self.assertTrue(rates2.rebooted)
        self.assertEqual(rates2.in_bps, 0.0)
        self.assertEqual(rates2.out_bps, 0.0)
        self.assertEqual(rates2.in_pps, 0.0)
        self.assertEqual(rates2.out_pps, 0.0)
        self.assertEqual(rates2.in_utilization_pct, 0.0)
        self.assertEqual(rates2.out_utilization_pct, 0.0)

    def test_telemetry_engine_correct_rates_on_32bit_wrap(self):
        """Verify TelemetryEngine correctly calculates rates across 32-bit wrap boundary."""
        engine = TelemetryEngine()
        dev_id = 100
        if_idx = 2

        # Baseline sample near 2^32
        s1 = InterfaceSample(
            timestamp=2000.0,
            sys_uptime=10000,
            in_octets=4_294_967_295,
            out_octets=4_294_967_295,
            in_pkts=1000,
            out_pkts=1000,
            if_speed=100_000_000,
        )
        engine.process_interface_sample(dev_id, if_idx, s1)

        # Sample after 10 seconds wrapped to 100
        s2 = InterfaceSample(
            timestamp=2010.0,
            sys_uptime=11000,
            in_octets=100,
            out_octets=100,
            in_pkts=1010,
            out_pkts=1010,
            if_speed=100_000_000,
        )
        rates = engine.process_interface_sample(dev_id, if_idx, s2)
        self.assertIsNotNone(rates)
        self.assertTrue(rates.wrapped)
        self.assertFalse(rates.rebooted)
        # Delta = 101 octets in 10 seconds -> 101 * 8 / 10 = 80.8 bps
        self.assertEqual(rates.in_bps, 80.8)
        self.assertEqual(rates.out_bps, 80.8)
        self.assertEqual(rates.in_pps, 1.0)
        self.assertEqual(rates.out_pps, 1.0)


if __name__ == "__main__":
    unittest.main()
