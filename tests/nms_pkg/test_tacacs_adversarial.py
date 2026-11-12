# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Adversarial stress and edge-case verification test suite for RFC 8907 TACACS+ Server.

Challenges:
1. Malformed Packets:
   - Truncated headers (<12 bytes)
   - Truncated packet bodies & length fields smaller than minimum struct sizes
   - Invalid TACACS+ major protocol versions (!= 0x0C)
   - Massive oversized packet length headers (> 65536 bytes)
2. Cryptographic Attacks:
   - Mismatched shared secret keys
   - Ciphertext byte corruption & bit-flipping
   - Zero-length bodies / empty payloads with mismatched length declarations
3. Sequence Number Desync:
   - Client sending even sequence numbers (violating client-odd / server-even RFC rule)
   - Client skipping sequence numbers (seq 1 -> seq 5)
   - Client initiating with out-of-order sequence numbers (seq 3 / seq 5 without seq 1)
4. Single-Connection Session Multiplexing & Interleaving:
   - Concurrently interleaving 10 distinct session IDs over a single persistent TCP socket
   - Heterogeneous AAA mix: PAP, ASCII interactive, Authorization, Accounting
   - Verifying zero cross-talk, correct session_id correlation, and no socket lockup
5. Server Post-Attack Robustness & State Integrity:
   - Server survives barrage of malformed/corrupted packets without crash or hang
   - Server continues to process legitimate AAA requests cleanly
   - Daemon status and WAL integrity remain intact
"""

from __future__ import annotations

import asyncio
import os
import random
import secrets
import struct
import tempfile
import time
import unittest
from typing import Dict, List, Optional, Tuple

from nms.common.db import get_db_connection, init_db
from nms.tacacs.acct import (
    TAC_PLUS_ACCT_FLAG_START,
    TAC_PLUS_ACCT_STATUS_SUCCESS,
)
from nms.tacacs.authen import (
    TAC_PLUS_AUTHEN_STATUS_FAIL,
    TAC_PLUS_AUTHEN_STATUS_GETPASS,
    TAC_PLUS_AUTHEN_STATUS_PASS,
    TAC_PLUS_AUTHEN_SVC_LOGIN,
    TAC_PLUS_AUTHEN_TYPE_ASCII,
    TAC_PLUS_AUTHEN_TYPE_PAP,
)
from nms.tacacs.author import (
    TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
)
from nms.tacacs.codec import (
    TAC_PLUS_ACCT,
    TAC_PLUS_AUTHEN,
    TAC_PLUS_AUTHOR,
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_MINOR_VER_DEFAULT,
    TAC_PLUS_MINOR_VER_ONE,
    TAC_PLUS_SINGLE_CONNECT_FLAG,
    AVPair,
    AcctReply,
    AcctRequest,
    AuthenContinue,
    AuthenReply,
    AuthenStart,
    AuthorReply,
    AuthorRequest,
    TacacsHeader,
    unpack_header,
)
from nms.tacacs.crypto import (
    decrypt_body,
    encrypt_body,
    generate_pad,
    xor_bytes,
)
from nms.tacacs.server import TacacsServer

TEST_PORT = 4955
TEST_SECRET = "testing123"


class RawTacacsClient:
    """Low-level raw client allowing arbitrary byte-level and packet-level manipulation."""

    def __init__(self, host: str = "127.0.0.1", port: int = TEST_PORT, secret: str = TEST_SECRET):
        self.host = host
        self.port = port
        self.secret = secret
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

    async def close(self) -> None:
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass

    async def send_raw_bytes(self, data: bytes) -> None:
        if not self.writer:
            raise RuntimeError("Not connected")
        self.writer.write(data)
        await self.writer.drain()

    async def read_response_raw(self, timeout: float = 2.0) -> Tuple[Optional[TacacsHeader], Optional[bytes]]:
        if not self.reader:
            raise RuntimeError("Not connected")
        try:
            hdr_bytes = await asyncio.wait_for(self.reader.readexactly(12), timeout=timeout)
            hdr = unpack_header(hdr_bytes)
            body_bytes = b""
            if hdr.length > 0:
                body_bytes = await asyncio.wait_for(self.reader.readexactly(hdr.length), timeout=timeout)
            return hdr, body_bytes
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionResetError):
            return None, None

    async def send_packet(
        self,
        header: TacacsHeader,
        plain_body: bytes,
        custom_secret: Optional[str] = None,
        tamper_fn=None,
    ) -> None:
        secret_to_use = custom_secret if custom_secret is not None else self.secret
        enc_body = encrypt_body(header, plain_body, secret_to_use)
        if tamper_fn:
            enc_body = tamper_fn(enc_body)
        header.length = len(enc_body)
        await self.send_raw_bytes(header.pack() + enc_body)


class TestTacacsAdversarialStress(unittest.IsolatedAsyncioTestCase):
    """Adversarial stress harness for RFC 8907 TACACS+ Daemon."""

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp_dir.name, "adv_enterprise.db")
        init_db(self.db_path)

        self.server = TacacsServer(
            host="127.0.0.1",
            port=TEST_PORT,
            fallback_port=TEST_PORT,
            db_path=self.db_path,
            idle_timeout=5.0,
            single_connect_timeout=15.0,
        )
        await self.server.start()

    async def asyncTearDown(self):
        await self.server.stop()
        await asyncio.sleep(0.05)
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    # =========================================================================
    # Group 1: Malformed Packets
    # =========================================================================

    async def test_truncated_headers(self):
        """Server must gracefully handle truncated headers (<12 bytes) without crashing."""
        for num_bytes in (1, 3, 7, 11):
            client = RawTacacsClient(port=TEST_PORT)
            await client.connect()
            try:
                # Send truncated header bytes and abruptly close
                garbage = secrets.token_bytes(num_bytes)
                await client.send_raw_bytes(garbage)
                await client.close()
            except Exception:
                pass

        # Verify server is still alive
        alive_client = RawTacacsClient(port=TEST_PORT)
        await alive_client.connect()
        try:
            hdr = TacacsHeader(major_version=0x0C, minor_version=1, type=TAC_PLUS_AUTHEN, seq_no=1, session_id=0x1234)
            start = AuthenStart(action=1, priv_lvl=1, authen_type=TAC_PLUS_AUTHEN_TYPE_PAP, user="admin", data=b"Admin123!")
            await alive_client.send_packet(hdr, start.pack())
            resp_hdr, resp_body = await alive_client.read_response_raw()
            self.assertIsNotNone(resp_hdr)
            self.assertIsNotNone(resp_body)
            dec = decrypt_body(resp_hdr, resp_body, TEST_SECRET)
            reply = AuthenReply.unpack(dec)
            self.assertEqual(reply.status, TAC_PLUS_AUTHEN_STATUS_PASS)
        finally:
            await alive_client.close()

    async def test_length_fields_smaller_than_struct_headers(self):
        """Header length declared smaller than minimum body struct sizes must be rejected safely."""
        # 1. AuthenStart requires >= 8 bytes; send length = 4
        client = RawTacacsClient(port=TEST_PORT)
        await client.connect()
        try:
            hdr = TacacsHeader(major_version=0x0C, minor_version=1, type=TAC_PLUS_AUTHEN, seq_no=1, session_id=0x9999)
            hdr.length = 4
            pad = generate_pad(hdr.session_id, TEST_SECRET, hdr.raw_version, hdr.seq_no, 4)
            bogus_body = xor_bytes(b"\x01\x01\x01\x01", pad)
            await client.send_raw_bytes(hdr.pack() + bogus_body)
            # Server should drop the connection due to integrity failure
            resp_hdr, _ = await client.read_response_raw(timeout=1.0)
            self.assertIsNone(resp_hdr)
        finally:
            await client.close()

        # 2. AuthorRequest requires >= 8 bytes; send length = 3
        client2 = RawTacacsClient(port=TEST_PORT)
        await client2.connect()
        try:
            hdr2 = TacacsHeader(major_version=0x0C, minor_version=0, type=TAC_PLUS_AUTHOR, seq_no=1, session_id=0x8888)
            hdr2.length = 3
            pad2 = generate_pad(hdr2.session_id, TEST_SECRET, hdr2.raw_version, hdr2.seq_no, 3)
            bogus_body2 = xor_bytes(b"\x01\x01\x01", pad2)
            await client2.send_raw_bytes(hdr2.pack() + bogus_body2)
            resp_hdr2, _ = await client2.read_response_raw(timeout=1.0)
            self.assertIsNone(resp_hdr2)
        finally:
            await client2.close()

        # 3. AcctRequest requires >= 9 bytes; send length = 5
        client3 = RawTacacsClient(port=TEST_PORT)
        await client3.connect()
        try:
            hdr3 = TacacsHeader(major_version=0x0C, minor_version=0, type=TAC_PLUS_ACCT, seq_no=1, session_id=0x7777)
            hdr3.length = 5
            pad3 = generate_pad(hdr3.session_id, TEST_SECRET, hdr3.raw_version, hdr3.seq_no, 5)
            bogus_body3 = xor_bytes(b"\x02\x01\x01\x01\x01", pad3)
            await client3.send_raw_bytes(hdr3.pack() + bogus_body3)
            resp_hdr3, _ = await client3.read_response_raw(timeout=1.0)
            self.assertIsNone(resp_hdr3)
        finally:
            await client3.close()

    async def test_invalid_major_version(self):
        """Server must immediately reject packets with major_version != 0x0C."""
        for bad_ver in (0x00, 0x01, 0x0B, 0x0D, 0x0F):
            client = RawTacacsClient(port=TEST_PORT)
            await client.connect()
            try:
                # Raw version packed byte has major_ver in high nibble
                hdr = TacacsHeader(major_version=bad_ver, minor_version=0, type=TAC_PLUS_AUTHEN, seq_no=1, session_id=0x1111)
                start = AuthenStart(action=1, priv_lvl=1, authen_type=TAC_PLUS_AUTHEN_TYPE_PAP, user="admin", data=b"Admin123!")
                await client.send_packet(hdr, start.pack())
                resp_hdr, resp_body = await client.read_response_raw(timeout=1.0)
                # Connection should be dropped cleanly
                self.assertIsNone(resp_hdr)
            finally:
                await client.close()

    async def test_oversized_packet_length(self):
        """Header declaring packet length > 65536 bytes must be dropped immediately."""
        client = RawTacacsClient(port=TEST_PORT)
        await client.connect()
        try:
            hdr = TacacsHeader(major_version=0x0C, minor_version=0, type=TAC_PLUS_AUTHEN, seq_no=1, session_id=0x5555)
            hdr.length = 70000
            await client.send_raw_bytes(hdr.pack())
            resp_hdr, _ = await client.read_response_raw(timeout=1.0)
            self.assertIsNone(resp_hdr)
        finally:
            await client.close()

    # =========================================================================
    # Group 2: Cryptographic Attacks
    # =========================================================================

    async def test_mismatched_shared_secrets(self):
        """Packets encrypted with wrong shared secret must be dropped via integrity check."""
        client = RawTacacsClient(port=TEST_PORT)
        await client.connect()
        try:
            hdr = TacacsHeader(major_version=0x0C, minor_version=1, type=TAC_PLUS_AUTHEN, seq_no=1, session_id=0x4321)
            start = AuthenStart(action=1, priv_lvl=1, authen_type=TAC_PLUS_AUTHEN_TYPE_PAP, user="admin", data=b"Admin123!")
            # Encrypt with completely wrong secret
            await client.send_packet(hdr, start.pack(), custom_secret="COMPLETELY_WRONG_SECRET_KEY")
            resp_hdr, _ = await client.read_response_raw(timeout=1.0)
            # Integrity check fails -> connection dropped
            self.assertIsNone(resp_hdr)
        finally:
            await client.close()

    async def test_altered_ciphertext_tampering(self):
        """Ciphertext tampering must either be dropped (length corruption) or fail authentication (data corruption)."""
        # Case A: Corrupting length fields (offsets 4, 5, 6, 7 in AuthenStart)
        # Must be caught by validate_body_integrity and connection dropped
        for len_offset in (4, 5, 6, 7):
            client = RawTacacsClient(port=TEST_PORT)
            await client.connect()
            try:
                hdr = TacacsHeader(major_version=0x0C, minor_version=1, type=TAC_PLUS_AUTHEN, seq_no=1, session_id=0x7700 + len_offset)
                start = AuthenStart(action=1, priv_lvl=1, authen_type=TAC_PLUS_AUTHEN_TYPE_PAP, user="admin", data=b"Admin123!")

                def corrupt_len(enc_bytes: bytes) -> bytes:
                    ba = bytearray(enc_bytes)
                    ba[len_offset] ^= 0x55
                    return bytes(ba)

                await client.send_packet(hdr, start.pack(), tamper_fn=corrupt_len)
                resp_hdr, _ = await client.read_response_raw(timeout=1.0)
                # Length integrity check fails -> connection dropped
                self.assertIsNone(resp_hdr, f"Tampered length field at offset {len_offset} was not dropped")
            finally:
                await client.close()

        # Case B: Corrupting payload data fields (username / password data bytes)
        # Lengths still match, but decryption yields garbage -> MUST NOT PASS, must return FAIL
        client_b = RawTacacsClient(port=TEST_PORT)
        await client_b.connect()
        try:
            hdr_b = TacacsHeader(major_version=0x0C, minor_version=1, type=TAC_PLUS_AUTHEN, seq_no=1, session_id=0x8899)
            start_b = AuthenStart(action=1, priv_lvl=1, authen_type=TAC_PLUS_AUTHEN_TYPE_PAP, user="admin", data=b"Admin123!")

            def corrupt_payload(enc_bytes: bytes) -> bytes:
                ba = bytearray(enc_bytes)
                # Offset >= 8 is payload (user / port / rem_addr / data)
                ba[-1] ^= 0x01  # Flip 1 bit in password data
                return bytes(ba)

            await client_b.send_packet(hdr_b, start_b.pack(), tamper_fn=corrupt_payload)
            resp_hdr_b, resp_body_b = await client_b.read_response_raw(timeout=1.0)
            self.assertIsNotNone(resp_hdr_b)
            dec_b = decrypt_body(resp_hdr_b, resp_body_b, TEST_SECRET)
            reply_b = AuthenReply.unpack(dec_b)
            # Tampered password data MUST NEVER authenticate
            self.assertEqual(reply_b.status, TAC_PLUS_AUTHEN_STATUS_FAIL)
        finally:
            await client_b.close()

    async def test_zero_length_body_with_payload_expected(self):
        """Header with length=0 when body is required must be handled without crash."""
        client = RawTacacsClient(port=TEST_PORT)
        await client.connect()
        try:
            hdr = TacacsHeader(major_version=0x0C, minor_version=0, type=TAC_PLUS_AUTHEN, seq_no=1, session_id=0x1212)
            hdr.length = 0
            await client.send_raw_bytes(hdr.pack())
            resp_hdr, resp_body = await client.read_response_raw(timeout=1.0)
            # Server returns an AuthenReply with ERROR status due to empty AuthenStart
            if resp_hdr and resp_body:
                dec = decrypt_body(resp_hdr, resp_body, TEST_SECRET)
                if dec:
                    reply = AuthenReply.unpack(dec)
                    self.assertIn(reply.status, (TAC_PLUS_AUTHEN_STATUS_FAIL, 7))  # 7 is STATUS_ERROR
        finally:
            await client.close()

    # =========================================================================
    # Group 3: Sequence Number Desync
    # =========================================================================

    async def test_client_sending_even_sequence_number(self):
        """Client sending even seq_no (seq 2, 4) must be handled without crash or state corruption."""
        client = RawTacacsClient(port=TEST_PORT)
        await client.connect()
        try:
            # Client sends seq_no=2
            hdr = TacacsHeader(major_version=0x0C, minor_version=0, type=TAC_PLUS_AUTHEN, seq_no=2, session_id=0x2222)
            # Body payload
            start = AuthenStart(action=1, priv_lvl=1, authen_type=TAC_PLUS_AUTHEN_TYPE_PAP, user="admin", data=b"Admin123!")
            body = start.pack()
            # Send packet
            await client.send_packet(hdr, body)
            resp_hdr, resp_body = await client.read_response_raw(timeout=1.0)
            # Connection either dropped or rejected; verify no server crash
        finally:
            await client.close()

        # Confirm server is still functioning normally
        sanity_client = RawTacacsClient(port=TEST_PORT)
        await sanity_client.connect()
        try:
            hdr_s = TacacsHeader(major_version=0x0C, minor_version=1, type=TAC_PLUS_AUTHEN, seq_no=1, session_id=0x2223)
            start_s = AuthenStart(action=1, priv_lvl=1, authen_type=TAC_PLUS_AUTHEN_TYPE_PAP, user="admin", data=b"Admin123!")
            await sanity_client.send_packet(hdr_s, start_s.pack())
            resp_hdr_s, resp_body_s = await sanity_client.read_response_raw(timeout=2.0)
            self.assertIsNotNone(resp_hdr_s)
        finally:
            await sanity_client.close()

    async def test_client_skipping_sequence_numbers(self):
        """Client jumping sequence numbers (e.g. seq 1 -> seq 5) must not crash the server."""
        client = RawTacacsClient(port=TEST_PORT)
        await client.connect()
        sess_id = 0x3333
        try:
            # 1. Client sends valid seq 1 START
            hdr1 = TacacsHeader(major_version=0x0C, minor_version=0, type=TAC_PLUS_AUTHEN, seq_no=1, session_id=sess_id)
            start = AuthenStart(action=1, priv_lvl=1, authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII, user="operator")
            await client.send_packet(hdr1, start.pack())
            r_hdr1, r_body1 = await client.read_response_raw()
            self.assertIsNotNone(r_hdr1)
            self.assertEqual(r_hdr1.seq_no, 2)

            # 2. Client skips seq 3 and jumps directly to seq 5 or 9!
            hdr_skip = TacacsHeader(major_version=0x0C, minor_version=0, type=TAC_PLUS_AUTHEN, seq_no=7, session_id=sess_id)
            cont = AuthenContinue(user_msg="Operator123!")
            await client.send_packet(hdr_skip, cont.pack())
            r_hdr2, r_body2 = await client.read_response_raw(timeout=2.0)
            # Server either replies with next even seq or drops, but MUST NOT crash or hang
        finally:
            await client.close()

    async def test_client_initiating_session_with_unexpected_continue(self):
        """Client sending seq 3 CONTINUE without prior session must fail safely."""
        client = RawTacacsClient(port=TEST_PORT)
        await client.connect()
        try:
            hdr = TacacsHeader(major_version=0x0C, minor_version=0, type=TAC_PLUS_AUTHEN, seq_no=3, session_id=0x4444)
            cont = AuthenContinue(user_msg="SomePassword")
            await client.send_packet(hdr, cont.pack())
            resp_hdr, resp_body = await client.read_response_raw(timeout=2.0)
            if resp_hdr and resp_body:
                dec = decrypt_body(resp_hdr, resp_body, TEST_SECRET)
                self.assertIsNotNone(dec)
                reply = AuthenReply.unpack(dec)
                self.assertEqual(reply.status, TAC_PLUS_AUTHEN_STATUS_FAIL)
                self.assertIn("Invalid session state", reply.server_msg)
        finally:
            await client.close()

    # =========================================================================
    # Group 4: Single-Connection Session Interleaving (10 Concurrent Sessions)
    # =========================================================================

    async def test_single_connection_10_sessions_concurrent_interleaving(self):
        """Interleave packets from 10 distinct session IDs over a SINGLE TCP socket concurrently.

        Verifies:
        - Server multiplexes all 10 sessions over one connection with TAC_PLUS_SINGLE_CONNECT_FLAG
        - Heterogeneous AAA packet types (ASCII, PAP, Authorization, Accounting)
        - Zero cross-talk between sessions (replies have correct matching session IDs)
        - All 10 operations complete with 100% success and no socket hang
        """
        reader, writer = await asyncio.open_connection("127.0.0.1", TEST_PORT)

        # Generate 10 unique session IDs
        session_ids = [secrets.randbits(32) for _ in range(10)]
        # Map: session_id -> expected type & state
        session_types = {
            session_ids[0]: "PAP_ADMIN",
            session_ids[1]: "PAP_OPERATOR",
            session_ids[2]: "ASCII_OPERATOR",
            session_ids[3]: "ASCII_ADMIN",
            session_ids[4]: "AUTHOR_SHOW",
            session_ids[5]: "AUTHOR_PING",
            session_ids[6]: "AUTHOR_DENY_RELOAD",
            session_ids[7]: "ACCT_START",
            session_ids[8]: "ACCT_STOP",
            session_ids[9]: "PAP_FAIL",
        }

        # Response accumulator
        responses_by_session: Dict[int, List[Tuple[TacacsHeader, bytes]]] = {sid: [] for sid in session_ids}
        read_done = asyncio.Event()
        total_expected_replies = 13  # 7 single-round (1 each) + 1 PAP fail (1) + sess 2 (2) + sess 3 (3) = 13 total replies

        async def reader_worker():
            try:
                while len([r for replies in responses_by_session.values() for r in replies]) < total_expected_replies:
                    hdr_bytes = await asyncio.wait_for(reader.readexactly(12), timeout=10.0)
                    hdr = unpack_header(hdr_bytes)
                    b_bytes = b""
                    if hdr.length > 0:
                        b_bytes = await asyncio.wait_for(reader.readexactly(hdr.length), timeout=10.0)
                    plain = decrypt_body(hdr, b_bytes, TEST_SECRET)
                    if plain is None:
                        raise ValueError(f"Decryption failed for session 0x{hdr.session_id:08x}")
                    responses_by_session[hdr.session_id].append((hdr, plain))
            except Exception as e:
                pass
            finally:
                read_done.set()

        reader_task = asyncio.create_task(reader_worker())

        # Step 1: Send initial packets for all 10 sessions in interleaved/randomized order
        initial_packets = []

        # 0: PAP admin pass
        h0 = TacacsHeader(0x0C, 1, TAC_PLUS_AUTHEN, 1, TAC_PLUS_SINGLE_CONNECT_FLAG, session_ids[0], 0)
        b0 = AuthenStart(1, 1, TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHEN_SVC_LOGIN, "admin", data=b"Admin123!").pack()
        initial_packets.append((h0, b0))

        # 1: PAP operator pass
        h1 = TacacsHeader(0x0C, 1, TAC_PLUS_AUTHEN, 1, TAC_PLUS_SINGLE_CONNECT_FLAG, session_ids[1], 0)
        b1 = AuthenStart(1, 1, TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHEN_SVC_LOGIN, "operator", data=b"Operator123!").pack()
        initial_packets.append((h1, b1))

        # 2: ASCII operator step 1 (user provided)
        h2 = TacacsHeader(0x0C, 0, TAC_PLUS_AUTHEN, 1, TAC_PLUS_SINGLE_CONNECT_FLAG, session_ids[2], 0)
        b2 = AuthenStart(1, 1, TAC_PLUS_AUTHEN_TYPE_ASCII, TAC_PLUS_AUTHEN_SVC_LOGIN, "operator").pack()
        initial_packets.append((h2, b2))

        # 3: ASCII admin step 1 (user empty)
        h3 = TacacsHeader(0x0C, 0, TAC_PLUS_AUTHEN, 1, TAC_PLUS_SINGLE_CONNECT_FLAG, session_ids[3], 0)
        b3 = AuthenStart(1, 1, TAC_PLUS_AUTHEN_TYPE_ASCII, TAC_PLUS_AUTHEN_SVC_LOGIN, "").pack()
        initial_packets.append((h3, b3))

        # 4: Author permit show ip route
        h4 = TacacsHeader(0x0C, 0, TAC_PLUS_AUTHOR, 1, TAC_PLUS_SINGLE_CONNECT_FLAG, session_ids[4], 0)
        b4 = AuthorRequest(1, 15, 1, 1, "admin", "vty0", "10.0.0.1", [
            AVPair("service", "=", "shell"),
            AVPair("cmd", "=", "show"),
            AVPair("cmd-arg", "=", "ip"),
            AVPair("cmd-arg", "=", "route"),
        ]).pack()
        initial_packets.append((h4, b4))

        # 5: Author permit ping
        h5 = TacacsHeader(0x0C, 0, TAC_PLUS_AUTHOR, 1, TAC_PLUS_SINGLE_CONNECT_FLAG, session_ids[5], 0)
        b5 = AuthorRequest(1, 7, 1, 1, "operator", "vty0", "10.0.0.2", [
            AVPair("service", "=", "shell"),
            AVPair("cmd", "=", "ping"),
            AVPair("cmd-arg", "=", "8.8.8.8"),
        ]).pack()
        initial_packets.append((h5, b5))

        # 6: Author deny reload for operator
        h6 = TacacsHeader(0x0C, 0, TAC_PLUS_AUTHOR, 1, TAC_PLUS_SINGLE_CONNECT_FLAG, session_ids[6], 0)
        b6 = AuthorRequest(1, 7, 1, 1, "operator", "vty0", "10.0.0.3", [
            AVPair("service", "=", "shell"),
            AVPair("cmd", "=", "reload"),
        ]).pack()
        initial_packets.append((h6, b6))

        # 7: Acct START
        h7 = TacacsHeader(0x0C, 0, TAC_PLUS_ACCT, 1, TAC_PLUS_SINGLE_CONNECT_FLAG, session_ids[7], 0)
        b7 = AcctRequest(TAC_PLUS_ACCT_FLAG_START, 1, 15, 1, 1, "admin", "vty0", "10.0.0.4", [
            AVPair("service", "=", "shell"),
            AVPair("cmd", "=", "configure terminal"),
        ]).pack()
        initial_packets.append((h7, b7))

        # 8: Acct STOP
        h8 = TacacsHeader(0x0C, 0, TAC_PLUS_ACCT, 1, TAC_PLUS_SINGLE_CONNECT_FLAG, session_ids[8], 0)
        b8 = AcctRequest(4, 1, 7, 1, 1, "operator", "vty0", "10.0.0.5", [
            AVPair("service", "=", "shell"),
            AVPair("cmd", "=", "show version"),
        ]).pack()
        initial_packets.append((h8, b8))

        # 9: PAP wrong password
        h9 = TacacsHeader(0x0C, 1, TAC_PLUS_AUTHEN, 1, TAC_PLUS_SINGLE_CONNECT_FLAG, session_ids[9], 0)
        b9 = AuthenStart(1, 1, TAC_PLUS_AUTHEN_TYPE_PAP, TAC_PLUS_AUTHEN_SVC_LOGIN, "admin", data=b"WrongPass").pack()
        initial_packets.append((h9, b9))

        # Shuffle initial packets to stress concurrent arrival interleaving
        random.seed(42)
        shuffled_packets = list(initial_packets)
        random.shuffle(shuffled_packets)

        # Transmit all initial packets sequentially over the SAME single socket
        for hdr, body in shuffled_packets:
            enc = encrypt_body(hdr, body, TEST_SECRET)
            hdr.length = len(enc)
            writer.write(hdr.pack() + enc)
        await writer.drain()

        # Wait briefly for responses to arrive
        for _ in range(50):
            if len(responses_by_session[session_ids[2]]) >= 1 and len(responses_by_session[session_ids[3]]) >= 1:
                break
            await asyncio.sleep(0.05)

        # Step 2: Send continuation packets for interactive sessions 2 & 3
        # Session 2 was operator, sent user, expects GETPASS -> send CONTINUE with password
        h2_c = TacacsHeader(0x0C, 0, TAC_PLUS_AUTHEN, 3, TAC_PLUS_SINGLE_CONNECT_FLAG, session_ids[2], 0)
        b2_c = AuthenContinue(user_msg="Operator123!").pack()
        enc2 = encrypt_body(h2_c, b2_c, TEST_SECRET)
        h2_c.length = len(enc2)
        writer.write(h2_c.pack() + enc2)

        # Session 3 was admin, sent empty user, expects GETUSER -> send CONTINUE with user "admin"
        h3_c1 = TacacsHeader(0x0C, 0, TAC_PLUS_AUTHEN, 3, TAC_PLUS_SINGLE_CONNECT_FLAG, session_ids[3], 0)
        b3_c1 = AuthenContinue(user_msg="admin").pack()
        enc3_1 = encrypt_body(h3_c1, b3_c1, TEST_SECRET)
        h3_c1.length = len(enc3_1)
        writer.write(h3_c1.pack() + enc3_1)
        await writer.drain()

        # Wait for session 3 GETPASS reply
        for _ in range(50):
            if len(responses_by_session[session_ids[3]]) >= 2:
                break
            await asyncio.sleep(0.05)

        # Session 3: send password "Admin123!"
        h3_c2 = TacacsHeader(0x0C, 0, TAC_PLUS_AUTHEN, 5, TAC_PLUS_SINGLE_CONNECT_FLAG, session_ids[3], 0)
        b3_c2 = AuthenContinue(user_msg="Admin123!").pack()
        enc3_2 = encrypt_body(h3_c2, b3_c2, TEST_SECRET)
        h3_c2.length = len(enc3_2)
        writer.write(h3_c2.pack() + enc3_2)
        await writer.drain()

        # Wait for all expected replies to be processed
        try:
            await asyncio.wait_for(read_done.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        reader_task.cancel()

        # Assertions & Verification
        # 1. Check Session 0 (PAP Admin Pass)
        r0 = responses_by_session[session_ids[0]]
        self.assertEqual(len(r0), 1, "Session 0 should have 1 response")
        reply0 = AuthenReply.unpack(r0[0][1])
        self.assertEqual(reply0.status, TAC_PLUS_AUTHEN_STATUS_PASS)

        # 2. Check Session 1 (PAP Operator Pass)
        r1 = responses_by_session[session_ids[1]]
        self.assertEqual(len(r1), 1, "Session 1 should have 1 response")
        reply1 = AuthenReply.unpack(r1[0][1])
        self.assertEqual(reply1.status, TAC_PLUS_AUTHEN_STATUS_PASS)

        # 3. Check Session 2 (ASCII Operator Pass)
        r2 = responses_by_session[session_ids[2]]
        self.assertEqual(len(r2), 2, "Session 2 should have 2 responses (GETPASS, PASS)")
        self.assertEqual(AuthenReply.unpack(r2[0][1]).status, TAC_PLUS_AUTHEN_STATUS_GETPASS)
        self.assertEqual(AuthenReply.unpack(r2[1][1]).status, TAC_PLUS_AUTHEN_STATUS_PASS)

        # 4. Check Session 3 (ASCII Admin 3-step Pass)
        r3 = responses_by_session[session_ids[3]]
        self.assertEqual(len(r3), 3, "Session 3 should have 3 responses (GETUSER, GETPASS, PASS)")
        self.assertEqual(AuthenReply.unpack(r3[0][1]).status, 4)  # GETUSER
        self.assertEqual(AuthenReply.unpack(r3[1][1]).status, TAC_PLUS_AUTHEN_STATUS_GETPASS)
        self.assertEqual(AuthenReply.unpack(r3[2][1]).status, TAC_PLUS_AUTHEN_STATUS_PASS)

        # 5. Check Session 4 (Author Admin Show Route Permit)
        r4 = responses_by_session[session_ids[4]]
        self.assertEqual(len(r4), 1)
        reply4 = AuthorReply.unpack(r4[0][1])
        self.assertEqual(reply4.status, TAC_PLUS_AUTHOR_STATUS_PASS_ADD)

        # 6. Check Session 5 (Author Operator Ping Permit)
        r5 = responses_by_session[session_ids[5]]
        self.assertEqual(len(r5), 1)
        reply5 = AuthorReply.unpack(r5[0][1])
        self.assertEqual(reply5.status, TAC_PLUS_AUTHOR_STATUS_PASS_ADD)

        # 7. Check Session 6 (Author Operator Reload Deny)
        r6 = responses_by_session[session_ids[6]]
        self.assertEqual(len(r6), 1)
        reply6 = AuthorReply.unpack(r6[0][1])
        self.assertEqual(reply6.status, 0x10)  # TAC_PLUS_AUTHOR_STATUS_FAIL

        # 8. Check Session 7 (Acct START)
        r7 = responses_by_session[session_ids[7]]
        self.assertEqual(len(r7), 1)
        reply7 = AcctReply.unpack(r7[0][1])
        self.assertEqual(reply7.status, TAC_PLUS_ACCT_STATUS_SUCCESS)

        # 9. Check Session 8 (Acct STOP)
        r8 = responses_by_session[session_ids[8]]
        self.assertEqual(len(r8), 1)
        reply8 = AcctReply.unpack(r8[0][1])
        self.assertEqual(reply8.status, TAC_PLUS_ACCT_STATUS_SUCCESS)

        # 10. Check Session 9 (PAP Fail)
        r9 = responses_by_session[session_ids[9]]
        self.assertEqual(len(r9), 1)
        reply9 = AuthenReply.unpack(r9[0][1])
        self.assertEqual(reply9.status, TAC_PLUS_AUTHEN_STATUS_FAIL)

        # Verify exact session ID isolation (no cross-talk)
        for sid, replies in responses_by_session.items():
            for hdr, _ in replies:
                self.assertEqual(hdr.session_id, sid, f"Session ID mismatch: expected {sid}, got {hdr.session_id}")

    # =========================================================================
    # Group 5: Server Post-Attack Robustness & State Integrity
    # =========================================================================

    async def test_server_health_post_adversarial_barrage(self):
        """Subject server to 60 malformed/corrupted packets then confirm normal operation."""
        # Rapidly spray malformed packets from multiple connections
        for _ in range(20):
            # 1. Random junk bytes
            c = RawTacacsClient(port=TEST_PORT)
            try:
                await c.connect()
                await c.send_raw_bytes(secrets.token_bytes(random.randint(1, 50)))
            except Exception:
                pass
            finally:
                await c.close()

            # 2. Corrupted packet header
            c = RawTacacsClient(port=TEST_PORT)
            try:
                await c.connect()
                bad_hdr = TacacsHeader(major_version=random.randint(0, 10), seq_no=random.randint(2, 20), length=random.randint(1, 100))
                await c.send_raw_bytes(bad_hdr.pack() + secrets.token_bytes(bad_hdr.length))
            except Exception:
                pass
            finally:
                await c.close()

            # 3. Bad crypto secret
            c = RawTacacsClient(port=TEST_PORT)
            try:
                await c.connect()
                h = TacacsHeader(0x0C, 1, TAC_PLUS_AUTHEN, 1, 0, secrets.randbits(32), 0)
                st = AuthenStart(1, 1, TAC_PLUS_AUTHEN_TYPE_PAP, user="admin", data=b"pass").pack()
                await c.send_packet(h, st, custom_secret="bad_key")
            except Exception:
                pass
            finally:
                await c.close()

        # Small delay for background processing
        await asyncio.sleep(0.2)

        # Confirm legitimate client still succeeds
        clean_client = RawTacacsClient(port=TEST_PORT)
        await clean_client.connect()
        try:
            h = TacacsHeader(0x0C, 1, TAC_PLUS_AUTHEN, 1, 0, 0x99887766, 0)
            start = AuthenStart(1, 1, TAC_PLUS_AUTHEN_TYPE_PAP, user="admin", data=b"Admin123!").pack()
            await clean_client.send_packet(h, start)
            resp_hdr, resp_body = await clean_client.read_response_raw(timeout=3.0)
            self.assertIsNotNone(resp_hdr, "Server failed to respond to legitimate client after attack")
            dec = decrypt_body(resp_hdr, resp_body, TEST_SECRET)
            reply = AuthenReply.unpack(dec)
            self.assertEqual(reply.status, TAC_PLUS_AUTHEN_STATUS_PASS)
        finally:
            await clean_client.close()

        # Verify SQLite WAL database is uncorrupted
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check;")
            integrity_row = cursor.fetchone()
            self.assertEqual(integrity_row[0], "ok", "Database WAL corrupted after attack")

            # Check daemon heartbeat status
            cursor.execute("SELECT status, metrics_json FROM daemon_status WHERE daemon_name = 'tacacs_daemon'")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["status"], "RUNNING")

    async def test_cross_protocol_type_mutation_in_same_session(self):
        """Client switching packet types mid-session (e.g. Authen seq 1 -> Author seq 3)."""
        client = RawTacacsClient(port=TEST_PORT)
        await client.connect()
        sess_id = 0xABCDE123
        try:
            # Step 1: Authen START seq 1
            h1 = TacacsHeader(0x0C, 0, TAC_PLUS_AUTHEN, 1, TAC_PLUS_SINGLE_CONNECT_FLAG, sess_id, 0)
            b1 = AuthenStart(1, 1, TAC_PLUS_AUTHEN_TYPE_ASCII, TAC_PLUS_AUTHEN_SVC_LOGIN, "").pack()
            await client.send_packet(h1, b1)
            r_hdr1, r_body1 = await client.read_response_raw()
            self.assertIsNotNone(r_hdr1)
            self.assertEqual(r_hdr1.seq_no, 2)

            # Step 2: In the same session, send AuthorRequest seq 3!
            h2 = TacacsHeader(0x0C, 0, TAC_PLUS_AUTHOR, 3, TAC_PLUS_SINGLE_CONNECT_FLAG, sess_id, 0)
            b2 = AuthorRequest(1, 15, 1, 1, "admin", "vty0", "10.0.0.1", [
                AVPair("service", "=", "shell"),
                AVPair("cmd", "=", "show version"),
            ]).pack()
            await client.send_packet(h2, b2)
            r_hdr2, r_body2 = await client.read_response_raw(timeout=2.0)
            # Server must handle gracefully without crashing (either process author or reject)
        finally:
            await client.close()

    async def test_av_pair_fuzzing_and_boundary_extremes(self):
        """Author and Acct requests with 200 AV-pairs and malformed string characters."""
        client = RawTacacsClient(port=TEST_PORT)
        await client.connect()
        try:
            # Build 200 AV pairs
            many_pairs = [AVPair(f"custom-attr-{i}", "=" if i % 2 == 0 else "*", f"val-{i * 100}") for i in range(200)]
            many_pairs.append(AVPair("service", "=", "shell"))
            many_pairs.append(AVPair("cmd", "=", "show"))
            many_pairs.append(AVPair("cmd-arg", "=", "ip"))
            many_pairs.append(AVPair("cmd-arg", "=", "interface"))

            h = TacacsHeader(0x0C, 0, TAC_PLUS_AUTHOR, 1, 0, 0x55AA1122, 0)
            req = AuthorRequest(1, 15, 1, 1, "admin", "vty0", "127.0.0.1", many_pairs)
            await client.send_packet(h, req.pack())
            resp_hdr, resp_body = await client.read_response_raw(timeout=3.0)
            self.assertIsNotNone(resp_hdr)
            dec = decrypt_body(resp_hdr, resp_body, TEST_SECRET)
            reply = AuthorReply.unpack(dec)
            self.assertEqual(reply.status, TAC_PLUS_AUTHOR_STATUS_PASS_ADD)
        finally:
            await client.close()

    async def test_concurrent_multi_connection_load(self):
        """20 concurrent independent TCP connections firing AAA requests simultaneously."""
        async def client_worker(worker_id: int):
            c = RawTacacsClient(port=TEST_PORT)
            await c.connect()
            try:
                sid = secrets.randbits(32)
                h = TacacsHeader(0x0C, 1, TAC_PLUS_AUTHEN, 1, 0, sid, 0)
                st = AuthenStart(1, 1, TAC_PLUS_AUTHEN_TYPE_PAP, user="operator", data=b"Operator123!").pack()
                await c.send_packet(h, st)
                rh, rb = await c.read_response_raw(timeout=5.0)
                assert rh is not None, f"Worker {worker_id} got None header"
                dec = decrypt_body(rh, rb, TEST_SECRET)
                reply = AuthenReply.unpack(dec)
                assert reply.status == TAC_PLUS_AUTHEN_STATUS_PASS, f"Worker {worker_id} failed authen"
            finally:
                await c.close()

        # Run 20 concurrent connections
        tasks = [asyncio.create_task(client_worker(i)) for i in range(20)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                raise r


if __name__ == "__main__":
    unittest.main()
