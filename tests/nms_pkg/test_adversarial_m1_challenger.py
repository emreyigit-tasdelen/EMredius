# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Adversarial Challenge Test Suite for Milestone M1 Iteration 2.

Empirical verification of:
1. CHAP Authentication with arbitrary, random secrets over the wire.
2. Unauthenticated / Anonymous Authorization rejection (empty user, empty session).
3. Protocol Edge Cases: malformed packets, invalid lengths, boundary conditions.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import string
import struct
import tempfile
import unittest
from typing import List, Optional, Tuple

from nms.common.db import get_db_connection, hash_password, init_db
from nms.tacacs.acct import (
    TAC_PLUS_ACCT_FLAG_START,
    TAC_PLUS_ACCT_FLAG_STOP,
    TAC_PLUS_ACCT_STATUS_ERROR,
    TAC_PLUS_ACCT_STATUS_SUCCESS,
)
from nms.tacacs.authen import (
    TAC_PLUS_AUTHEN_STATUS_ERROR,
    TAC_PLUS_AUTHEN_STATUS_FAIL,
    TAC_PLUS_AUTHEN_STATUS_PASS,
    TAC_PLUS_AUTHEN_SVC_LOGIN,
    TAC_PLUS_AUTHEN_TYPE_CHAP,
)
from nms.tacacs.author import (
    TAC_PLUS_AUTHOR_STATUS_ERROR,
    TAC_PLUS_AUTHOR_STATUS_FAIL,
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
    TAC_PLUS_UNENCRYPTED_FLAG,
    AVPair,
    AcctReply,
    AcctRequest,
    AuthenReply,
    AuthenStart,
    AuthorReply,
    AuthorRequest,
    TacacsHeader,
    unpack_header,
)
from nms.tacacs.crypto import decrypt_body, encrypt_body
from nms.tacacs.server import TacacsServer
from test_tacacs_rfc8907 import TacacsTestClient


class TestAdversarialChapAuthentication(unittest.IsolatedAsyncioTestCase):
    """Adversarial Challenge 1: CHAP Authentication with Arbitrary Random Secrets."""

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp_dir.name, "test_adv_chap.db")
        init_db(self.db_path)

        self.server = TacacsServer(
            host="127.0.0.1",
            port=4955,
            fallback_port=4955,
            db_path=self.db_path,
        )
        await self.server.start()

    async def asyncTearDown(self):
        await self.server.stop()
        await asyncio.sleep(0.05)
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    async def test_chap_arbitrary_random_secrets_matrix(self):
        """Stress-test CHAP authentication across a matrix of randomly generated users and secrets."""
        test_secrets = [
            "X",  # 1 char
            secrets.token_hex(8),  # 16 char hex
            "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32)),  # 32 char
            "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?") for _ in range(64)),  # 64 char symbols
            "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(128)),  # 128 char long
            "Tr-Özêl_Kîmlîk_Döğrulämä_2026!#$%",  # Unicode UTF-8
            "Secret with multiple spaces and numbers 1234567890",  # Spaces
        ]

        for idx, secret in enumerate(test_secrets):
            username = f"rand_user_{idx}_{secrets.token_hex(4)}"
            with get_db_connection(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, enable_password_hash, chap_secret, priv_lvl, enabled)
                    VALUES (?, ?, '', ?, 7, 1)
                    """,
                    (username, hash_password(secret), secret),
                )
                conn.commit()

            chap_id = (idx * 37 + 1) % 256
            challenge = secrets.token_bytes(1 + (idx * 7) % 64)

            client = TacacsTestClient("127.0.0.1", 4955, "testing123")
            await client.connect()
            try:
                status, msg = await client.authenticate_chap(
                    user=username,
                    password=secret,
                    chap_id=chap_id,
                    challenge=challenge,
                )
                self.assertEqual(
                    status,
                    TAC_PLUS_AUTHEN_STATUS_PASS,
                    f"CHAP failed for user {username} with secret of len {len(secret)}: {msg}",
                )
                self.assertIn("Successful", msg)
            finally:
                await client.close()

    async def test_chap_bit_flip_response_fails(self):
        """Adversarial: Flip 1 bit in MD5 response hash. Must FAIL."""
        username = "bitflip_user"
        secret = "StrictSecret123!"
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, enable_password_hash, chap_secret, priv_lvl, enabled)
                VALUES (?, ?, '', ?, 7, 1)
                """,
                (username, hash_password(secret), secret),
            )
            conn.commit()

        client = TacacsTestClient("127.0.0.1", 4955, "testing123")
        await client.connect()
        try:
            chap_id = 42
            challenge = b"randomchallenge123"
            valid_md5 = hashlib.md5(bytes([chap_id]) + secret.encode("utf-8") + challenge).digest()
            corrupted_md5 = valid_md5[:-1] + bytes([valid_md5[-1] ^ 0x01])
            corrupted_chap_data = bytes([chap_id]) + challenge + corrupted_md5

            header = TacacsHeader(
                major_version=TAC_PLUS_MAJOR_VER,
                minor_version=TAC_PLUS_MINOR_VER_ONE,
                type=TAC_PLUS_AUTHEN,
                seq_no=1,
                session_id=client.session_id,
            )
            start = AuthenStart(
                action=1,
                priv_lvl=1,
                authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
                authen_service=TAC_PLUS_AUTHEN_SVC_LOGIN,
                user=username,
                data=corrupted_chap_data,
            )
            resp_hdr, resp_body = await client._send_receive(header, start.pack())
            reply = AuthenReply.unpack(resp_body)

            self.assertEqual(reply.status, TAC_PLUS_AUTHEN_STATUS_FAIL)
            self.assertIn("CHAP Authentication Failed", reply.server_msg)
        finally:
            await client.close()

    async def test_chap_truncated_payload_returns_error(self):
        """Adversarial: Send CHAP data shorter than 18 bytes. Must return STATUS_ERROR."""
        for short_len in (0, 1, 10, 17):
            client = TacacsTestClient("127.0.0.1", 4955, "testing123")
            await client.connect()
            try:
                short_data = b"\x01" * short_len
                header = TacacsHeader(
                    major_version=TAC_PLUS_MAJOR_VER,
                    minor_version=TAC_PLUS_MINOR_VER_ONE,
                    type=TAC_PLUS_AUTHEN,
                    seq_no=1,
                    session_id=client.session_id,
                )
                start = AuthenStart(
                    action=1,
                    priv_lvl=1,
                    authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
                    authen_service=TAC_PLUS_AUTHEN_SVC_LOGIN,
                    user="admin",
                    data=short_data,
                )
                resp_hdr, resp_body = await client._send_receive(header, start.pack())
                reply = AuthenReply.unpack(resp_body)
                self.assertEqual(
                    reply.status,
                    TAC_PLUS_AUTHEN_STATUS_ERROR,
                    f"Expected STATUS_ERROR for payload length {short_len}",
                )
                self.assertIn("too short", reply.server_msg)
            finally:
                await client.close()

    async def test_chap_disabled_user_fails(self):
        """Adversarial: User with valid chap_secret but enabled=0 must FAIL."""
        username = "disabled_user"
        secret = "Secret123!"
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, enable_password_hash, chap_secret, priv_lvl, enabled)
                VALUES (?, ?, '', ?, 7, 0)
                """,
                (username, hash_password(secret), secret),
            )
            conn.commit()

        client = TacacsTestClient("127.0.0.1", 4955, "testing123")
        await client.connect()
        try:
            status, msg = await client.authenticate_chap(username, secret)
            self.assertEqual(status, TAC_PLUS_AUTHEN_STATUS_FAIL)
        finally:
            await client.close()

    async def test_chap_nonexistent_user_fails(self):
        """Adversarial: Non-existent user must FAIL."""
        client = TacacsTestClient("127.0.0.1", 4955, "testing123")
        await client.connect()
        try:
            status, msg = await client.authenticate_chap("ghost_user_does_not_exist", "Secret123!")
            self.assertEqual(status, TAC_PLUS_AUTHEN_STATUS_FAIL)
        finally:
            await client.close()


class TestAdversarialUnauthenticatedAuthorization(unittest.IsolatedAsyncioTestCase):
    """Adversarial Challenge 2: Unauthenticated Authorization (Empty User and Empty Session)."""

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp_dir.name, "test_adv_author.db")
        init_db(self.db_path)

        self.server = TacacsServer(
            host="127.0.0.1",
            port=4956,
            fallback_port=4956,
            db_path=self.db_path,
        )
        await self.server.start()

    async def asyncTearDown(self):
        await self.server.stop()
        await asyncio.sleep(0.05)
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    async def test_empty_user_empty_session_shell_rejected(self):
        """Verify AuthorRequest with user='' and empty session for EXEC shell is rejected and NEVER permitted."""
        client = TacacsTestClient("127.0.0.1", 4956, "testing123")
        await client.connect()
        try:
            status, msg, args = await client.authorize_command(
                user="",
                cmd="",
                args=[],
                priv_lvl=1,
            )
            self.assertEqual(
                status,
                TAC_PLUS_AUTHOR_STATUS_FAIL,
                f"Expected TAC_PLUS_AUTHOR_STATUS_FAIL (0x10), got {status} ({msg})",
            )
            self.assertIn("Anonymous authorization rejected: user required", msg)
            self.assertNotEqual(status, TAC_PLUS_AUTHOR_STATUS_PASS_ADD)
        finally:
            await client.close()

    async def test_empty_user_empty_session_priv15_rejected(self):
        """Verify AuthorRequest with user='' claiming priv_lvl=15 is rejected and NEVER permitted."""
        client = TacacsTestClient("127.0.0.1", 4956, "testing123")
        await client.connect()
        try:
            status, msg, args = await client.authorize_command(
                user="",
                cmd="",
                args=[],
                priv_lvl=15,
            )
            self.assertEqual(status, TAC_PLUS_AUTHOR_STATUS_FAIL)
            self.assertIn("Anonymous authorization rejected: user required", msg)
            self.assertNotEqual(status, TAC_PLUS_AUTHOR_STATUS_PASS_ADD)
        finally:
            await client.close()

    async def test_empty_user_empty_session_command_rejected(self):
        """Verify AuthorRequest with user='' requesting commands is rejected and NEVER permitted."""
        client = TacacsTestClient("127.0.0.1", 4956, "testing123", single_connect=True)
        await client.connect()
        try:
            commands_to_test = [
                ("show", ["version"]),
                ("ping", ["127.0.0.1"]),
                ("reload", []),
                ("configure", ["terminal"]),
                ("format", ["flash:"]),
            ]
            for cmd, args in commands_to_test:
                status, msg, resp_args = await client.authorize_command(
                    user="",
                    cmd=cmd,
                    args=args,
                    priv_lvl=15,
                )
                self.assertEqual(
                    status,
                    TAC_PLUS_AUTHOR_STATUS_FAIL,
                    f"Anonymous execution of '{cmd}' was not rejected! Got status: {status}",
                )
                self.assertIn("Anonymous authorization rejected: user required", msg)
                self.assertNotEqual(status, TAC_PLUS_AUTHOR_STATUS_PASS_ADD)
        finally:
            await client.close()

    async def test_empty_user_multiplexed_session_isolation(self):
        """Verify that in single connection mode, an authenticated session does not leak username to a fresh session with user=''."""
        client = TacacsTestClient("127.0.0.1", 4956, "testing123", single_connect=True)
        await client.connect()
        try:
            # 1. First authenticate as operator
            client.session_id = secrets.randbits(32)
            auth_status, _ = await client.authenticate_pap("operator", "Operator123!")
            self.assertEqual(auth_status, TAC_PLUS_AUTHEN_STATUS_PASS)

            # 2. Next, start a new session ID for authorization with user=''
            client.session_id = secrets.randbits(32)
            author_status, msg, _ = await client.authorize_command(
                user="",
                cmd="show",
                args=["version"],
                priv_lvl=7,
            )
            self.assertEqual(author_status, TAC_PLUS_AUTHOR_STATUS_FAIL)
            self.assertIn("Anonymous authorization rejected", msg)
            self.assertNotEqual(author_status, TAC_PLUS_AUTHOR_STATUS_PASS_ADD)
        finally:
            await client.close()


class TestAdversarialProtocolEdgeCases(unittest.IsolatedAsyncioTestCase):
    """Adversarial Challenge 3: Edge Cases, Malformed Packets, and Boundary Conditions."""

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp_dir.name, "test_adv_edge.db")
        init_db(self.db_path)

        self.server = TacacsServer(
            host="127.0.0.1",
            port=4957,
            fallback_port=4957,
            db_path=self.db_path,
        )
        await self.server.start()

    async def asyncTearDown(self):
        await self.server.stop()
        await asyncio.sleep(0.05)
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    async def test_unencrypted_flag_packet_dropped(self):
        """Packets with TAC_PLUS_UNENCRYPTED_FLAG (0x01) must be rejected/dropped."""
        reader, writer = await asyncio.open_connection("127.0.0.1", 4957)
        try:
            header = TacacsHeader(
                major_version=TAC_PLUS_MAJOR_VER,
                minor_version=TAC_PLUS_MINOR_VER_DEFAULT,
                type=TAC_PLUS_AUTHEN,
                seq_no=1,
                flags=TAC_PLUS_UNENCRYPTED_FLAG,
                session_id=12345,
                length=10,
            )
            writer.write(header.pack() + b"0123456789")
            await writer.drain()

            # Server drops connection immediately
            resp = await reader.read(1024)
            self.assertEqual(resp, b"", "Server should close connection on unencrypted packet")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_invalid_major_version_dropped(self):
        """Packets with major version != 12 (RFC 8907 §4.1) must be dropped."""
        for bad_ver in (0, 1, 11, 13, 15):
            reader, writer = await asyncio.open_connection("127.0.0.1", 4957)
            try:
                header = TacacsHeader(
                    major_version=bad_ver,
                    minor_version=0,
                    type=TAC_PLUS_AUTHEN,
                    seq_no=1,
                    flags=0,
                    session_id=999,
                    length=0,
                )
                writer.write(header.pack())
                await writer.drain()

                resp = await reader.read(1024)
                self.assertEqual(resp, b"", f"Server should drop connection for bad major ver {bad_ver}")
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def test_packet_exceeding_max_length_dropped(self):
        """Header with length > MAX_PACKET_LENGTH (65536) must be dropped immediately."""
        reader, writer = await asyncio.open_connection("127.0.0.1", 4957)
        try:
            header = TacacsHeader(
                major_version=TAC_PLUS_MAJOR_VER,
                minor_version=0,
                type=TAC_PLUS_AUTHEN,
                seq_no=1,
                flags=0,
                session_id=1010,
                length=65537,
            )
            writer.write(header.pack())
            await writer.drain()

            resp = await reader.read(1024)
            self.assertEqual(resp, b"", "Server should drop connection on oversize packet length")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_corrupted_decryption_secret_drops_connection(self):
        """Sending packet encrypted with wrong shared secret fails integrity and drops connection."""
        reader, writer = await asyncio.open_connection("127.0.0.1", 4957)
        try:
            header = TacacsHeader(
                major_version=TAC_PLUS_MAJOR_VER,
                minor_version=TAC_PLUS_MINOR_VER_DEFAULT,
                type=TAC_PLUS_AUTHEN,
                seq_no=1,
                flags=0,
                session_id=5555,
                length=0,
            )
            start = AuthenStart(
                action=1,
                priv_lvl=1,
                authen_type=1,
                authen_service=1,
                user="admin",
            )
            plain_body = start.pack()
            enc_body = encrypt_body(header, plain_body, "completely_wrong_secret_12345")
            header.length = len(enc_body)
            writer.write(header.pack() + enc_body)
            await writer.drain()

            # Server fails decryption integrity check and immediately drops connection
            resp = await reader.read(1024)
            self.assertEqual(resp, b"", "Server should drop connection when decryption integrity fails")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_malformed_truncated_body_drops_connection(self):
        """Sending truncated body failing subfield length check must fail integrity and drop connection."""
        reader, writer = await asyncio.open_connection("127.0.0.1", 4957)
        try:
            header = TacacsHeader(
                major_version=TAC_PLUS_MAJOR_VER,
                minor_version=TAC_PLUS_MINOR_VER_DEFAULT,
                type=TAC_PLUS_AUTHOR,
                seq_no=1,
                flags=0,
                session_id=7777,
                length=0,
            )
            garbage_body = b"\x00\x01\x02\x03"
            enc_body = encrypt_body(header, garbage_body, "testing123")
            header.length = len(enc_body)
            writer.write(header.pack() + enc_body)
            await writer.drain()

            # Server fails subfield length integrity check and drops connection
            resp = await reader.read(1024)
            self.assertEqual(resp, b"", "Server should drop connection on truncated/malformed body")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_accounting_flag_collision_rejected(self):
        """Flag collision 0x06 (START | STOP) must be rejected with TAC_PLUS_ACCT_STATUS_ERROR."""
        client = TacacsTestClient("127.0.0.1", 4957, "testing123")
        await client.connect()
        try:
            status, msg = await client.account_command(
                "operator",
                "show",
                ["version"],
                flags=(TAC_PLUS_ACCT_FLAG_START | TAC_PLUS_ACCT_FLAG_STOP),
            )
            self.assertEqual(status, TAC_PLUS_ACCT_STATUS_ERROR)
            self.assertIn("Invalid accounting flags", msg)
        finally:
            await client.close()

    async def test_large_command_arguments_boundary(self):
        """Test boundary conditions with multiple max-length 255-byte arguments totaling 2040 bytes."""
        client = TacacsTestClient("127.0.0.1", 4957, "testing123")
        await client.connect()
        try:
            # 8 arguments of 240 bytes each (+ 8 bytes "cmd-arg=" prefix = 248 bytes, <= 255)
            args = ["B" * 240 for _ in range(8)]
            status, msg, resp_args = await client.authorize_command(
                user="admin",
                cmd="show",
                args=args,
                priv_lvl=15,
            )
            self.assertEqual(status, TAC_PLUS_AUTHOR_STATUS_PASS_ADD)
        finally:
            await client.close()


if __name__ == "__main__":
    unittest.main()
