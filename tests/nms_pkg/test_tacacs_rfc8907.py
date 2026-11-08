# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Comprehensive RFC 8907 TACACS+ Unit and Acceptance Test Suite.

Tests:
1. SQLite WAL database connection, schema, idempotent seeding, models.
2. 12-byte header packing/unpacking and AV-pair parser.
3. RFC 8907 §4.5 MD5 pad generation, XOR stream cipher, and length summation integrity.
4. Authentication state machines (ASCII interactive, PAP, CHAP, ENABLE).
5. Command authorization (command reconstruction, regex allow/deny, priority, vendor AV-pairs).
6. Accounting processor (flag validation, 0x06 collision rejection, atomic WAL persistence).
7. Async TCP daemon (single-connection multiplexing, LPM secret resolution, WAL heartbeat).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import sqlite3
import tempfile
import time
import unittest
from typing import Any, List, Optional, Tuple

from nms.common.db import get_db_connection, hash_password, init_db, verify_password
from nms.common.models import (
    DaemonStatus,
    Group,
    TacacsAccountingRecord,
    TacacsClient,
    TacacsRule,
    User,
)
from nms.tacacs.acct import (
    AccountingProcessor,
    TAC_PLUS_ACCT_FLAG_START,
    TAC_PLUS_ACCT_FLAG_STOP,
    TAC_PLUS_ACCT_FLAG_WATCHDOG,
    TAC_PLUS_ACCT_STATUS_ERROR,
    TAC_PLUS_ACCT_STATUS_SUCCESS,
)
from nms.tacacs.authen import (
    TAC_PLUS_AUTHEN_STATUS_ERROR,
    TAC_PLUS_AUTHEN_STATUS_FAIL,
    TAC_PLUS_AUTHEN_STATUS_GETPASS,
    TAC_PLUS_AUTHEN_STATUS_GETUSER,
    TAC_PLUS_AUTHEN_STATUS_PASS,
    TAC_PLUS_AUTHEN_SVC_ENABLE,
    TAC_PLUS_AUTHEN_SVC_LOGIN,
    TAC_PLUS_AUTHEN_TYPE_ASCII,
    TAC_PLUS_AUTHEN_TYPE_CHAP,
    TAC_PLUS_AUTHEN_TYPE_PAP,
    TAC_PLUS_CONTINUE_FLAG_ABORT,
)
from nms.tacacs.author import (
    TAC_PLUS_AUTHOR_STATUS_FAIL,
    TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
    RegexPolicyEngine,
    build_vendor_shell_av_pairs,
    reconstruct_command_line,
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
    generate_md5_pad,
    generate_pad,
    validate_body_integrity,
    xor_bytes,
)
from nms.tacacs.server import ClientSecretResolver, TacacsServer


class TacacsTestClient:
    """Simulated Network Device Client for Automated RFC 8907 Testing."""

    def __init__(self, host: str, port: int, secret: str, single_connect: bool = False):
        self.host = host
        self.port = port
        self.secret = secret
        self.single_connect = single_connect
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.session_id = secrets.randbits(32)

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

    async def close(self) -> None:
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass

    async def _send_receive(
        self, header: TacacsHeader, plain_body: bytes
    ) -> Tuple[TacacsHeader, bytes]:
        if not self.writer or not self.reader:
            raise RuntimeError("Client not connected")

        if self.single_connect and header.seq_no == 1:
            header.flags |= TAC_PLUS_SINGLE_CONNECT_FLAG

        enc_body = encrypt_body(header, plain_body, self.secret)
        header.length = len(enc_body)
        self.writer.write(header.pack() + enc_body)
        await self.writer.drain()

        resp_hdr_bytes = await self.reader.readexactly(12)
        resp_hdr = unpack_header(resp_hdr_bytes)

        resp_body_enc = b""
        if resp_hdr.length > 0:
            resp_body_enc = await self.reader.readexactly(resp_hdr.length)

        resp_body = decrypt_body(resp_hdr, resp_body_enc, self.secret)
        if resp_body is None:
            raise ValueError("Response decryption or integrity check failed")
        return resp_hdr, resp_body

    async def authenticate_pap(self, user: str, password: str) -> Tuple[int, str]:
        header = TacacsHeader(
            major_version=TAC_PLUS_MAJOR_VER,
            minor_version=TAC_PLUS_MINOR_VER_ONE,
            type=TAC_PLUS_AUTHEN,
            seq_no=1,
            flags=0,
            session_id=self.session_id,
            length=0,
        )
        start = AuthenStart(
            action=1,
            priv_lvl=1,
            authen_type=TAC_PLUS_AUTHEN_TYPE_PAP,
            authen_service=TAC_PLUS_AUTHEN_SVC_LOGIN,
            user=user,
            port="vty0",
            rem_addr="10.0.0.5",
            data=password.encode("utf-8"),
        )
        resp_hdr, resp_body = await self._send_receive(header, start.pack())
        reply = AuthenReply.unpack(resp_body)
        return reply.status, reply.server_msg

    async def authenticate_ascii_full(self, user: str, password: str) -> Tuple[int, str]:
        header = TacacsHeader(
            major_version=TAC_PLUS_MAJOR_VER,
            minor_version=TAC_PLUS_MINOR_VER_DEFAULT,
            type=TAC_PLUS_AUTHEN,
            seq_no=1,
            flags=0,
            session_id=self.session_id,
            length=0,
        )
        # Step 1: START with empty username
        start = AuthenStart(
            action=1,
            priv_lvl=1,
            authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII,
            authen_service=TAC_PLUS_AUTHEN_SVC_LOGIN,
            user="",
        )
        resp_hdr, resp_body = await self._send_receive(header, start.pack())
        reply1 = AuthenReply.unpack(resp_body)
        if reply1.status != TAC_PLUS_AUTHEN_STATUS_GETUSER:
            return reply1.status, reply1.server_msg

        # Step 2: CONTINUE with username
        cont1 = AuthenContinue(user_msg=user, flags=0)
        hdr2 = TacacsHeader(
            major_version=TAC_PLUS_MAJOR_VER,
            minor_version=TAC_PLUS_MINOR_VER_DEFAULT,
            type=TAC_PLUS_AUTHEN,
            seq_no=3,
            flags=0,
            session_id=self.session_id,
            length=0,
        )
        resp_hdr, resp_body = await self._send_receive(hdr2, cont1.pack())
        reply2 = AuthenReply.unpack(resp_body)
        if reply2.status != TAC_PLUS_AUTHEN_STATUS_GETPASS:
            return reply2.status, reply2.server_msg

        # Step 3: CONTINUE with password
        cont2 = AuthenContinue(user_msg=password, flags=0)
        hdr3 = TacacsHeader(
            major_version=TAC_PLUS_MAJOR_VER,
            minor_version=TAC_PLUS_MINOR_VER_DEFAULT,
            type=TAC_PLUS_AUTHEN,
            seq_no=5,
            flags=0,
            session_id=self.session_id,
            length=0,
        )
        resp_hdr, resp_body = await self._send_receive(hdr3, cont2.pack())
        reply3 = AuthenReply.unpack(resp_body)
        return reply3.status, reply3.server_msg

    async def authenticate_ascii_abort(self) -> Tuple[int, str]:
        header = TacacsHeader(
            major_version=TAC_PLUS_MAJOR_VER,
            minor_version=TAC_PLUS_MINOR_VER_DEFAULT,
            type=TAC_PLUS_AUTHEN,
            seq_no=1,
            flags=0,
            session_id=self.session_id,
            length=0,
        )
        start = AuthenStart(
            action=1,
            priv_lvl=1,
            authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII,
            authen_service=TAC_PLUS_AUTHEN_SVC_LOGIN,
            user="",
        )
        resp_hdr, resp_body = await self._send_receive(header, start.pack())

        cont = AuthenContinue(user_msg="", flags=TAC_PLUS_CONTINUE_FLAG_ABORT)
        hdr2 = TacacsHeader(
            major_version=TAC_PLUS_MAJOR_VER,
            minor_version=TAC_PLUS_MINOR_VER_DEFAULT,
            type=TAC_PLUS_AUTHEN,
            seq_no=3,
            flags=0,
            session_id=self.session_id,
            length=0,
        )
        resp_hdr, resp_body = await self._send_receive(hdr2, cont.pack())
        reply = AuthenReply.unpack(resp_body)
        return reply.status, reply.server_msg

    async def authenticate_chap(
        self, user: str, password: str, chap_id: int = 1, challenge: bytes = b"testchal1234"
    ) -> Tuple[int, str]:
        header = TacacsHeader(
            major_version=TAC_PLUS_MAJOR_VER,
            minor_version=TAC_PLUS_MINOR_VER_ONE,
            type=TAC_PLUS_AUTHEN,
            seq_no=1,
            flags=0,
            session_id=self.session_id,
            length=0,
        )
        # Expected response: MD5(chap_id + password + challenge)
        expected_md5 = hashlib.md5(bytes([chap_id]) + password.encode("utf-8") + challenge).digest()
        chap_data = bytes([chap_id]) + challenge + expected_md5

        start = AuthenStart(
            action=1,
            priv_lvl=1,
            authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
            authen_service=TAC_PLUS_AUTHEN_SVC_LOGIN,
            user=user,
            data=chap_data,
        )
        resp_hdr, resp_body = await self._send_receive(header, start.pack())
        reply = AuthenReply.unpack(resp_body)
        return reply.status, reply.server_msg

    async def authenticate_enable(self, user: str, enable_password: str, priv_lvl: int = 15) -> Tuple[int, str]:
        header = TacacsHeader(
            major_version=TAC_PLUS_MAJOR_VER,
            minor_version=TAC_PLUS_MINOR_VER_DEFAULT,
            type=TAC_PLUS_AUTHEN,
            seq_no=1,
            flags=0,
            session_id=self.session_id,
            length=0,
        )
        start = AuthenStart(
            action=1,
            priv_lvl=priv_lvl,
            authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII,
            authen_service=TAC_PLUS_AUTHEN_SVC_ENABLE,
            user=user,
        )
        resp_hdr, resp_body = await self._send_receive(header, start.pack())
        reply1 = AuthenReply.unpack(resp_body)
        if reply1.status != TAC_PLUS_AUTHEN_STATUS_GETPASS:
            return reply1.status, reply1.server_msg

        cont = AuthenContinue(user_msg=enable_password, flags=0)
        hdr2 = TacacsHeader(
            major_version=TAC_PLUS_MAJOR_VER,
            minor_version=TAC_PLUS_MINOR_VER_DEFAULT,
            type=TAC_PLUS_AUTHEN,
            seq_no=3,
            flags=0,
            session_id=self.session_id,
            length=0,
        )
        resp_hdr, resp_body = await self._send_receive(hdr2, cont.pack())
        reply2 = AuthenReply.unpack(resp_body)
        return reply2.status, reply2.server_msg

    async def authorize_command(
        self, user: str, cmd: str, args: List[str], priv_lvl: int = 1
    ) -> Tuple[int, str, List[AVPair]]:
        self.session_id = secrets.randbits(32)
        header = TacacsHeader(
            major_version=TAC_PLUS_MAJOR_VER,
            minor_version=TAC_PLUS_MINOR_VER_DEFAULT,
            type=TAC_PLUS_AUTHOR,
            seq_no=1,
            flags=0,
            session_id=self.session_id,
            length=0,
        )
        av_list = [AVPair("service", "=", "shell")]
        if cmd:
            av_list.append(AVPair("cmd", "=", cmd))
            for a in args:
                av_list.append(AVPair("cmd-arg", "=", a))

        req = AuthorRequest(
            priv_lvl=priv_lvl,
            user=user,
            port="vty0",
            rem_addr="10.0.0.5",
            args=av_list,
        )
        resp_hdr, resp_body = await self._send_receive(header, req.pack())
        reply = AuthorReply.unpack(resp_body)
        return reply.status, reply.server_msg, reply.args

    async def account_command(
        self,
        user: str,
        cmd: str,
        args: List[str],
        flags: int = TAC_PLUS_ACCT_FLAG_START,
        priv_lvl: int = 1,
        extra_av_pairs: Optional[List[AVPair]] = None,
    ) -> Tuple[int, str]:
        header = TacacsHeader(
            major_version=TAC_PLUS_MAJOR_VER,
            minor_version=TAC_PLUS_MINOR_VER_DEFAULT,
            type=TAC_PLUS_ACCT,
            seq_no=1,
            flags=0,
            session_id=self.session_id,
            length=0,
        )
        av_list = [AVPair("service", "=", "shell")]
        if cmd:
            av_list.append(AVPair("cmd", "=", cmd))
            for a in args:
                av_list.append(AVPair("cmd-arg", "=", a))
        if extra_av_pairs:
            av_list.extend(extra_av_pairs)

        req = AcctRequest(
            flags=flags,
            priv_lvl=priv_lvl,
            user=user,
            port="vty0",
            rem_addr="10.0.0.5",
            args=av_list,
        )
        resp_hdr, resp_body = await self._send_receive(header, req.pack())
        reply = AcctReply.unpack(resp_body)
        return reply.status, reply.server_msg


# =====================================================================
# Unit & Acceptance Test Classes
# =====================================================================

class TestDatabaseAndModels(unittest.TestCase):
    """Test Suite 1: SQLite WAL, Pragma Settings, Models, and Seeding."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp_dir.name, "test_db.db")
        init_db(self.db_path)

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_wal_pragma_configured(self):
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            mode = cursor.fetchone()[0]
            self.assertEqual(mode.lower(), "wal")

            cursor.execute("PRAGMA foreign_keys;")
            fk = cursor.fetchone()[0]
            self.assertEqual(fk, 1)

    def test_default_seeding(self):
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()

            # Groups
            cursor.execute("SELECT name, priv_lvl FROM groups ORDER BY priv_lvl DESC")
            groups = [(r["name"], r["priv_lvl"]) for r in cursor.fetchall()]
            self.assertIn(("admin", 15), groups)
            self.assertIn(("operator", 7), groups)
            self.assertIn(("helpdesk", 1), groups)

            # Users
            cursor.execute("SELECT username, priv_lvl, enabled, chap_secret FROM users")
            users = {r["username"]: (r["priv_lvl"], r["enabled"], r["chap_secret"]) for r in cursor.fetchall()}
            self.assertIn("admin", users)
            self.assertEqual(users["admin"], (15, 1, "Admin123!"))
            self.assertIn("operator", users)
            self.assertEqual(users["operator"], (7, 1, "Operator123!"))
            self.assertIn("helpdesk", users)
            self.assertEqual(users["helpdesk"], (1, 1, "Guest123!"))

            # Rules
            cursor.execute("SELECT pattern, action FROM tacacs_rules")
            rules = [(r["pattern"], r["action"]) for r in cursor.fetchall()]
            self.assertTrue(any("show" in p for p, a in rules))
            self.assertTrue(any("reload" in p for p, a in rules))

            # Default client
            cursor.execute("SELECT ip_cidr, shared_secret FROM tacacs_clients WHERE ip_cidr = '127.0.0.1/32'")
            client = cursor.fetchone()
            self.assertIsNotNone(client)
            self.assertEqual(client["shared_secret"], "testing123")

    def test_database_migration_adds_chap_secret(self):
        """Tests that idempotent migration adds chap_secret column to legacy database."""
        legacy_db = os.path.join(self.tmp_dir.name, "legacy_test.db")
        # Create legacy table without chap_secret column
        conn = sqlite3.connect(legacy_db)
        conn.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(64) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                enable_password_hash VARCHAR(255) DEFAULT '',
                priv_lvl INTEGER DEFAULT 1,
                group_id INTEGER,
                enabled BOOLEAN NOT NULL DEFAULT 1
            );
            """
        )
        conn.execute(
            "INSERT INTO users (username, password_hash, priv_lvl) VALUES ('legacy_user', 'hash123', 5);"
        )
        conn.commit()
        conn.close()

        # Run init_db which should execute the migration
        init_db(legacy_db)

        # Verify chap_secret column now exists
        with get_db_connection(legacy_db) as conn2:
            cursor = conn2.cursor()
            cursor.execute("PRAGMA table_info(users);")
            cols = [r["name"] for r in cursor.fetchall()]
            self.assertIn("chap_secret", cols)

            # Verify existing row can be queried and has empty chap_secret default
            cursor.execute("SELECT username, chap_secret FROM users WHERE username = 'legacy_user'")
            row = cursor.fetchone()
            self.assertEqual(row["chap_secret"], "")

        # Verify second init_db call is idempotent
        init_db(legacy_db)

    def test_password_hashing(self):
        h = hash_password("SuperSecret1!")
        self.assertTrue(h.startswith("pbkdf2:sha256:100000$"))
        self.assertTrue(verify_password("SuperSecret1!", h))
        self.assertFalse(verify_password("WrongSecret!", h))

    def test_models_serialization(self):
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = 'admin'")
            row = cursor.fetchone()
            user = User.from_row(row)
            self.assertEqual(user.username, "admin")
            self.assertEqual(user.priv_lvl, 15)
            self.assertEqual(user.chap_secret, "Admin123!")
            self.assertIn("username", user.to_dict())
            self.assertIn("chap_secret", user.to_dict())

    def test_user_model_chap_secret_serialization(self):
        """Tests User model dataclass, to_dict, and from_row with chap_secret and fallback."""
        u = User(username="test_user", chap_secret="my_super_secret")
        d = u.to_dict()
        self.assertEqual(d["username"], "test_user")
        self.assertEqual(d["chap_secret"], "my_super_secret")

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = 'admin'")
            row = cursor.fetchone()
            user_from_db = User.from_row(row)
            self.assertEqual(user_from_db.username, "admin")
            self.assertEqual(user_from_db.chap_secret, "Admin123!")

            # Verify safe fallback when chap_secret is not in row keys
            cursor.execute("SELECT id, username, password_hash, priv_lvl, group_id, enabled FROM users WHERE username = 'admin'")
            partial_row = cursor.fetchone()
            partial_user = User.from_row(partial_row)
            self.assertEqual(partial_user.chap_secret, "")


class TestCodecAndCrypto(unittest.TestCase):
    """Test Suite 2: Codec Header/Body Packing and RFC 8907 §4.5 MD5 Pad Crypto."""

    def test_header_pack_unpack(self):
        hdr = TacacsHeader(
            major_version=12,
            minor_version=0,
            type=1,
            seq_no=1,
            flags=4,
            session_id=0xDEADBEEF,
            length=128,
        )
        raw = hdr.pack()
        self.assertEqual(len(raw), 12)
        parsed = unpack_header(raw)
        self.assertEqual(parsed.major_version, 12)
        self.assertEqual(parsed.minor_version, 0)
        self.assertEqual(parsed.type, 1)
        self.assertEqual(parsed.seq_no, 1)
        self.assertEqual(parsed.flags, 4)
        self.assertEqual(parsed.session_id, 0xDEADBEEF)
        self.assertEqual(parsed.length, 128)

    def test_av_pair_parsing(self):
        p1 = AVPair.parse("service=shell")
        self.assertEqual(p1.name, "service")
        self.assertEqual(p1.separator, "=")
        self.assertEqual(p1.value, "shell")
        self.assertTrue(p1.is_mandatory)

        p2 = AVPair.parse("cmd*ping")
        self.assertEqual(p2.name, "cmd")
        self.assertEqual(p2.separator, "*")
        self.assertEqual(p2.value, "ping")
        self.assertFalse(p2.is_mandatory)

        # Embedded equals sign in value
        p3 = AVPair.parse("cmd-arg=interface=Gi0/1")
        self.assertEqual(p3.name, "cmd-arg")
        self.assertEqual(p3.value, "interface=Gi0/1")

    def test_body_codecs_roundtrip(self):
        # 1. AuthenStart
        start = AuthenStart(1, 15, 1, 1, "testuser", "tty0", "1.1.1.1", b"data123")
        start_raw = start.pack()
        start_unpacked = AuthenStart.unpack(start_raw)
        self.assertEqual(start_unpacked.user, "testuser")
        self.assertEqual(start_unpacked.data, b"data123")

        # 2. AuthenReply
        reply = AuthenReply(1, 1, "Welcome", b"d")
        reply_unpacked = AuthenReply.unpack(reply.pack())
        self.assertEqual(reply_unpacked.server_msg, "Welcome")
        self.assertEqual(reply_unpacked.status, 1)

        # 3. AuthenContinue
        cont = AuthenContinue("pass123", b"d", 0)
        cont_unpacked = AuthenContinue.unpack(cont.pack())
        self.assertEqual(cont_unpacked.user_msg, "pass123")

        # 4. AuthorRequest
        req = AuthorRequest(1, 15, 1, 1, "admin", "vty0", "2.2.2.2", [AVPair("service", "=", "shell")])
        req_unpacked = AuthorRequest.unpack(req.pack())
        self.assertEqual(req_unpacked.user, "admin")
        self.assertEqual(len(req_unpacked.args), 1)

        # 5. AuthorReply
        areply = AuthorReply(1, "Permitted", b"", [AVPair("priv-lvl", "=", "15")])
        areply_unpacked = AuthorReply.unpack(areply.pack())
        self.assertEqual(areply_unpacked.status, 1)
        self.assertEqual(len(areply_unpacked.args), 1)

        # 6. AcctRequest
        acct = AcctRequest(2, 1, 1, 1, 1, "oper", "vty1", "3.3.3.3", [AVPair("cmd", "=", "show")])
        acct_unpacked = AcctRequest.unpack(acct.pack())
        self.assertEqual(acct_unpacked.flags, 2)
        self.assertEqual(acct_unpacked.user, "oper")

        # 7. AcctReply
        acre = AcctReply(1, "Logged", b"")
        acre_unpacked = AcctReply.unpack(acre.pack())
        self.assertEqual(acre_unpacked.status, 1)
        self.assertEqual(acre_unpacked.server_msg, "Logged")

    def test_md5_pad_and_xor_symmetry(self):
        hdr = TacacsHeader(12, 0, 1, 1, 0, 0x12345678, 48)
        pad = generate_md5_pad(hdr, "testing123", 48)
        self.assertEqual(len(pad), 48)

        data = b"Enterprise TACACS+ Secret Payload 1234567890ABC"
        cipher = xor_bytes(data, pad[: len(data)])
        plain = xor_bytes(cipher, pad[: len(data)])
        self.assertEqual(plain, data)

    def test_wrong_secret_integrity_rejection(self):
        hdr = TacacsHeader(12, 0, TAC_PLUS_AUTHEN, 1, 0, 0x11223344, 0)
        start = AuthenStart(1, 1, 1, 1, "admin", "vty", "127.0.0.1", b"")
        body_bytes = start.pack()
        hdr.length = len(body_bytes)

        # Encrypt with key A
        enc_body = encrypt_body(hdr, body_bytes, "secretA")

        # Decrypt with wrong key B
        dec_body = decrypt_body(hdr, enc_body, "wrongSecretB")
        self.assertIsNone(dec_body)


class TestAsyncTacacsServerAndAAA(unittest.IsolatedAsyncioTestCase):
    """Test Suite 3: End-to-End Async TCP Server and AAA State Machines."""

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp_dir.name, "test_enterprise.db")
        init_db(self.db_path)

        # Use unprivileged port 4949 for testing
        self.server = TacacsServer(
            host="127.0.0.1",
            port=4949,
            fallback_port=4949,
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

    # --- Authentication Tests ---
    async def test_pap_authentication_pass(self):
        client = TacacsTestClient("127.0.0.1", 4949, "testing123")
        await client.connect()
        try:
            status, msg = await client.authenticate_pap("admin", "Admin123!")
            self.assertEqual(status, TAC_PLUS_AUTHEN_STATUS_PASS)
            self.assertIn("Successful", msg)
        finally:
            await client.close()

    async def test_pap_authentication_fail(self):
        client = TacacsTestClient("127.0.0.1", 4949, "testing123")
        await client.connect()
        try:
            status, msg = await client.authenticate_pap("admin", "WrongPassword!")
            self.assertEqual(status, TAC_PLUS_AUTHEN_STATUS_FAIL)
        finally:
            await client.close()

    async def test_ascii_interactive_login(self):
        client = TacacsTestClient("127.0.0.1", 4949, "testing123")
        await client.connect()
        try:
            status, msg = await client.authenticate_ascii_full("operator", "Operator123!")
            self.assertEqual(status, TAC_PLUS_AUTHEN_STATUS_PASS)
            self.assertIn("successful", msg)
        finally:
            await client.close()

    async def test_ascii_abort(self):
        client = TacacsTestClient("127.0.0.1", 4949, "testing123")
        await client.connect()
        try:
            status, msg = await client.authenticate_ascii_abort()
            self.assertEqual(status, TAC_PLUS_AUTHEN_STATUS_FAIL)
            self.assertIn("aborted", msg)
        finally:
            await client.close()

    async def test_chap_authentication_pass(self):
        client = TacacsTestClient("127.0.0.1", 4949, "testing123")
        await client.connect()
        try:
            status, msg = await client.authenticate_chap("admin", "Admin123!")
            self.assertEqual(status, TAC_PLUS_AUTHEN_STATUS_PASS)
            self.assertIn("Successful", msg)
        finally:
            await client.close()

    async def test_chap_authentication_fail(self):
        client = TacacsTestClient("127.0.0.1", 4949, "testing123")
        await client.connect()
        try:
            status, msg = await client.authenticate_chap("admin", "WrongChapPassword!")
            self.assertEqual(status, TAC_PLUS_AUTHEN_STATUS_FAIL)
        finally:
            await client.close()

    async def test_chap_authentication_arbitrary_user_with_chap_secret(self):
        """Tests CHAP succeeds for an arbitrary production user with chap_secret (not hardcoded)."""
        custom_user = "arbitrary_user_2026"
        custom_secret = "RandomNonStandardSecret#987654321!"
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, enable_password_hash, chap_secret, priv_lvl, enabled)
                VALUES (?, ?, '', ?, 7, 1)
                """,
                (custom_user, hash_password(custom_secret), custom_secret),
            )
            conn.commit()

        client = TacacsTestClient("127.0.0.1", 4949, "testing123")
        await client.connect()
        try:
            status, msg = await client.authenticate_chap(custom_user, custom_secret)
            self.assertEqual(status, TAC_PLUS_AUTHEN_STATUS_PASS)
            self.assertIn("Successful", msg)
        finally:
            await client.close()

    async def test_chap_authentication_fail_pbkdf2_without_chap_secret(self):
        """Tests CHAP fails gracefully when only PBKDF2 hash exists and chap_secret is empty."""
        pbkdf2_user = "only_pbkdf2_user"
        secret = "SecretWithoutChap123!"
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, enable_password_hash, chap_secret, priv_lvl, enabled)
                VALUES (?, ?, '', '', 7, 1)
                """,
                (pbkdf2_user, hash_password(secret)),
            )
            conn.commit()

        client = TacacsTestClient("127.0.0.1", 4949, "testing123")
        await client.connect()
        try:
            status, msg = await client.authenticate_chap(pbkdf2_user, secret)
            self.assertEqual(status, TAC_PLUS_AUTHEN_STATUS_FAIL)
            self.assertIn("requires chap_secret", msg)
        finally:
            await client.close()

    async def test_enable_privilege_escalation(self):
        client = TacacsTestClient("127.0.0.1", 4949, "testing123")
        await client.connect()
        try:
            status, msg = await client.authenticate_enable("admin", "Enable123!", priv_lvl=15)
            self.assertEqual(status, TAC_PLUS_AUTHEN_STATUS_PASS)
            self.assertIn("successful", msg)
        finally:
            await client.close()

    async def test_enable_escalation_fail(self):
        client = TacacsTestClient("127.0.0.1", 4949, "testing123")
        await client.connect()
        try:
            status, msg = await client.authenticate_enable("admin", "BadEnablePass!", priv_lvl=15)
            self.assertEqual(status, TAC_PLUS_AUTHEN_STATUS_FAIL)
        finally:
            await client.close()

    # --- Authorization Tests ---
    async def test_command_authorization_permit_diagnostic(self):
        client = TacacsTestClient("127.0.0.1", 4949, "testing123", single_connect=True)
        await client.connect()
        try:
            # Operator running 'show version'
            status, msg, _ = await client.authorize_command("operator", "show", ["version"], priv_lvl=7)
            self.assertEqual(status, TAC_PLUS_AUTHOR_STATUS_PASS_ADD)

            # Operator running 'ping 10.0.0.1'
            status, msg, _ = await client.authorize_command("operator", "ping", ["10.0.0.1"], priv_lvl=7)
            self.assertEqual(status, TAC_PLUS_AUTHOR_STATUS_PASS_ADD)
        finally:
            await client.close()

    async def test_command_authorization_deny_destructive(self):
        client = TacacsTestClient("127.0.0.1", 4949, "testing123", single_connect=True)
        await client.connect()
        try:
            # reload command denied
            status, msg, _ = await client.authorize_command("operator", "reload", [], priv_lvl=7)
            self.assertEqual(status, TAC_PLUS_AUTHOR_STATUS_FAIL)

            # format flash: denied
            status, msg, _ = await client.authorize_command("operator", "format", ["flash:"], priv_lvl=7)
            self.assertEqual(status, TAC_PLUS_AUTHOR_STATUS_FAIL)

            # erase startup-config denied
            status, msg, _ = await client.authorize_command("operator", "erase", ["startup-config"], priv_lvl=7)
            self.assertEqual(status, TAC_PLUS_AUTHOR_STATUS_FAIL)

            # configure terminal denied
            status, msg, _ = await client.authorize_command("operator", "configure", ["terminal"], priv_lvl=7)
            self.assertEqual(status, TAC_PLUS_AUTHOR_STATUS_FAIL)
        finally:
            await client.close()

    async def test_anonymous_authorization_rejected(self):
        """Tests that authorization requests with user='' are rejected and do not inherit operator privileges."""
        client = TacacsTestClient("127.0.0.1", 4949, "testing123", single_connect=True)
        await client.connect()
        try:
            status, msg, _ = await client.authorize_command("", "show", ["version"], priv_lvl=7)
            self.assertEqual(status, TAC_PLUS_AUTHOR_STATUS_FAIL)
            self.assertIn("Anonymous authorization rejected", msg)
        finally:
            await client.close()

    async def test_vendor_av_pairs_dispatch(self):
        # Shell session for Cisco
        pairs_cisco = build_vendor_shell_av_pairs("cisco", priv_lvl=15)
        dict_cisco = {p.name: p.value for p in pairs_cisco}
        self.assertEqual(dict_cisco.get("service"), "shell")
        self.assertEqual(dict_cisco.get("priv-lvl"), "15")

        # Shell session for Juniper
        pairs_juniper = build_vendor_shell_av_pairs("juniper", priv_lvl=15)
        dict_juniper = {p.name: p.value for p in pairs_juniper}
        self.assertEqual(dict_juniper.get("service"), "junos-exec")
        self.assertEqual(dict_juniper.get("local-user-name"), "super-user")

        # Shell session for Fortinet
        pairs_forti = build_vendor_shell_av_pairs("fortinet", priv_lvl=15)
        dict_forti = {p.name: p.value for p in pairs_forti}
        self.assertEqual(dict_forti.get("service"), "fortigate")
        self.assertEqual(dict_forti.get("admin_prof"), "super_admin")

        # Shell session for Aruba
        pairs_aruba = build_vendor_shell_av_pairs("aruba", priv_lvl=15)
        dict_aruba = {p.name: p.value for p in pairs_aruba}
        self.assertEqual(dict_aruba.get("user-role"), "network-admin")

        # Shell session for Huawei
        pairs_huawei = build_vendor_shell_av_pairs("huawei", priv_lvl=15)
        dict_huawei = {p.name: p.value for p in pairs_huawei}
        self.assertEqual(dict_huawei.get("Huawei-Exec-Privilege"), "3")

    # --- Accounting Tests ---
    async def test_command_accounting_start_and_db_logging(self):
        client = TacacsTestClient("127.0.0.1", 4949, "testing123")
        await client.connect()
        try:
            status, msg = await client.account_command(
                "operator",
                "show",
                ["running-config"],
                flags=TAC_PLUS_ACCT_FLAG_START,
                priv_lvl=7,
            )
            self.assertEqual(status, TAC_PLUS_ACCT_STATUS_SUCCESS)

            # Verify SQLite WAL row
            with get_db_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT username, cmd, priv_lvl, status FROM tacacs_accounting "
                    "WHERE username = 'operator' ORDER BY id DESC LIMIT 1"
                )
                row = cursor.fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row["username"], "operator")
                self.assertEqual(row["cmd"], "show running-config")
                self.assertEqual(row["status"], "PERMITTED")
        finally:
            await client.close()

    async def test_accounting_illegal_flag_collision(self):
        client = TacacsTestClient("127.0.0.1", 4949, "testing123")
        await client.connect()
        try:
            # 0x06 is START | STOP collision
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

    async def test_command_accounting_status_av_pair_and_param(self):
        """Tests that accounting status can be extracted from AV-pairs or parameters, defaulting to PERMITTED."""
        client = TacacsTestClient("127.0.0.1", 4949, "testing123")
        await client.connect()
        try:
            # 1. Via AV-pair: status=DENIED
            status, msg = await client.account_command(
                "operator",
                "format",
                ["flash:"],
                flags=TAC_PLUS_ACCT_FLAG_STOP,
                priv_lvl=7,
                extra_av_pairs=[AVPair("status", "=", "DENIED")],
            )
            self.assertEqual(status, TAC_PLUS_ACCT_STATUS_SUCCESS)

            with get_db_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT username, cmd, status FROM tacacs_accounting "
                    "WHERE username = 'operator' AND cmd LIKE 'format%' ORDER BY id DESC LIMIT 1"
                )
                row = cursor.fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row["status"], "DENIED")

            # 2. Directly via processor status parameter
            proc = AccountingProcessor(self.db_path)
            p_status, p_msg = proc.process_accounting_request(
                flags=TAC_PLUS_ACCT_FLAG_STOP,
                device_ip="10.0.0.1",
                client_ip="10.0.0.2",
                username="admin",
                priv_lvl=15,
                av_pairs=[AVPair("cmd", "=", "reload")],
                status="DENIED",
            )
            self.assertEqual(p_status, TAC_PLUS_ACCT_STATUS_SUCCESS)
            with get_db_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT status FROM tacacs_accounting WHERE username = 'admin' AND cmd = 'reload'"
                )
                r = cursor.fetchone()
                self.assertEqual(r["status"], "DENIED")
        finally:
            await client.close()

    # --- Multiplexing & Heartbeat Tests ---
    async def test_single_connection_multiplexing(self):
        client = TacacsTestClient("127.0.0.1", 4949, "testing123", single_connect=True)
        await client.connect()
        try:
            # Session 1: PAP
            status1, _ = await client.authenticate_pap("admin", "Admin123!")
            self.assertEqual(status1, TAC_PLUS_AUTHEN_STATUS_PASS)

            # Session 2: Command Authorization over SAME TCP socket
            client.session_id = secrets.randbits(32)
            status2, _, _ = await client.authorize_command("admin", "show", ["ip", "route"], priv_lvl=15)
            self.assertEqual(status2, TAC_PLUS_AUTHOR_STATUS_PASS_ADD)

            # Session 3: Accounting over SAME TCP socket
            client.session_id = secrets.randbits(32)
            status3, _ = await client.account_command("admin", "show", ["ip", "route"], flags=TAC_PLUS_ACCT_FLAG_STOP)
            self.assertEqual(status3, TAC_PLUS_ACCT_STATUS_SUCCESS)
        finally:
            await client.close()

    async def test_daemon_heartbeat_in_wal(self):
        # Give heartbeat loop a moment to persist
        await asyncio.sleep(0.5)
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status, pid, metrics_json FROM daemon_status WHERE daemon_name = 'tacacs_daemon'")
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["status"], "RUNNING")
            self.assertEqual(row["pid"], os.getpid())
            metrics = json.loads(row["metrics_json"])
            self.assertIn("uptime_seconds", metrics)
            self.assertIn("port", metrics)

    def test_server_port_fallback_configuration(self):
        """Tests that TacacsServer port fallback is configurable."""
        server_default = TacacsServer(port=49, db_path=self.db_path)
        self.assertTrue(server_default.allow_port_fallback)

        server_configured = TacacsServer(port=49, allow_port_fallback=False, db_path=self.db_path)
        self.assertFalse(server_configured.allow_port_fallback)


class TestLpmClientResolver(unittest.TestCase):
    """Test Suite 4: Longest Prefix Match (LPM) NAS Secret Lookup."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp_dir.name, "test_lpm.db")
        init_db(self.db_path)

        with get_db_connection(self.db_path) as conn:
            conn.execute(
                "INSERT INTO tacacs_clients (name, ip_cidr, shared_secret, vendor) VALUES (?, ?, ?, ?)",
                ("Enterprise Core", "10.0.0.0/8", "key_slash_8", "cisco"),
            )
            conn.execute(
                "INSERT INTO tacacs_clients (name, ip_cidr, shared_secret, vendor) VALUES (?, ?, ?, ?)",
                ("Branch Network", "10.10.0.0/16", "key_slash_16", "cisco"),
            )
            conn.execute(
                "INSERT INTO tacacs_clients (name, ip_cidr, shared_secret, vendor) VALUES (?, ?, ?, ?)",
                ("Specific Switch", "10.10.1.5/32", "key_slash_32", "juniper"),
            )

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_longest_prefix_match(self):
        resolver = ClientSecretResolver(self.db_path)

        # Exact match should pick /32
        p1 = resolver.resolve("10.10.1.5")
        self.assertIsNotNone(p1)
        self.assertEqual(p1.shared_secret, "key_slash_32")
        self.assertEqual(p1.vendor, "juniper")

        # In branch should pick /16
        p2 = resolver.resolve("10.10.2.1")
        self.assertIsNotNone(p2)
        self.assertEqual(p2.shared_secret, "key_slash_16")

        # In enterprise general should pick /8
        p3 = resolver.resolve("10.99.1.1")
        self.assertIsNotNone(p3)
        self.assertEqual(p3.shared_secret, "key_slash_8")

        # Unknown outside should be None
        p4 = resolver.resolve("172.16.0.1")
        self.assertIsNone(p4)


if __name__ == "__main__":
    unittest.main()
