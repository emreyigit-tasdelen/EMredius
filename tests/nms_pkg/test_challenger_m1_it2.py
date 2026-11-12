# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Empirical Verification & Stress Test Suite by Challenger (Milestone M1 Iteration 2).

Mission Objectives:
1. Concurrency: Verify SQLite WAL concurrency by simulating concurrent accounting writes
   and authorization reads under heavy load without database lockups or data loss.
2. Database Integrity & Idempotence: Test database migration on an existing SQLite file
   created without the 'chap_secret' column, verifying idempotent migration and data preservation.
3. Edge Case Handling: Test accounting flag collision (e.g., START | STOP, STOP | WATCHDOG,
   invalid bitmasks) ensuring improper flag combinations are rejected with ERROR and not logged,
   while valid RFC 8907 combinations (including UPDATE = START | WATCHDOG) succeed.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import os
import secrets
import sqlite3
import tempfile
import time
import unittest
from typing import List, Tuple

from nms.common.db import (
    get_db_connection,
    hash_password,
    init_db,
)
from nms.tacacs.acct import (
    AccountingProcessor,
    TAC_PLUS_ACCT_FLAG_START,
    TAC_PLUS_ACCT_FLAG_STOP,
    TAC_PLUS_ACCT_FLAG_WATCHDOG,
    TAC_PLUS_ACCT_STATUS_ERROR,
    TAC_PLUS_ACCT_STATUS_SUCCESS,
    handle_acct_packet,
)
from nms.tacacs.author import (
    RegexPolicyEngine,
    TAC_PLUS_AUTHOR_STATUS_FAIL,
    TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
    handle_author_packet,
)
from nms.tacacs.authen import (
    handle_authen_packet,
    TAC_PLUS_AUTHEN_STATUS_FAIL,
    TAC_PLUS_AUTHEN_STATUS_PASS,
    TAC_PLUS_AUTHEN_SVC_LOGIN,
    TAC_PLUS_AUTHEN_TYPE_CHAP,
)
from nms.tacacs.codec import (
    AVPair,
    AcctReply,
    AcctRequest,
    AuthenStart,
    AuthorReply,
    AuthorRequest,
    TacacsHeader,
    TAC_PLUS_ACCT,
    TAC_PLUS_AUTHEN,
    TAC_PLUS_AUTHOR,
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_MINOR_VER_DEFAULT,
    TAC_PLUS_MINOR_VER_ONE,
    TAC_PLUS_SINGLE_CONNECT_FLAG,
    unpack_header,
)
from nms.tacacs.crypto import decrypt_body, encrypt_body
from nms.tacacs.server import TacacsServer

CHALLENGER_TEST_PORT = 4977
CHALLENGER_SECRET = "challenger_secret_2026"


class ChallengerTacacsClient:
    """Helper client for empirical testing over TCP socket."""

    def __init__(self, host: str, port: int, secret: str = CHALLENGER_SECRET):
        self.host = host
        self.port = port
        self.secret = secret
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
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

    async def _send_receive(self, header: TacacsHeader, plain_body: bytes) -> Tuple[TacacsHeader, bytes]:
        if not self.writer or not self.reader:
            raise RuntimeError("Client not connected")
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
            raise ValueError("Response decryption failed")
        return resp_hdr, resp_body

    async def authorize(
        self, user: str, cmd: str, args: List[str], priv_lvl: int = 7
    ) -> Tuple[int, str]:
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
        if cmd is not None:
            av_list.append(AVPair("cmd", "=", cmd))
            for a in args:
                av_list.append(AVPair("cmd-arg", "=", a))

        req = AuthorRequest(
            priv_lvl=priv_lvl,
            user=user,
            port="vty0",
            rem_addr="192.168.100.10",
            args=av_list,
        )
        resp_hdr, resp_body = await self._send_receive(header, req.pack())
        reply = AuthorReply.unpack(resp_body)
        return reply.status, reply.server_msg

    async def account(
        self,
        user: str,
        cmd: str,
        args: List[str],
        flags: int = TAC_PLUS_ACCT_FLAG_START,
        priv_lvl: int = 7,
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
        if cmd is not None:
            av_list.append(AVPair("cmd", "=", cmd))
            for a in args:
                av_list.append(AVPair("cmd-arg", "=", a))

        req = AcctRequest(
            flags=flags,
            priv_lvl=priv_lvl,
            user=user,
            port="vty0",
            rem_addr="192.168.100.10",
            args=av_list,
        )
        resp_hdr, resp_body = await self._send_receive(header, req.pack())
        reply = AcctReply.unpack(resp_body)
        return reply.status, reply.server_msg


class TestAccountingFlagCollisionAndValidation(unittest.TestCase):
    """Test Suite 1: Accounting Flag Collision & Rejection Matrix."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp_dir.name, "flag_test.db")
        init_db(self.db_path)
        self.processor = AccountingProcessor(self.db_path)

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_flag_collision_start_and_stop_rejected(self):
        """START | STOP (0x02 | 0x04 = 0x06) must be strictly rejected with ERROR and not logged."""
        collision_flags = TAC_PLUS_ACCT_FLAG_START | TAC_PLUS_ACCT_FLAG_STOP
        status, msg = self.processor.process_accounting_request(
            flags=collision_flags,
            device_ip="10.0.0.1",
            client_ip="10.0.0.2",
            username="admin",
            priv_lvl=15,
            av_pairs=[AVPair("cmd", "=", "reload")],
        )

        # 1. Must return TAC_PLUS_ACCT_STATUS_ERROR (0x02)
        self.assertEqual(status, TAC_PLUS_ACCT_STATUS_ERROR)
        self.assertIn("Invalid accounting flags combination", msg)

        # 2. Must NOT insert any row into tacacs_accounting
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM tacacs_accounting WHERE cmd = 'reload'")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 0, "Collision record was incorrectly persisted in database!")

    def test_flag_collision_stop_and_watchdog_rejected(self):
        """STOP | WATCHDOG (0x04 | 0x08 = 0x0C) must be strictly rejected with ERROR."""
        collision_flags = TAC_PLUS_ACCT_FLAG_STOP | TAC_PLUS_ACCT_FLAG_WATCHDOG
        status, msg = self.processor.process_accounting_request(
            flags=collision_flags,
            device_ip="10.0.0.1",
            client_ip="10.0.0.2",
            username="operator",
            priv_lvl=7,
            av_pairs=[AVPair("cmd", "=", "show ip route")],
        )

        self.assertEqual(status, TAC_PLUS_ACCT_STATUS_ERROR)
        self.assertIn("Invalid accounting flags combination", msg)

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM tacacs_accounting WHERE username = 'operator'")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 0)

    def test_flag_collision_start_stop_watchdog_all_set_rejected(self):
        """START | STOP | WATCHDOG (0x02 | 0x04 | 0x08 = 0x0E) must be strictly rejected with ERROR."""
        collision_flags = (
            TAC_PLUS_ACCT_FLAG_START | TAC_PLUS_ACCT_FLAG_STOP | TAC_PLUS_ACCT_FLAG_WATCHDOG
        )
        status, msg = self.processor.process_accounting_request(
            flags=collision_flags,
            device_ip="10.0.0.1",
            client_ip="10.0.0.2",
            username="admin",
            priv_lvl=15,
            av_pairs=[AVPair("cmd", "=", "configure terminal")],
        )

        self.assertEqual(status, TAC_PLUS_ACCT_STATUS_ERROR)
        self.assertIn("Invalid accounting flags combination", msg)

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM tacacs_accounting")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 0)

    def test_zero_flags_and_bogus_bitmasks_rejected(self):
        """0x00 and arbitrary invalid bitmasks (0x01, 0x10, 0x20, 0xFF) must be rejected."""
        bogus_flag_vectors = [0x00, 0x01, 0x10, 0x20, 0x40, 0x80, 0xFF]
        for bad_flag in bogus_flag_vectors:
            status, msg = self.processor.process_accounting_request(
                flags=bad_flag,
                device_ip="10.0.0.1",
                client_ip="10.0.0.2",
                username="test_user",
                priv_lvl=1,
                av_pairs=[AVPair("cmd", "=", f"test_cmd_{bad_flag}")],
            )
            self.assertEqual(
                status,
                TAC_PLUS_ACCT_STATUS_ERROR,
                f"Flag 0x{bad_flag:02x} was unexpectedly accepted!",
            )

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM tacacs_accounting")
            count = cursor.fetchone()[0]
            self.assertEqual(count, 0)

    def test_valid_rfc8907_flag_combinations_succeed(self):
        """Valid RFC 8907 flags: START (2), STOP (4), WATCHDOG (8), and UPDATE (START|WATCHDOG = 10) must succeed."""
        valid_vectors = [
            (TAC_PLUS_ACCT_FLAG_START, "START record"),
            (TAC_PLUS_ACCT_FLAG_STOP, "STOP record"),
            (TAC_PLUS_ACCT_FLAG_WATCHDOG, "WATCHDOG record"),
            (TAC_PLUS_ACCT_FLAG_START | TAC_PLUS_ACCT_FLAG_WATCHDOG, "UPDATE record (START|WATCHDOG)"),
        ]

        for flag, desc in valid_vectors:
            status, msg = self.processor.process_accounting_request(
                flags=flag,
                device_ip="10.0.0.1",
                client_ip="10.0.0.2",
                username="audit_user",
                priv_lvl=7,
                av_pairs=[AVPair("cmd", "=", f"command_for_{desc}")],
            )
            self.assertEqual(
                status,
                TAC_PLUS_ACCT_STATUS_SUCCESS,
                f"Valid flag combination '{desc}' (0x{flag:02x}) was rejected with msg: {msg}",
            )

        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM tacacs_accounting WHERE username = 'audit_user'")
            count = cursor.fetchone()[0]
            self.assertEqual(count, len(valid_vectors))


class TestDatabaseMigrationLegacySchemaIdempotence(unittest.TestCase):
    """Test Suite 2: Legacy Database Migration Without chap_secret Column."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.legacy_db_path = os.path.join(self.tmp_dir.name, "legacy_schema.db")

        # Create a genuine pre-migration legacy database WITHOUT chap_secret column
        conn = sqlite3.connect(self.legacy_db_path)
        with conn:
            conn.execute(
                """
                CREATE TABLE groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(64) UNIQUE NOT NULL,
                    priv_lvl INTEGER NOT NULL DEFAULT 1,
                    default_policy VARCHAR(16) NOT NULL DEFAULT 'deny',
                    description TEXT DEFAULT ''
                );
                """
            )
            # Legacy users table missing chap_secret
            conn.execute(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username VARCHAR(64) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    enable_password_hash VARCHAR(255) DEFAULT '',
                    priv_lvl INTEGER DEFAULT 1,
                    group_id INTEGER REFERENCES groups(id),
                    enabled BOOLEAN NOT NULL DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE tacacs_clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(64) NOT NULL,
                    ip_cidr VARCHAR(45) UNIQUE NOT NULL,
                    shared_secret VARCHAR(128) NOT NULL,
                    vendor VARCHAR(32) NOT NULL DEFAULT 'cisco',
                    description TEXT DEFAULT '',
                    is_active BOOLEAN NOT NULL DEFAULT 1
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE tacacs_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id INTEGER REFERENCES groups(id),
                    priority INTEGER NOT NULL DEFAULT 100,
                    pattern TEXT NOT NULL,
                    action VARCHAR(10) NOT NULL,
                    description TEXT DEFAULT ''
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE tacacs_accounting (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    device_ip VARCHAR(45) NOT NULL,
                    client_ip VARCHAR(45) DEFAULT '',
                    username VARCHAR(64) NOT NULL,
                    priv_lvl INTEGER NOT NULL DEFAULT 1,
                    cmd TEXT NOT NULL,
                    status VARCHAR(16) NOT NULL DEFAULT 'PERMITTED'
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE daemon_status (
                    daemon_name VARCHAR(64) PRIMARY KEY,
                    last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    pid INTEGER,
                    status VARCHAR(32) DEFAULT 'RUNNING',
                    metrics_json TEXT DEFAULT '{}'
                );
                """
            )

            # Insert legacy users
            legacy_admin_hash = hash_password("OldAdminPass123!")
            legacy_op_hash = hash_password("OldOpPass123!")
            conn.execute(
                "INSERT INTO users (username, password_hash, priv_lvl) VALUES (?, ?, ?)",
                ("legacy_admin", legacy_admin_hash, 15),
            )
            conn.execute(
                "INSERT INTO users (username, password_hash, priv_lvl) VALUES (?, ?, ?)",
                ("legacy_operator", legacy_op_hash, 7),
            )
            conn.execute(
                "INSERT INTO tacacs_clients (name, ip_cidr, shared_secret) VALUES (?, ?, ?)",
                ("legacy_client", "127.0.0.1/32", CHALLENGER_SECRET),
            )
        conn.close()

    def tearDown(self):
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_legacy_schema_migrates_and_preserves_data(self):
        """Verifies migration adds chap_secret without error and preserves existing users."""
        # 1. Before migration: verify chap_secret is NOT present
        conn = sqlite3.connect(self.legacy_db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users);")
        pre_cols = [r["name"] for r in cursor.fetchall()]
        self.assertNotIn("chap_secret", pre_cols)
        conn.close()

        # 2. Run init_db on legacy database
        init_db(self.legacy_db_path)

        # 3. After migration: verify chap_secret is present
        conn = get_db_connection(self.legacy_db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users);")
        post_cols = [r["name"] for r in cursor.fetchall()]
        self.assertIn("chap_secret", post_cols, "Migration failed to add chap_secret column!")

        # 4. Verify existing legacy users exist with their original credentials preserved
        cursor.execute("SELECT username, chap_secret, priv_lvl FROM users WHERE username = 'legacy_operator'")
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["username"], "legacy_operator")
        self.assertEqual(row["priv_lvl"], 7)
        # Migrated column defaults to empty string or default value
        self.assertEqual(row["chap_secret"], "")

        # 5. Run PRAGMA integrity_check
        cursor.execute("PRAGMA integrity_check;")
        self.assertEqual(cursor.fetchone()[0], "ok")
        conn.close()

    def test_migration_is_fully_idempotent(self):
        """Repeated invocations of init_db must succeed without duplicate column errors."""
        # Run init_db multiple times in succession
        for iteration in range(1, 5):
            try:
                init_db(self.legacy_db_path)
            except Exception as e:
                self.fail(f"init_db failed on idempotent iteration {iteration}: {e}")

        conn = get_db_connection(self.legacy_db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users);")
        cols = [r["name"] for r in cursor.fetchall()]
        self.assertIn("chap_secret", cols)
        self.assertEqual(cols.count("chap_secret"), 1, "Duplicate chap_secret column created!")
        conn.close()

    def test_migrated_database_chap_authentication_flow(self):
        """Tests that a migrated database can authenticate via CHAP once chap_secret is provisioned."""
        init_db(self.legacy_db_path)

        # Provision chap_secret on legacy_operator
        custom_chap_secret = "LegacyChapSecret12345!"
        with get_db_connection(self.legacy_db_path) as conn:
            conn.execute(
                "UPDATE users SET chap_secret = ? WHERE username = 'legacy_operator'",
                (custom_chap_secret,),
            )
            conn.commit()

        # Build simulated CHAP challenge-response
        chap_id = b"\x01"
        challenge = b"challenger_rand_challenge_16b!"
        expected_md5 = hashlib.md5(chap_id + custom_chap_secret.encode("utf-8") + challenge).digest()
        chap_data = chap_id + challenge + expected_md5

        header = TacacsHeader(
            major_version=TAC_PLUS_MAJOR_VER,
            minor_version=TAC_PLUS_MINOR_VER_ONE,
            type=TAC_PLUS_AUTHEN,
            seq_no=1,
            session_id=0x99881122,
        )
        start = AuthenStart(
            action=1,
            priv_lvl=7,
            authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP,
            authen_service=TAC_PLUS_AUTHEN_SVC_LOGIN,
            user="legacy_operator",
            data=chap_data,
        )

        class DummySession:
            client_ip = "127.0.0.1"

        class DummyClientProfile:
            shared_secret = CHALLENGER_SECRET

        loop = asyncio.new_event_loop()
        try:
            resp_hdr, resp_body, is_term = loop.run_until_complete(
                handle_authen_packet(
                    header=header,
                    plain_body=start.pack(),
                    session=DummySession(),
                    db_path=self.legacy_db_path,
                )
            )
            from nms.tacacs.codec import AuthenReply
            reply = AuthenReply.unpack(resp_body)
            self.assertEqual(reply.status, TAC_PLUS_AUTHEN_STATUS_PASS)
            self.assertIn("Successful", reply.server_msg)
        finally:
            loop.close()


class TestSqliteWalConcurrencyStress(unittest.IsolatedAsyncioTestCase):
    """Test Suite 3: Empirical SQLite WAL Concurrency (Writes + Reads Under Contention)."""

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp_dir.name, "wal_concurrency.db")
        init_db(self.db_path)

        # Configure dedicated client secret
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO tacacs_clients (name, ip_cidr, shared_secret, vendor)
                VALUES ('challenger_client', '127.0.0.1/32', ?, 'cisco')
                ON CONFLICT(ip_cidr) DO UPDATE SET shared_secret = excluded.shared_secret
                """,
                (CHALLENGER_SECRET,),
            )
            conn.commit()

        self.port = CHALLENGER_TEST_PORT
        self.server = TacacsServer(
            host="127.0.0.1",
            port=self.port,
            fallback_port=self.port,
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

    async def test_simultaneous_50_accounting_writes_and_50_authorization_reads(self):
        """Empirically stress WAL mode with 50 concurrent accounting writes and 50 concurrent authorization reads.

        Asserts:
        1. All 50 accounting writes succeed with STATUS_SUCCESS (0x01).
        2. All 50 authorization reads evaluate correctly without blocking or deadlocking.
        3. tacacs_accounting contains exactly 50 new rows with zero data loss or truncation.
        4. No 'database is locked' or operational errors occur.
        5. SQLite PRAGMA integrity_check returns 'ok'.
        """
        concurrency = 50

        async def _author_worker(idx: int) -> Tuple[int, str]:
            client = ChallengerTacacsClient("127.0.0.1", self.port)
            try:
                await client.connect()
                status, msg = await client.authorize(
                    user="operator",
                    cmd="show",
                    args=["ip", "route", f"10.{idx}.0.0/16"],
                    priv_lvl=7,
                )
                return status, msg
            finally:
                await client.close()

        async def _acct_worker(idx: int) -> Tuple[int, str]:
            client = ChallengerTacacsClient("127.0.0.1", self.port)
            try:
                await client.connect()
                status, msg = await client.account(
                    user="operator",
                    cmd="show",
                    args=["interface", f"TenGigabitEthernet1/0/{idx}"],
                    flags=TAC_PLUS_ACCT_FLAG_STOP,
                    priv_lvl=7,
                )
                return status, msg
            finally:
                await client.close()

        # Interleave 50 author and 50 acct tasks
        tasks = []
        for i in range(concurrency):
            tasks.append(_author_worker(i))
            tasks.append(_acct_worker(i))

        start_time = time.perf_counter()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.perf_counter() - start_time

        # Verify no task threw an unhandled exception
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                self.fail(f"Task {i} raised unhandled exception: {res}")

        # Separate author and acct results
        author_results = results[0::2]
        acct_results = results[1::2]

        # Verify all authorization requests passed (PASS_ADD 0x01)
        for i, (status, msg) in enumerate(author_results):
            self.assertEqual(
                status,
                TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                f"Author worker {i} failed: status=0x{status:02x}, msg={msg}",
            )

        # Verify all accounting requests succeeded (SUCCESS 0x01)
        for i, (status, msg) in enumerate(acct_results):
            self.assertEqual(
                status,
                TAC_PLUS_ACCT_STATUS_SUCCESS,
                f"Acct worker {i} failed: status=0x{status:02x}, msg={msg}",
            )

        # Verify SQLite WAL row count and integrity
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM tacacs_accounting WHERE cmd LIKE 'show interface TenGigabitEthernet1/0/%'"
            )
            row_count = cursor.fetchone()[0]
            self.assertEqual(
                row_count,
                concurrency,
                f"Data loss detected! Expected {concurrency} rows, found {row_count}.",
            )

            # Check distinct rows to guarantee no overwrite
            cursor.execute(
                "SELECT COUNT(DISTINCT cmd) FROM tacacs_accounting WHERE cmd LIKE 'show interface TenGigabitEthernet1/0/%'"
            )
            distinct_count = cursor.fetchone()[0]
            self.assertEqual(
                distinct_count,
                concurrency,
                f"Data collision/overwrite detected! Expected {concurrency} distinct commands, found {distinct_count}.",
            )

            # Check database WAL integrity
            cursor.execute("PRAGMA integrity_check;")
            integrity = cursor.fetchone()[0]
            self.assertEqual(integrity, "ok", "Database integrity check failed!")

    async def test_high_intensity_raw_db_layer_wal_concurrency(self):
        """Direct DB layer stress test: 100 concurrent threads doing rapid interleaved read/writes with active contention."""
        thread_count = 50
        errors: List[str] = []

        def _writer_thread(worker_id: int):
            try:
                proc = AccountingProcessor(self.db_path)
                for step in range(5):
                    status, msg = proc.process_accounting_request(
                        flags=TAC_PLUS_ACCT_FLAG_STOP,
                        device_ip="172.16.1.1",
                        client_ip="172.16.1.1",
                        username=f"stress_writer_{worker_id}",
                        priv_lvl=7,
                        av_pairs=[
                            AVPair("service", "=", "shell"),
                            AVPair("cmd", "=", "ping"),
                            AVPair("cmd-arg", "=", f"10.200.{worker_id}.{step}"),
                        ],
                    )
                    if status != TAC_PLUS_ACCT_STATUS_SUCCESS:
                        errors.append(f"Writer {worker_id} failed: {msg}")
            except Exception as e:
                errors.append(f"Writer {worker_id} exception: {e}")

        def _reader_thread(worker_id: int):
            try:
                engine = RegexPolicyEngine(self.db_path)
                for step in range(5):
                    is_permitted, reason = engine.evaluate(
                        username="operator",
                        full_cmd=f"show ip interface GigabitEthernet0/{worker_id}",
                        user_priv=7,
                    )
                    if not is_permitted:
                        errors.append(f"Reader {worker_id} denied unexpectedly: {reason}")
            except Exception as e:
                errors.append(f"Reader {worker_id} exception: {e}")

        executor = ThreadPoolExecutor(max_workers=thread_count * 2)
        futures = []
        for w in range(thread_count):
            futures.append(executor.submit(_writer_thread, w))
            futures.append(executor.submit(_reader_thread, w))

        for f in futures:
            f.result()
        executor.shutdown(wait=True)

        self.assertEqual(
            len(errors),
            0,
            f"Encountered {len(errors)} concurrency/locking errors: {errors[:5]}",
        )

        # Assert total writes in database
        expected_total_writes = thread_count * 5
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM tacacs_accounting WHERE username LIKE 'stress_writer_%'"
            )
            count = cursor.fetchone()[0]
            self.assertEqual(
                count,
                expected_total_writes,
                f"Expected {expected_total_writes} writes, found {count}",
            )


if __name__ == "__main__":
    unittest.main()
