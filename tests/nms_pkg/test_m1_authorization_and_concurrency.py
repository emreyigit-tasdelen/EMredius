# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Adversarial Security & SQLite WAL Concurrency Stress Test Suite for Milestone M1 (Challenger 2).

Mission Requirements:
1. Write and run adversarial tests targeting Command Authorization:
   - Obfuscation & bypass attempts: RELOAD, reload\\n, config   terminal, format  flash:/boot, erase /force, quotes, trailing whitespace, flag injections.
   - Verify that forbidden commands are strictly rejected (FAIL 0x10) while permitted commands (show ip interface brief, ping 8.8.8.8) are permitted (PASS_ADD 0x01).
2. Stress test SQLite WAL concurrency:
   - Send 50 concurrent accounting requests simultaneously from simulated clients.
   - Verify all 50 accounting records are recorded in tacacs_accounting without any 'database is locked' error or data loss.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import os
import secrets
import sqlite3
import tempfile
import time
import unittest
from typing import List, Tuple

from nms.common.db import get_db_connection, init_db
from nms.tacacs.acct import (
    TAC_PLUS_ACCT_FLAG_START,
    TAC_PLUS_ACCT_FLAG_STOP,
    TAC_PLUS_ACCT_STATUS_ERROR,
    TAC_PLUS_ACCT_STATUS_SUCCESS,
)
from nms.tacacs.author import (
    TAC_PLUS_AUTHOR_STATUS_FAIL,
    TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
    RegexPolicyEngine,
)
from nms.tacacs.codec import (
    TAC_PLUS_ACCT,
    TAC_PLUS_AUTHOR,
    TAC_PLUS_MAJOR_VER,
    TAC_PLUS_MINOR_VER_DEFAULT,
    AVPair,
    AcctReply,
    AcctRequest,
    AuthorReply,
    AuthorRequest,
    TacacsHeader,
    unpack_header,
)
from nms.tacacs.crypto import decrypt_body, encrypt_body
from nms.tacacs.server import TacacsServer


class AdversarialTacacsClient:
    """Simulated client helper for adversarial testing over TCP."""

    def __init__(self, host: str, port: int, secret: str = "testing123", single_connect: bool = True):
        self.host = host
        self.port = port
        self.secret = secret
        self.single_connect = single_connect
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
        if self.single_connect and header.seq_no == 1:
            header.flags |= 0x04  # TAC_PLUS_SINGLE_CONNECT_FLAG
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
            rem_addr="10.0.0.5",
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
        task_id: str = "",
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
        if task_id:
            av_list.append(AVPair("task_id", "=", task_id))

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


class TestAdversarialCommandAuthorization(unittest.IsolatedAsyncioTestCase):
    """Adversarial stress testing for Command Authorization bypasses and obfuscation."""

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp_dir.name, "adv_auth.db")
        init_db(self.db_path)

        self.port = 4960
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

    async def test_forbidden_commands_rejection_matrix(self):
        """Verify that all obfuscation and bypass attempts on forbidden commands are strictly rejected."""
        client = AdversarialTacacsClient("127.0.0.1", self.port)
        await client.connect()

        # Matrix of forbidden commands under operator (priv 7)
        # Format: (cmd, [args], description)
        forbidden_test_vectors = [
            # 1. Case variation bypasses
            ("RELOAD", [], "Uppercase RELOAD"),
            ("ReLoAd", [], "Mixed-case ReLoAd"),
            ("rElOaD", ["now"], "Mixed-case rElOaD with arg"),
            ("CONFIG", ["terminal"], "Uppercase CONFIG terminal"),
            ("cOnFiGuRe", ["terminal"], "Mixed-case configure terminal"),
            ("FORMAT", ["flash:/boot"], "Uppercase FORMAT flash"),
            ("ERASE", ["/force"], "Uppercase ERASE /force"),

            # 2. Whitespace & newline injection bypasses
            ("reload\n", [], "Newline in cmd"),
            ("reload\r\n", [], "CRLF in cmd"),
            ("reload", ["\n"], "Newline in args"),
            ("reload   ", [], "Trailing spaces in cmd"),
            ("   reload", [], "Leading spaces in cmd"),
            ("config", ["  terminal"], "Multiple spaces between cmd and arg"),
            ("config", ["terminal   "], "Trailing spaces in arg"),
            ("config   terminal", [], "Multiple spaces in single cmd"),
            ("config\tterminal", [], "Tab separator in single cmd"),
            ("config", ["\tterminal"], "Tab separator in arg"),
            ("config\nterminal", [], "Newline separator in single cmd"),
            ("configure", ["   terminal"], "Multiple spaces in configure terminal"),
            ("format  flash:/boot", [], "Multiple spaces in format flash"),
            ("format", ["  flash:/boot"], "Multiple spaces in format arg"),
            ("erase /force", [], "Flag in single cmd"),
            ("erase", ["/force"], "Flag in arg"),
            ("erase", ["  nvram:"], "Multiple spaces in erase nvram"),

            # 3. Flag / Option injection bypasses
            ("reload", ["-f"], "reload with -f flag"),
            ("reload", ["--force"], "reload with --force flag"),
            ("reload", ["/noconfirm"], "reload with /noconfirm switch"),
            ("reload", ["in", "5"], "reload in 5 timer"),
            ("format", ["/y", "flash:"], "format with /y switch"),
            ("format", ["-f", "flash:/boot"], "format with -f flag"),
            ("erase", ["/force", "startup-config"], "erase with /force startup-config"),
            ("erase", ["--all"], "erase with --all"),
            ("configure", ["terminal", "--force"], "configure terminal with extra flags"),

            # 4. Quotes / wrapper bypass attempts
            ("\"reload\"", [], "Double quotes around reload"),
            ("'reload'", [], "Single quotes around reload"),
            ("config", ["\"terminal\""], "Double quotes around arg"),
            ("config", ["'terminal'"], "Single quotes around arg"),
            ("\"config\"", ["terminal"], "Double quotes around cmd"),
            ("'config'", ["terminal"], "Single quotes around cmd"),
            ("\"format\"", ["flash:/boot"], "Double quotes around format"),
            ("format", ["\"flash:/boot\""], "Double quotes around format arg"),
            ("\"erase\"", ["/force"], "Double quotes around erase"),
            ("erase", ["\"/force\""], "Double quotes around erase arg"),

            # 5. Shell separator / command chaining attempts
            ("reload; ls", [], "Semicolon chaining"),
            ("reload && echo hi", [], "AND chaining"),
            ("reload | reboot", [], "Pipe chaining"),
        ]

        try:
            for cmd, args, desc in forbidden_test_vectors:
                client.session_id = secrets.randbits(32)
                status, msg = await client.authorize("operator", cmd, args, priv_lvl=7)
                self.assertEqual(
                    status,
                    TAC_PLUS_AUTHOR_STATUS_FAIL,
                    f"SECURITY BREACH / BYPASS DETECTED: Command '{cmd} {args}' ({desc}) was NOT rejected! "
                    f"Received status=0x{status:02x}, msg='{msg.strip()}'",
                )
        finally:
            await client.close()

    async def test_permitted_commands_integrity(self):
        """Verify that legitimate diagnostic and operational commands are strictly permitted (PASS_ADD 0x01)."""
        client = AdversarialTacacsClient("127.0.0.1", self.port)
        await client.connect()

        permitted_vectors = [
            ("show", ["ip", "interface", "brief"], "show ip interface brief"),
            ("ping", ["8.8.8.8"], "ping 8.8.8.8"),
            ("show", ["running-config"], "show running-config"),
            ("show", ["version"], "show version"),
            ("show", ["interfaces", "status"], "show interfaces status"),
            ("ping", ["192.168.1.1"], "ping 192.168.1.1"),
            ("ping", ["-c", "4", "10.0.0.1"], "ping with count flag"),
            ("traceroute", ["8.8.4.4"], "traceroute 8.8.4.4"),
            ("clear", ["counters"], "clear counters"),
        ]

        try:
            for cmd, args, desc in permitted_vectors:
                client.session_id = secrets.randbits(32)
                status, msg = await client.authorize("operator", cmd, args, priv_lvl=7)
                self.assertEqual(
                    status,
                    TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
                    f"FALSE REJECTION: Permitted command '{cmd} {args}' ({desc}) was rejected! "
                    f"Received status=0x{status:02x}, msg='{msg.strip()}'",
                )
        finally:
            await client.close()

    async def test_helpdesk_restricted_privilege_boundaries(self):
        """Verify that helpdesk user (priv 1) cannot execute operator commands like clear counters."""
        client = AdversarialTacacsClient("127.0.0.1", self.port)
        await client.connect()
        try:
            # Helpdesk can show
            client.session_id = secrets.randbits(32)
            status, _ = await client.authorize("helpdesk", "show", ["ip", "route"], priv_lvl=1)
            self.assertEqual(status, TAC_PLUS_AUTHOR_STATUS_PASS_ADD)

            # Helpdesk CANNOT clear counters
            client.session_id = secrets.randbits(32)
            status, _ = await client.authorize("helpdesk", "clear", ["counters"], priv_lvl=1)
            self.assertEqual(
                status,
                TAC_PLUS_AUTHOR_STATUS_FAIL,
                "Helpdesk should not be permitted to execute clear counters",
            )

            # Helpdesk CANNOT reload
            client.session_id = secrets.randbits(32)
            status, _ = await client.authorize("helpdesk", "reload", [], priv_lvl=1)
            self.assertEqual(status, TAC_PLUS_AUTHOR_STATUS_FAIL)
        finally:
            await client.close()


class TestSqliteWalConcurrencyStress(unittest.IsolatedAsyncioTestCase):
    """Stress test SQLite WAL concurrency with 50+ concurrent requests."""

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmp_dir.name, "adv_concurrency.db")
        init_db(self.db_path)

        self.port = 4961
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

    async def test_50_concurrent_accounting_requests_no_lock(self):
        """Send 50 concurrent accounting requests simultaneously from distinct simulated clients.

        Asserts:
        - 100% of the 50 requests receive TAC_PLUS_ACCT_STATUS_SUCCESS (0x01).
        - Exactly 50 records appear in tacacs_accounting.
        - Zero 'database is locked' errors or dropped packets.
        """
        concurrency_count = 50
        batch_id = f"batch_{int(time.time()*1000)}"

        async def _client_worker(index: int) -> Tuple[int, str]:
            client = AdversarialTacacsClient("127.0.0.1", self.port)
            try:
                await client.connect()
                task_tag = f"{batch_id}_task_{index:03d}"
                cmd = "show"
                args = ["interface", f"GigabitEthernet0/{index}"]
                status, msg = await client.account(
                    user=f"stress_user_{index % 5}",
                    cmd=cmd,
                    args=args,
                    flags=TAC_PLUS_ACCT_FLAG_STOP,
                    priv_lvl=7,
                    task_id=task_tag,
                )
                return status, msg
            finally:
                await client.close()

        start_time = time.perf_counter()
        # Fire all 50 concurrent accounting requests simultaneously
        results = await asyncio.gather(*[_client_worker(i) for i in range(concurrency_count)])
        duration = time.perf_counter() - start_time

        # 1. Assert all 50 returned SUCCESS
        statuses = [r[0] for r in results]
        messages = [r[1] for r in results]

        failed_count = sum(1 for s in statuses if s != TAC_PLUS_ACCT_STATUS_SUCCESS)
        error_msgs = [m for s, m in zip(statuses, messages) if s != TAC_PLUS_ACCT_STATUS_SUCCESS]

        self.assertEqual(
            failed_count,
            0,
            f"Concurrency stress test failed! {failed_count}/{concurrency_count} requests failed. "
            f"Errors: {error_msgs[:5]}",
        )

        # 2. Check for any 'database is locked' in response messages
        locked_errors = [m for m in messages if "database is locked" in m.lower() or "locked" in m.lower()]
        self.assertEqual(len(locked_errors), 0, f"Detected database locking errors: {locked_errors}")

        # 3. Assert all 50 records exist in tacacs_accounting table
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM tacacs_accounting WHERE cmd LIKE ?",
                (f"%GigabitEthernet0/%",),
            )
            count = cursor.fetchone()[0]
            self.assertEqual(
                count,
                concurrency_count,
                f"Data loss detected! Expected {concurrency_count} rows in tacacs_accounting, found {count}.",
            )

            # Check distinct commands to ensure no duplication or overwrite
            cursor.execute(
                "SELECT COUNT(DISTINCT cmd) FROM tacacs_accounting WHERE cmd LIKE ?",
                (f"%GigabitEthernet0/%",),
            )
            distinct_cmds = cursor.fetchone()[0]
            self.assertEqual(
                distinct_cmds,
                concurrency_count,
                f"Data integrity loss! Expected {concurrency_count} distinct commands, found {distinct_cmds}.",
            )

    async def test_100_mixed_concurrent_authorization_and_accounting(self):
        """Stress test with 50 concurrent authorization + 50 concurrent accounting requests simultaneously (100 total)."""
        concurrency_each = 50

        async def _author_worker(index: int) -> Tuple[int, str]:
            client = AdversarialTacacsClient("127.0.0.1", self.port)
            try:
                await client.connect()
                status, msg = await client.authorize(
                    user="operator",
                    cmd="show",
                    args=["ip", "route", f"10.0.{index}.0"],
                    priv_lvl=7,
                )
                return status, msg
            finally:
                await client.close()

        async def _acct_worker(index: int) -> Tuple[int, str]:
            client = AdversarialTacacsClient("127.0.0.1", self.port)
            try:
                await client.connect()
                status, msg = await client.account(
                    user="operator",
                    cmd="show",
                    args=["ip", "route", f"10.0.{index}.0"],
                    flags=TAC_PLUS_ACCT_FLAG_START,
                    priv_lvl=7,
                )
                return status, msg
            finally:
                await client.close()

        tasks = []
        for i in range(concurrency_each):
            tasks.append(_author_worker(i))
            tasks.append(_acct_worker(i))

        start_time = time.perf_counter()
        results = await asyncio.gather(*tasks)
        duration = time.perf_counter() - start_time

        # Half are author, half are acct
        author_results = results[0::2]
        acct_results = results[1::2]

        # Verify all author requests passed
        for status, msg in author_results:
            self.assertEqual(status, TAC_PLUS_AUTHOR_STATUS_PASS_ADD)

        # Verify all acct requests succeeded
        for status, msg in acct_results:
            self.assertEqual(status, TAC_PLUS_ACCT_STATUS_SUCCESS)

        # Verify accounting records in DB
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM tacacs_accounting WHERE cmd LIKE 'show ip route 10.0.%'"
            )
            count = cursor.fetchone()[0]
            self.assertEqual(
                count,
                concurrency_each,
                f"Expected {concurrency_each} accounting records in mixed stress test, got {count}",
            )

    async def test_50_concurrent_accounting_with_active_external_db_contention(self):
        """Stress test SQLite WAL with 50 concurrent TCP accounting requests while external threads perform continuous DB reads and writes."""
        concurrency_count = 50
        stop_background = False
        background_errors = []

        def _background_db_worker():
            """Simulates simultaneous Flask web API or background pollers reading/writing SQLite."""
            while not stop_background:
                try:
                    with get_db_connection(self.db_path) as conn:
                        cursor = conn.cursor()
                        # Read contention
                        cursor.execute("SELECT COUNT(*) FROM tacacs_accounting")
                        cursor.fetchone()
                        # Write contention
                        cursor.execute(
                            "INSERT INTO tacacs_accounting (timestamp, device_ip, client_ip, username, priv_lvl, cmd, status) "
                            "VALUES (CURRENT_TIMESTAMP, '10.254.0.1', '10.254.0.1', 'poller', 1, 'snmp_poll_health', 'PERMITTED')"
                        )
                        conn.commit()
                except Exception as e:
                    background_errors.append(str(e))
                time.sleep(0.005)

        executor = ThreadPoolExecutor(max_workers=2)
        bg_future1 = executor.submit(_background_db_worker)
        bg_future2 = executor.submit(_background_db_worker)

        try:
            async def _client_worker(index: int) -> Tuple[int, str]:
                client = AdversarialTacacsClient("127.0.0.1", self.port)
                try:
                    await client.connect()
                    status, msg = await client.account(
                        user=f"contention_user_{index}",
                        cmd="show",
                        args=["environment", f"sensor_{index}"],
                        flags=TAC_PLUS_ACCT_FLAG_STOP,
                        priv_lvl=7,
                    )
                    return status, msg
                finally:
                    await client.close()

            # Fire all 50 concurrent TCP clients simultaneously under heavy background contention
            results = await asyncio.gather(*[_client_worker(i) for i in range(concurrency_count)])

            # Verify every client succeeded
            for i, (status, msg) in enumerate(results):
                self.assertEqual(
                    status,
                    TAC_PLUS_ACCT_STATUS_SUCCESS,
                    f"Client {i} failed under DB contention: status={status}, msg={msg.strip()}",
                )

            # Verify DB recorded all 50 records
            with get_db_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) FROM tacacs_accounting WHERE cmd LIKE 'show environment sensor_%'"
                )
                count = cursor.fetchone()[0]
                self.assertEqual(count, concurrency_count)

        finally:
            stop_background = True
            executor.shutdown(wait=True)

        self.assertEqual(
            len(background_errors),
            0,
            f"External DB workers encountered locking errors: {background_errors[:5]}",
        )


if __name__ == "__main__":
    unittest.main()
