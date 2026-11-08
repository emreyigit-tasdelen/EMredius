# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""RFC 8907 Accounting Processor and Real-Time SQLite WAL Logger."""

from __future__ import annotations

from datetime import datetime, timezone
import sqlite3
from typing import Any, List, Optional, Tuple

from nms.common.db import get_db_connection
from nms.tacacs.codec import (
    TAC_PLUS_ACCT,
    TAC_PLUS_ACCT_FLAG_START,
    TAC_PLUS_ACCT_FLAG_STOP,
    TAC_PLUS_ACCT_FLAG_WATCHDOG,
    TAC_PLUS_ACCT_STATUS_ERROR,
    TAC_PLUS_ACCT_STATUS_SUCCESS,
    AVPair,
    AcctReply,
    AcctRequest,
    TacacsHeader,
)


class AccountingProcessor:
    """Processes Accounting Requests and persists audit rows into SQLite WAL."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def process_accounting_request(
        self,
        flags: int,
        device_ip: str,
        client_ip: str,
        username: str,
        priv_lvl: int,
        av_pairs: List[AVPair],
        status: Optional[str] = None,
    ) -> Tuple[int, str]:
        """Validates flags, formats command audit string, and writes to SQLite.

        Returns:
            (status: int, server_msg: str)
        """
        # 1. Validate flags per RFC 8907 §7.1 Table 2
        valid_single = flags in (
            TAC_PLUS_ACCT_FLAG_START,
            TAC_PLUS_ACCT_FLAG_STOP,
            TAC_PLUS_ACCT_FLAG_WATCHDOG,
        )
        valid_update = flags == (TAC_PLUS_ACCT_FLAG_START | TAC_PLUS_ACCT_FLAG_WATCHDOG)
        if not (valid_single or valid_update):
            return TAC_PLUS_ACCT_STATUS_ERROR, "Invalid accounting flags combination (collision/conflict)\n"

        # 2. Extract command and attributes
        cmd = None
        cmd_args: List[str] = []
        service = "shell"
        task_id = None
        elapsed_time = 0
        record_status = "PERMITTED"
        if status:
            s_candidate = status.strip().upper()
            if s_candidate in ("PERMITTED", "DENIED"):
                record_status = s_candidate

        for pair in av_pairs:
            if pair.name == "cmd":
                cmd = pair.value
            elif pair.name == "cmd-arg":
                cmd_args.append(pair.value)
            elif pair.name == "service":
                service = pair.value
            elif pair.name == "task_id":
                task_id = pair.value
            elif pair.name == "elapsed_time":
                try:
                    elapsed_time = int(pair.value)
                except ValueError:
                    pass
            elif pair.name == "status":
                s_candidate = pair.value.strip().upper()
                if s_candidate in ("PERMITTED", "DENIED"):
                    record_status = s_candidate

        # 3. Format command string
        if cmd is not None:
            if cmd_args:
                full_cmd = f"{cmd} {' '.join(cmd_args)}".strip()
            else:
                full_cmd = cmd.strip()
        else:
            full_cmd = f"[{service} session - flag 0x{flags:02x}]"

        # 4. Atomic database insert
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            with get_db_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO tacacs_accounting 
                    (timestamp, device_ip, client_ip, username, priv_lvl, cmd, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        now_iso,
                        device_ip,
                        client_ip or device_ip,
                        username or "unknown",
                        priv_lvl,
                        full_cmd,
                        record_status,
                    ),
                )
                conn.commit()
            return TAC_PLUS_ACCT_STATUS_SUCCESS, "Accounting logged successfully\n"
        except Exception as e:
            return TAC_PLUS_ACCT_STATUS_ERROR, f"Database persistence failure: {e}\n"


async def handle_acct_packet(
    header: TacacsHeader,
    plain_body: bytes,
    session: Any,
    client_profile: Any,
    db_path: str,
) -> Tuple[Optional[TacacsHeader], Optional[bytes], bool]:
    """Processes an incoming Accounting REQUEST packet.

    Returns:
        (resp_header, resp_body_bytes, is_terminal=True)
    """
    resp_header = TacacsHeader(
        major_version=header.major_version,
        minor_version=header.minor_version,
        type=TAC_PLUS_ACCT,
        seq_no=header.seq_no + 1,
        flags=0,
        session_id=header.session_id,
        length=0,
    )

    try:
        req = AcctRequest.unpack(plain_body)
    except Exception as e:
        reply = AcctReply(
            status=TAC_PLUS_ACCT_STATUS_ERROR,
            server_msg=f"Malformed AcctRequest: {e}\n",
        )
        return resp_header, reply.pack(), True

    device_ip = getattr(session, "client_ip", "127.0.0.1")
    client_ip = req.rem_addr or device_ip
    username = req.user or getattr(session, "username", "") or "unknown"

    processor = AccountingProcessor(db_path)
    status, msg = processor.process_accounting_request(
        flags=req.flags,
        device_ip=device_ip,
        client_ip=client_ip,
        username=username,
        priv_lvl=req.priv_lvl,
        av_pairs=req.args,
    )

    reply = AcctReply(status=status, server_msg=msg)
    return resp_header, reply.pack(), True
