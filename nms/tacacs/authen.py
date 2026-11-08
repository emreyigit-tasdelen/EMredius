# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""RFC 8907 Authentication State Machine (ASCII, PAP, CHAP, ENABLE)."""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple

from nms.common.db import get_db_connection, verify_password
from nms.tacacs.codec import (
    TAC_PLUS_AUTHEN,
    TAC_PLUS_AUTHEN_LOGIN,
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
    TAC_PLUS_REPLY_FLAG_NOECHO,
    AuthenContinue,
    AuthenReply,
    AuthenStart,
    TacacsHeader,
)


@dataclass
class AuthenSession:
    """Conversational state for multi-round-trip authentication sessions."""

    session_id: int
    client_ip: str
    username: str = ""
    authen_type: int = TAC_PLUS_AUTHEN_TYPE_ASCII
    authen_service: int = TAC_PLUS_AUTHEN_SVC_LOGIN
    priv_lvl: int = 1
    state: str = "INIT"  # "WAIT_USER", "WAIT_PASS", "WAIT_ENABLE_PASS", "DONE"
    retry_count: int = 0
    max_retries: int = 3
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)

    def is_expired(self, timeout: float = 60.0) -> bool:
        return (time.time() - self.last_activity) > timeout


def _resolve_chap_secret(
    chap_secret: Optional[str] = None, stored_hash: Optional[str] = None
) -> Optional[str]:
    """Retrieves plaintext secret for MD5 CHAP digest calculation.

    RFC 8907 §5.1 / RFC 1994 CHAP requires cleartext shared secret:
    MD5(chap_id + secret + challenge).

    Returns:
        chap_secret if present and non-empty.
        stored_hash if unhashed (legacy/test cleartext, not starting with pbkdf2).
        None if only a one-way PBKDF2 hash is available or secret is absent.
    """
    if chap_secret:
        return chap_secret
    if stored_hash and not stored_hash.startswith("pbkdf2:"):
        return stored_hash
    return None


async def handle_authen_packet(
    header: TacacsHeader,
    plain_body: bytes,
    session: Any,
    db_path: str,
) -> Tuple[Optional[TacacsHeader], Optional[bytes], bool]:
    """Processes an incoming Authentication packet (START or CONTINUE).

    Returns:
        (resp_header, resp_body_bytes, is_terminal)
    """
    resp_header = TacacsHeader(
        major_version=header.major_version,
        minor_version=header.minor_version,
        type=TAC_PLUS_AUTHEN,
        seq_no=header.seq_no + 1,
        flags=0,
        session_id=header.session_id,
        length=0,
    )

    if header.seq_no == 1:
        # Authentication START
        try:
            start = AuthenStart.unpack(plain_body)
        except Exception as e:
            reply = AuthenReply(
                status=TAC_PLUS_AUTHEN_STATUS_ERROR,
                server_msg=f"Malformed AuthenStart: {e}",
            )
            return resp_header, reply.pack(), True

        session.authen_type = start.authen_type
        session.authen_service = start.authen_service
        session.priv_lvl = start.priv_lvl
        session.last_activity = time.time()

        # 1. ENABLE Service Flow
        if start.authen_service == TAC_PLUS_AUTHEN_SVC_ENABLE:
            session.username = start.user
            session.state = "WAIT_ENABLE_PASS"
            reply = AuthenReply(
                status=TAC_PLUS_AUTHEN_STATUS_GETPASS,
                flags=TAC_PLUS_REPLY_FLAG_NOECHO,
                server_msg="Password: ",
            )
            return resp_header, reply.pack(), False

        # 2. PAP Flow
        if start.authen_type == TAC_PLUS_AUTHEN_TYPE_PAP:
            username = start.user
            password = start.data.decode("utf-8", errors="replace")
            is_valid = False
            with get_db_connection(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT password_hash, enabled FROM users WHERE username = ?",
                    (username,),
                )
                row = cursor.fetchone()
                if row and row["enabled"] and verify_password(password, row["password_hash"]):
                    is_valid = True

            if is_valid:
                reply = AuthenReply(
                    status=TAC_PLUS_AUTHEN_STATUS_PASS,
                    server_msg="PAP Authentication Successful\n",
                )
            else:
                reply = AuthenReply(
                    status=TAC_PLUS_AUTHEN_STATUS_FAIL,
                    server_msg="PAP Authentication Failed\n",
                )
            return resp_header, reply.pack(), True

        # 3. CHAP Flow
        if start.authen_type == TAC_PLUS_AUTHEN_TYPE_CHAP:
            username = start.user
            data = start.data
            if len(data) < 18:
                reply = AuthenReply(
                    status=TAC_PLUS_AUTHEN_STATUS_ERROR,
                    server_msg="CHAP payload too short (minimum 18 bytes)\n",
                )
                return resp_header, reply.pack(), True

            chap_id = data[0:1]
            challenge = data[1:-16]
            response = data[-16:]

            is_valid = False
            missing_secret = False
            with get_db_connection(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT chap_secret, password_hash, enabled FROM users WHERE username = ?",
                    (username,),
                )
                row = cursor.fetchone()
                if row and row["enabled"]:
                    chap_sec = row["chap_secret"] if "chap_secret" in row.keys() else ""
                    secret = _resolve_chap_secret(chap_sec, row["password_hash"])
                    if secret:
                        expected = hashlib.md5(chap_id + secret.encode("utf-8") + challenge).digest()
                        if hmac.compare_digest(response, expected):
                            is_valid = True
                    else:
                        missing_secret = True

            if is_valid:
                reply = AuthenReply(
                    status=TAC_PLUS_AUTHEN_STATUS_PASS,
                    server_msg="CHAP Authentication Successful\n",
                )
            else:
                fail_msg = (
                    "CHAP Authentication Failed: Account requires chap_secret or cleartext secret\n"
                    if missing_secret
                    else "CHAP Authentication Failed\n"
                )
                reply = AuthenReply(
                    status=TAC_PLUS_AUTHEN_STATUS_FAIL,
                    server_msg=fail_msg,
                )
            return resp_header, reply.pack(), True

        # 4. ASCII Interactive Flow
        if not start.user:
            session.state = "WAIT_USER"
            reply = AuthenReply(
                status=TAC_PLUS_AUTHEN_STATUS_GETUSER,
                server_msg="Username: ",
            )
            return resp_header, reply.pack(), False
        else:
            session.username = start.user
            session.state = "WAIT_PASS"
            reply = AuthenReply(
                status=TAC_PLUS_AUTHEN_STATUS_GETPASS,
                flags=TAC_PLUS_REPLY_FLAG_NOECHO,
                server_msg="Password: ",
            )
            return resp_header, reply.pack(), False

    else:
        # Authentication CONTINUE (seq_no >= 3)
        try:
            cont = AuthenContinue.unpack(plain_body)
        except Exception as e:
            reply = AuthenReply(
                status=TAC_PLUS_AUTHEN_STATUS_ERROR,
                server_msg=f"Malformed AuthenContinue: {e}",
            )
            return resp_header, reply.pack(), True

        session.last_activity = time.time()

        if cont.flags & TAC_PLUS_CONTINUE_FLAG_ABORT:
            session.state = "DONE"
            reply = AuthenReply(
                status=TAC_PLUS_AUTHEN_STATUS_FAIL,
                server_msg="Authentication aborted\n",
            )
            return resp_header, reply.pack(), True

        if session.state == "WAIT_ENABLE_PASS":
            enable_password = cont.user_msg
            is_valid = False
            with get_db_connection(db_path) as conn:
                cursor = conn.cursor()
                # Check user enable secret if user is known
                if session.username:
                    cursor.execute(
                        "SELECT enable_password_hash FROM users WHERE username = ?",
                        (session.username,),
                    )
                    row = cursor.fetchone()
                    if row and row["enable_password_hash"] and verify_password(enable_password, row["enable_password_hash"]):
                        is_valid = True

                # If user had no enable secret or username was empty, fallback to admin enable secret
                if not is_valid:
                    cursor.execute(
                        "SELECT enable_password_hash FROM users WHERE username = 'admin'"
                    )
                    row = cursor.fetchone()
                    if row and row["enable_password_hash"] and verify_password(enable_password, row["enable_password_hash"]):
                        is_valid = True

            session.state = "DONE"
            if is_valid:
                reply = AuthenReply(
                    status=TAC_PLUS_AUTHEN_STATUS_PASS,
                    server_msg="Enable privilege escalation successful\n",
                )
            else:
                reply = AuthenReply(
                    status=TAC_PLUS_AUTHEN_STATUS_FAIL,
                    server_msg="Enable authentication failed\n",
                )
            return resp_header, reply.pack(), True

        if session.state == "WAIT_USER":
            session.username = cont.user_msg.strip()
            session.state = "WAIT_PASS"
            reply = AuthenReply(
                status=TAC_PLUS_AUTHEN_STATUS_GETPASS,
                flags=TAC_PLUS_REPLY_FLAG_NOECHO,
                server_msg="Password: ",
            )
            return resp_header, reply.pack(), False

        if session.state == "WAIT_PASS":
            password = cont.user_msg
            is_valid = False
            with get_db_connection(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT password_hash, enabled FROM users WHERE username = ?",
                    (session.username,),
                )
                row = cursor.fetchone()
                if row and row["enabled"] and verify_password(password, row["password_hash"]):
                    is_valid = True

            if is_valid:
                session.state = "DONE"
                reply = AuthenReply(
                    status=TAC_PLUS_AUTHEN_STATUS_PASS,
                    server_msg="Authentication successful\n",
                )
                return resp_header, reply.pack(), True
            else:
                session.retry_count += 1
                if session.retry_count >= getattr(session, "max_retries", 3):
                    session.state = "DONE"
                    reply = AuthenReply(
                        status=TAC_PLUS_AUTHEN_STATUS_FAIL,
                        server_msg="Authentication failed: Max attempts exceeded\n",
                    )
                    return resp_header, reply.pack(), True
                else:
                    reply = AuthenReply(
                        status=TAC_PLUS_AUTHEN_STATUS_GETPASS,
                        flags=TAC_PLUS_REPLY_FLAG_NOECHO,
                        server_msg="Password: ",
                    )
                    return resp_header, reply.pack(), False

    # Default fallback
    reply = AuthenReply(status=TAC_PLUS_AUTHEN_STATUS_FAIL, server_msg="Invalid session state\n")
    return resp_header, reply.pack(), True
