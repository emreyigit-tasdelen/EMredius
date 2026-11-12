# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""RFC 8907 Authorization and Regex Command Policy Engine."""

from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple

from nms.common.db import get_db_connection
from nms.tacacs.codec import (
    TAC_PLUS_AUTHOR,
    TAC_PLUS_AUTHOR_STATUS_ERROR,
    TAC_PLUS_AUTHOR_STATUS_FAIL,
    TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
    AVPair,
    AuthorReply,
    AuthorRequest,
    TacacsHeader,
)


def reconstruct_command_line(av_pairs: List[AVPair]) -> Tuple[Optional[str], str]:
    """Extracts service, cmd, and reconstructs the full command line.

    Returns:
        (service_name, reconstructed_command_line)
    """
    service = None
    cmd = None
    args: List[str] = []

    for pair in av_pairs:
        if pair.name == "service":
            service = pair.value
        elif pair.name == "cmd":
            cmd = pair.value
        elif pair.name == "cmd-arg":
            args.append(pair.value)

    if cmd is None or cmd == "":
        return service, ""

    if args:
        full_command = f"{cmd} {' '.join(args)}".strip()
    else:
        full_command = cmd.strip()

    return service, full_command


def build_vendor_shell_av_pairs(vendor: str, priv_lvl: int, group_name: str = "") -> List[AVPair]:
    """Constructs vendor-tailored AV-pairs for session-level EXEC shell authorization."""
    vendor_lower = (vendor or "cisco").lower()
    pairs = [AVPair("service", "=", "shell")]

    if vendor_lower in ("cisco", "generic"):
        pairs.append(AVPair("priv-lvl", "=", str(priv_lvl)))
        pairs.append(AVPair("timeout", "*", "0"))
        pairs.append(AVPair("idletime", "*", "15"))

    elif vendor_lower == "juniper":
        template_name = "super-user" if priv_lvl >= 15 else ("operator" if priv_lvl >= 7 else "read-only")
        pairs = [
            AVPair("service", "=", "junos-exec"),
            AVPair("local-user-name", "=", template_name),
        ]

    elif vendor_lower == "fortinet":
        admin_prof = "super_admin" if priv_lvl >= 15 else "read_only"
        pairs = [
            AVPair("service", "=", "fortigate"),
            AVPair("admin_prof", "=", admin_prof),
            AVPair("vdom", "*", "root"),
        ]

    elif vendor_lower in ("aruba", "hp"):
        pairs.append(AVPair("priv-lvl", "=", str(priv_lvl)))
        role_name = "network-admin" if priv_lvl >= 15 else "network-operator"
        pairs.append(AVPair("user-role", "=", role_name))
        pairs.append(AVPair("Aruba-Admin-Role", "=", "administrators" if priv_lvl >= 15 else "operators"))

    elif vendor_lower == "huawei":
        huawei_priv = 3 if priv_lvl >= 15 else (2 if priv_lvl >= 7 else 1)
        pairs.append(AVPair("priv-lvl", "=", str(huawei_priv)))
        pairs.append(AVPair("Huawei-Exec-Privilege", "=", str(huawei_priv)))

    return pairs


class RegexPolicyEngine:
    """Evaluates reconstructed command lines against database regex rules."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def evaluate(
        self,
        username: str,
        full_cmd: str,
        user_priv: int = 1,
    ) -> Tuple[bool, str]:
        """Evaluates full_cmd against ordered regex rules for user's group.

        Returns:
            (is_permitted, reason)
        """
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT u.id, u.username, u.priv_lvl, u.group_id, g.name AS group_name, g.default_policy
                FROM users u
                LEFT JOIN groups g ON u.group_id = g.id
                WHERE u.username = ?
                """,
                (username,),
            )
            user_row = cursor.fetchone()

            group_id = None
            default_policy = "deny"
            effective_priv = user_priv

            if user_row:
                group_id = user_row["group_id"]
                effective_priv = user_row["priv_lvl"] if user_row["priv_lvl"] is not None else user_priv
                default_policy = user_row["default_policy"] or "deny"
            else:
                # User not in DB; check if a group matches the requested priv_lvl
                cursor.execute(
                    "SELECT id, default_policy FROM groups WHERE priv_lvl = ? LIMIT 1",
                    (user_priv,),
                )
                grp = cursor.fetchone()
                if grp:
                    group_id = grp["id"]
                    default_policy = grp["default_policy"] or "deny"

            if not group_id:
                # If no group found, admin (priv 15) permits by default, otherwise deny
                if effective_priv >= 15:
                    return True, "Permitted by administrative fallback"
                return False, "No group policy defined"

            cursor.execute(
                """
                SELECT pattern, action, description
                FROM tacacs_rules
                WHERE group_id = ?
                ORDER BY priority ASC, id ASC
                """,
                (group_id,),
            )
            rules = cursor.fetchall()

            for r in rules:
                pattern = r["pattern"]
                action = r["action"].strip().lower()
                desc = r["description"] or ""
                try:
                    if re.search(pattern, full_cmd, re.IGNORECASE):
                        if action == "permit":
                            return True, f"Permitted by rule: {pattern} ({desc})"
                        else:
                            return False, f"Denied by rule: {pattern} ({desc})"
                except re.error:
                    continue

            # Fallback to group default policy
            if default_policy.lower() == "permit":
                return True, "Permitted by group default policy"
            return False, "Denied by group default policy"


async def handle_author_packet(
    header: TacacsHeader,
    plain_body: bytes,
    session: Any,
    client_profile: Any,
    db_path: str,
) -> Tuple[Optional[TacacsHeader], Optional[bytes], bool]:
    """Processes an incoming Authorization REQUEST packet.

    Returns:
        (resp_header, resp_body_bytes, is_terminal=True)
    """
    resp_header = TacacsHeader(
        major_version=header.major_version,
        minor_version=header.minor_version,
        type=TAC_PLUS_AUTHOR,
        seq_no=header.seq_no + 1,
        flags=0,
        session_id=header.session_id,
        length=0,
    )

    try:
        req = AuthorRequest.unpack(plain_body)
    except Exception as e:
        reply = AuthorReply(
            status=TAC_PLUS_AUTHOR_STATUS_ERROR,
            server_msg=f"Malformed AuthorRequest: {e}",
        )
        return resp_header, reply.pack(), True

    service, full_cmd = reconstruct_command_line(req.args)
    vendor = getattr(client_profile, "vendor", "cisco") if client_profile else "cisco"
    username = req.user or getattr(session, "username", "")

    if not username:
        reply = AuthorReply(
            status=TAC_PLUS_AUTHOR_STATUS_FAIL,
            server_msg="Anonymous authorization rejected: user required\n",
        )
        return resp_header, reply.pack(), True

    # Case 1: Session-level EXEC Shell Authorization (cmd is empty)
    if not full_cmd:
        priv_lvl = req.priv_lvl
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT priv_lvl FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row and row["priv_lvl"] is not None:
                priv_lvl = row["priv_lvl"]

        resp_args = build_vendor_shell_av_pairs(vendor=vendor, priv_lvl=priv_lvl)
        reply = AuthorReply(
            status=TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            server_msg="Shell session authorized\n",
            args=resp_args,
        )
        return resp_header, reply.pack(), True

    # Case 2: Per-Command Authorization
    engine = RegexPolicyEngine(db_path)
    is_permitted, reason = engine.evaluate(
        username=username,
        full_cmd=full_cmd,
        user_priv=req.priv_lvl,
    )

    if is_permitted:
        reply = AuthorReply(
            status=TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
            server_msg=f"{reason}\n",
        )
    else:
        reply = AuthorReply(
            status=TAC_PLUS_AUTHOR_STATUS_FAIL,
            server_msg=f"{reason}\n",
        )

    return resp_header, reply.pack(), True
