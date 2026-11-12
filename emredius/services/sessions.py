# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""RADIUS accounting sessions: listing, RFC 5176 Disconnect-Request via radclient, ghost session cleanup."""
import ipaddress
import logging
import re

import pymysql

from ..core import get_db, is_valid_ip, run_cmd, safe_int
from .radius_users import ServiceError

log = logging.getLogger(__name__)

ACTIVE_LIMIT = 1000  # max. active sessions rendered on the page (the badge shows the real total)
PAST_LIMIT = 50
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def radclient_attr_value(value, max_len=253):
    """Makes a value safe for a double-quoted radclient attribute: strips CR/LF and other control characters,
    escapes backslash and double quote. Truncation happens BEFORE escaping so an escape is never cut in half."""
    s = _CTRL_RE.sub("", str(value if value is not None else ""))[:max_len]
    return s.replace("\\", "\\\\").replace('"', '\\"')


def find_nas(nasip, nas_rows):
    """Finds the NAS row for a NAS IP: exact nasname match first, otherwise the most specific CIDR block containing it."""
    try:
        ip = ipaddress.ip_address(str(nasip).strip())
    except ValueError:
        return None
    best, best_prefix = None, -1
    for r in nas_rows:
        name = (r.get("nasname") or "").strip()
        if not name:
            continue
        if name == str(nasip).strip():
            return r
        if "/" in name:
            try:
                net = ipaddress.ip_network(name, strict=False)
            except ValueError:
                continue
            if net.version == ip.version and ip in net and net.prefixlen > best_prefix:
                best, best_prefix = r, net.prefixlen
        else:
            try:
                if ipaddress.ip_address(name) == ip:
                    return r
            except ValueError:
                continue
    return best


def list_sessions():
    """Returns dict(active_total, active, past)."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM radacct WHERE acctstoptime IS NULL")
            active_total = int((cur.fetchone() or {}).get("c") or 0)
            cur.execute("""
                SELECT radacctid, acctsessionid, username, framedipaddress, callingstationid,
                       nasipaddress, acctstarttime, acctsessiontime,
                       acctinputoctets, acctoutputoctets
                FROM radacct
                WHERE acctstoptime IS NULL
                ORDER BY radacctid DESC
                LIMIT %s
            """, (ACTIVE_LIMIT,))
            active = cur.fetchall()
            cur.execute("""
                SELECT radacctid, username, framedipaddress, callingstationid,
                       nasipaddress, acctstarttime, acctstoptime, acctsessiontime,
                       acctinputoctets, acctoutputoctets, acctterminatecause
                FROM radacct
                WHERE acctstoptime IS NOT NULL
                ORDER BY radacctid DESC LIMIT %s
            """, (PAST_LIMIT,))
            past = cur.fetchall()
    finally:
        conn.close()
    return {"active_total": active_total, "active": active, "past": past}


def disconnect(radacctid):
    """Sends a Disconnect-Request for one open session.
    Returns dict(result=ack|nak|timeout|error, username, target, detail). Raises ServiceError for
    'session not found / already closed / no NAS' cases (dict `audit` attribute set when it must be logged)."""
    conn = get_db()
    nas_rows = []
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT radacctid, username, nasipaddress, framedipaddress, acctsessionid, acctstoptime
                FROM radacct WHERE radacctid = %s
            """, (radacctid,))
            row = cur.fetchone()
            if row:
                cur.execute("SELECT id, nasname, shortname, secret, ports FROM nas")
                nas_rows = cur.fetchall()
    finally:
        conn.close()

    if not row:
        raise ServiceError("Oturum bulunamadı!")
    if row.get("acctstoptime") is not None:
        raise ServiceError("Bu oturum zaten sonlanmış.")
    username = row.get("username") or ""
    nasip = (row.get("nasipaddress") or "").strip()
    if not is_valid_ip(nasip):
        raise ServiceError(f"Oturumun NAS adresi geçersiz ('{nasip}'); Disconnect-Request gönderilemedi.")

    nas_row = find_nas(nasip, nas_rows)
    if not nas_row or not (nas_row.get("secret") or ""):
        return {"result": "no_nas", "username": username, "target": nasip, "detail": ""}

    secret = nas_row["secret"]
    coa_port = safe_int(nas_row.get("ports"), 3799, 1, 65535)
    lines = [f'User-Name = "{radclient_attr_value(username)}"']
    framedip = (row.get("framedipaddress") or "").strip()
    if framedip:
        try:
            if ipaddress.ip_address(framedip).version == 4:
                lines.append(f"Framed-IP-Address = {ipaddress.ip_address(framedip)}")
        except ValueError:
            pass
    session_id = row.get("acctsessionid") or ""
    if session_id:
        lines.append(f'Acct-Session-Id = "{radclient_attr_value(session_id)}"')
    packet = "\n".join(lines) + "\n"

    target = f"[{nasip}]:{coa_port}" if ":" in nasip else f"{nasip}:{coa_port}"
    cmd = ["radclient", "-r", "1", "-t", "3", target, "disconnect", secret]
    if secret.startswith("-"):
        # keep getopt from treating the secret as an option
        cmd = ["radclient", "-r", "1", "-t", "3", "--", target, "disconnect", secret]
    rc, out, err = run_cmd(cmd, timeout=12, input_text=packet)
    combined = f"{out}\n{err}"
    # radclient prints "Received Disconnect-ACK Id ..." on success. On a NAK it prints
    # "Expected Disconnect-ACK got Disconnect-NAK", so a plain substring test for "Disconnect-ACK" is not enough.
    is_nak = "Disconnect-NAK" in combined
    is_ack = (not is_nak) and bool(re.search(r"(Received|rad_recv:)\s+Disconnect-ACK\b", combined))

    if is_ack:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE radacct SET acctstoptime = NOW(), acctterminatecause = 'Admin-Reset'
                    WHERE radacctid = %s AND acctstoptime IS NULL
                """, (radacctid,))
        finally:
            conn.close()
        return {"result": "ack", "username": username, "target": target, "detail": ""}
    if is_nak:
        m = re.search(r"Error-Cause\s*=\s*([^\r\n]+)", combined)
        return {"result": "nak", "username": username, "target": target,
                "detail": m.group(1).strip()[:80] if m else "belirtilmedi"}
    if re.search(r"no (reply|response)", combined, re.I) or "[timeout]" in combined:
        return {"result": "timeout", "username": username, "target": target, "detail": ""}
    detail = (err or out or f"radclient çıkış kodu {rc}").strip().splitlines()
    return {"result": "error", "username": username, "target": target,
            "detail": detail[-1][:200] if detail else f"radclient çıkış kodu {rc}"}


def clean_ghost_sessions():
    """Closes sessions without any accounting update for 24 h. Returns the number of closed rows."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            try:
                # a session is a ghost when the NAS has not sent ANY accounting update (start/interim) for 24 h
                cur.execute("""
                    UPDATE radacct
                    SET acctstoptime = NOW(), acctterminatecause = 'Ghost-Session-Timeout'
                    WHERE acctstoptime IS NULL
                      AND COALESCE(acctupdatetime, acctstarttime) < NOW() - INTERVAL 24 HOUR
                """)
            except pymysql.MySQLError as e:
                if not (e.args and e.args[0] == 1054):  # 1054 = unknown column (schema without acctupdatetime)
                    raise
                cur.execute("""
                    UPDATE radacct
                    SET acctstoptime = NOW(), acctterminatecause = 'Ghost-Session-Timeout'
                    WHERE acctstoptime IS NULL AND acctstarttime < NOW() - INTERVAL 24 HOUR
                """)
            return cur.rowcount
    except Exception as e:
        log.error("clean_ghost_sessions: %s", e)
        raise ServiceError("Hayalet oturumlar temizlenemedi (veritabanı hatası).") from e
    finally:
        conn.close()
