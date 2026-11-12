# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""RADIUS groups / profiles (radgroupreply, radgroupcheck, radusergroup)."""
import logging

import pymysql

from ..core import GROUPNAME_RE, RATE_LIMIT_RE, get_db, is_valid_vlan
from .radius_users import ServiceError

log = logging.getLogger(__name__)

# Group reply attributes managed by the group form; other radgroupreply/radgroupcheck rows are left untouched.
GROUP_MANAGED_REPLY_ATTRS = ("Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id", "Mikrotik-Rate-Limit")


def list_groups():
    conn = get_db()
    try:
        with conn.cursor() as cur:
            # Group list = union of all group tables; correlated sub-selects so duplicate rows cannot duplicate groups
            cur.execute("""
                SELECT g.groupname,
                       (SELECT r.value FROM radgroupreply r WHERE r.groupname = g.groupname AND r.attribute = 'Tunnel-Private-Group-Id' ORDER BY r.id DESC LIMIT 1) AS vlan_id,
                       (SELECT r.value FROM radgroupreply r WHERE r.groupname = g.groupname AND r.attribute = 'Mikrotik-Rate-Limit' ORDER BY r.id DESC LIMIT 1) AS rate_limit,
                       (SELECT COUNT(DISTINCT u.username) FROM radusergroup u WHERE u.groupname = g.groupname) AS member_count
                FROM (
                    SELECT groupname FROM radgroupreply
                    UNION SELECT groupname FROM radgroupcheck
                    UNION SELECT groupname FROM radusergroup
                ) g
                WHERE g.groupname IS NOT NULL AND g.groupname <> ''
                ORDER BY g.groupname ASC
            """)
            return cur.fetchall()
    finally:
        conn.close()


def validate_group(groupname, vlan, rate):
    """Returns (groupname, vlan, rate) cleaned. Raises ServiceError."""
    groupname, vlan, rate = (groupname or "").strip(), (vlan or "").strip(), (rate or "").strip()
    if not GROUPNAME_RE.fullmatch(groupname):
        raise ServiceError("Geçersiz grup adı! (1-64 karakter; harf, rakam ve . _ - kullanılabilir)")
    if vlan:
        if not (vlan.isascii() and is_valid_vlan(vlan)):
            raise ServiceError("VLAN ID 1-4094 arasında bir sayı olmalıdır!")
        vlan = str(int(vlan))
    if rate and not RATE_LIMIT_RE.fullmatch(rate):
        raise ServiceError("Geçersiz hız limiti biçimi! (Örn: 10M/5M)")
    return groupname, vlan, rate


def save_group(groupname, vlan, rate):
    """Creates the group or updates its VLAN / rate attributes. Returns (stored_groupname, existed)."""
    groupname, vlan, rate = validate_group(groupname, vlan, rate)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            # Reuse the stored spelling of an existing group (MariaDB compares names case-insensitively)
            cur.execute("""
                SELECT groupname FROM radgroupreply WHERE groupname = %s
                UNION SELECT groupname FROM radgroupcheck WHERE groupname = %s
                UNION SELECT groupname FROM radusergroup WHERE groupname = %s
                LIMIT 1
            """, (groupname, groupname, groupname))
            row = cur.fetchone()
            existed = row is not None
            if existed:
                groupname = row["groupname"]

            conn.begin()
            # radgroupreply has no unique key: replace the managed attributes instead of appending duplicates
            ph = ",".join(["%s"] * len(GROUP_MANAGED_REPLY_ATTRS))
            cur.execute(f"DELETE FROM radgroupreply WHERE groupname = %s AND attribute IN ({ph})",
                        (groupname,) + GROUP_MANAGED_REPLY_ATTRS)
            if vlan:
                cur.execute("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, 'Tunnel-Type', ':=', '13')", (groupname,))
                cur.execute("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, 'Tunnel-Medium-Type', ':=', '6')", (groupname,))
                cur.execute("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, 'Tunnel-Private-Group-Id', ':=', %s)", (groupname, vlan))
            if rate:
                cur.execute("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)", (groupname, rate))
            if vlan or rate:
                # The placeholder row is only needed while the group has no real attributes
                cur.execute("DELETE FROM radgroupreply WHERE groupname = %s AND attribute = 'Reply-Message' AND value = 'Welcome'", (groupname,))
            else:
                cur.execute("""
                    SELECT (SELECT COUNT(*) FROM radgroupreply WHERE groupname = %s)
                         + (SELECT COUNT(*) FROM radgroupcheck WHERE groupname = %s) AS n
                """, (groupname, groupname))
                if int(cur.fetchone()["n"] or 0) == 0:
                    cur.execute("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (%s, 'Reply-Message', ':=', 'Welcome')", (groupname,))
            conn.commit()
            return groupname, existed, vlan, rate
    except pymysql.MySQLError as e:
        try:
            conn.rollback()
        except Exception:
            pass
        log.error("save_group: %s", e)
        raise ServiceError("Grup kaydedilemedi (veritabanı hatası).") from e
    finally:
        conn.close()


def delete_group(groupname):
    """Deletes all rows of a group. Returns (n_attributes, n_members); (0, 0) = not found."""
    groupname = (groupname or "").strip()
    if not groupname or len(groupname) > 64:
        raise ServiceError("Geçersiz grup adı!")
    conn = get_db()
    try:
        with conn.cursor() as cur:
            conn.begin()
            cur.execute("DELETE FROM radgroupreply WHERE groupname = %s", (groupname,))
            n_reply = cur.rowcount
            cur.execute("DELETE FROM radgroupcheck WHERE groupname = %s", (groupname,))
            n_check = cur.rowcount
            cur.execute("DELETE FROM radusergroup WHERE groupname = %s", (groupname,))
            n_members = cur.rowcount
            conn.commit()
            return n_reply + n_check, n_members
    except pymysql.MySQLError as e:
        try:
            conn.rollback()
        except Exception:
            pass
        log.error("delete_group: %s", e)
        raise ServiceError("Grup silinemedi (veritabanı hatası).") from e
    finally:
        conn.close()
