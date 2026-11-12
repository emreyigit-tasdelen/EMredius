# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""MAC Authentication Bypass (MAB) whitelist: radcheck username = password = MAC, radius_meta.account_type = 'mac'."""
import logging

import pymysql

from ..core import get_db, is_valid_vlan, lookup_mac_vendor, normalize_mac
from .radius_users import ServiceError

log = logging.getLogger(__name__)

MAC_DESC_MAX_LEN = 255
_VLAN_ATTRS = ("Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id")


def list_macs():
    """(whitelisted devices, last 5 rejected MAC-like logins)."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT c.username AS mac,
                       (SELECT r.value FROM radreply r WHERE r.username = c.username AND r.attribute = 'Tunnel-Private-Group-Id' ORDER BY r.id DESC LIMIT 1) AS vlan_id,
                       m.description, m.vendor, m.created_at
                FROM (SELECT username, MAX(id) AS id FROM radcheck WHERE attribute = 'Cleartext-Password' GROUP BY username) c
                JOIN radius_meta m ON m.username = c.username
                WHERE m.account_type = 'mac'
                ORDER BY c.id DESC
            """)
            macs = cur.fetchall()
            # unknown / rejected devices (last 5 radpostauth rejects with a MAC-like username)
            cur.execute("""
                SELECT username, authdate, reply
                FROM radpostauth
                WHERE reply = 'Access-Reject' AND (username LIKE '%:%' OR username LIKE '%-%')
                ORDER BY id DESC LIMIT 5
            """)
            unknown = cur.fetchall()
    finally:
        conn.close()
    for m in macs:
        m["vendor"] = m.get("vendor") or lookup_mac_vendor(m["mac"])
    for p in unknown:
        p["vendor"] = lookup_mac_vendor(p["username"])
    return macs, unknown


def _is_mac_account(cur, mac):
    cur.execute("SELECT account_type FROM radius_meta WHERE username = %s", (mac,))
    return any((r.get("account_type") or "") == "mac" for r in cur.fetchall())


def add_mac(raw_mac, desc, vlan):
    """Adds or updates a whitelisted MAC. Returns (mac, vendor, vlan)."""
    mac = normalize_mac(raw_mac or "")
    if not mac:
        raise ServiceError("Geçersiz MAC adresi formatı! 12 onaltılık karakter olmalıdır.")
    desc = (desc or "").strip()
    if not desc or len(desc) > MAC_DESC_MAX_LEN:
        raise ServiceError(f"Cihaz tanımı zorunludur (en fazla {MAC_DESC_MAX_LEN} karakter).")
    vlan = (vlan or "").strip()
    if vlan:
        if not (vlan.isascii() and is_valid_vlan(vlan)):
            raise ServiceError("VLAN ID 1-4094 arasında bir sayı olmalıdır!")
        vlan = str(int(vlan))
    vendor = lookup_mac_vendor(mac)

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 AS x FROM radcheck WHERE username = %s LIMIT 1", (mac,))
            if cur.fetchone() and not _is_mac_account(cur, mac):
                raise ServiceError(f"'{mac}' adı başka bir hesap tarafından kullanılıyor.")
            conn.begin()
            # radcheck / radreply have no unique key: replace the managed rows instead of appending duplicates
            cur.execute("DELETE FROM radcheck WHERE username = %s AND attribute = 'Cleartext-Password'", (mac,))
            cur.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, 'Cleartext-Password', ':=', %s)",
                        (mac, mac))
            ph = ",".join(["%s"] * len(_VLAN_ATTRS))
            cur.execute(f"DELETE FROM radreply WHERE username = %s AND attribute IN ({ph})", (mac,) + _VLAN_ATTRS)
            if vlan:
                cur.execute("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Tunnel-Type', ':=', '13')", (mac,))
                cur.execute("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Tunnel-Medium-Type', ':=', '6')", (mac,))
                cur.execute("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Tunnel-Private-Group-Id', ':=', %s)", (mac, vlan))
            cur.execute("SELECT 1 AS x FROM radius_meta WHERE username = %s LIMIT 1", (mac,))
            if cur.fetchone():
                cur.execute("UPDATE radius_meta SET account_type = 'mac', description = %s, vendor = %s WHERE username = %s",
                            (desc, vendor, mac))
            else:
                cur.execute("INSERT INTO radius_meta (username, account_type, description, vendor) VALUES (%s, 'mac', %s, %s)",
                            (mac, desc, vendor))
            conn.commit()
    except pymysql.MySQLError as e:
        try:
            conn.rollback()
        except Exception:
            pass
        log.error("add_mac: %s", e)
        raise ServiceError("MAC adresi kaydedilemedi (veritabanı hatası).") from e
    finally:
        conn.close()
    return mac, vendor, vlan


def delete_mac(raw_mac):
    """Deletes a whitelisted MAC (only accounts of type 'mac'). Returns the normalised MAC."""
    mac = normalize_mac(raw_mac or "")
    if not mac:
        raise ServiceError("Geçersiz MAC adresi!")
    conn = get_db()
    try:
        with conn.cursor() as cur:
            if not _is_mac_account(cur, mac):
                raise ServiceError(f"'{mac}' MAC listesinde bulunamadı.")
            conn.begin()
            cur.execute("DELETE FROM radcheck WHERE username = %s", (mac,))
            cur.execute("DELETE FROM radreply WHERE username = %s", (mac,))
            cur.execute("DELETE FROM radusergroup WHERE username = %s", (mac,))
            cur.execute("DELETE FROM radius_meta WHERE username = %s", (mac,))
            conn.commit()
    except pymysql.MySQLError as e:
        try:
            conn.rollback()
        except Exception:
            pass
        log.error("delete_mac: %s", e)
        raise ServiceError("MAC adresi silinemedi (veritabanı hatası).") from e
    finally:
        conn.close()
    return mac
