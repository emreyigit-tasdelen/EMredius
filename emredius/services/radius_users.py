# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""RADIUS user accounts (radcheck / radreply / radusergroup / radius_meta): validation, CRUD, CSV export/import.
No HTTP handling here: functions take plain values and return data or raise ServiceError."""
import csv
import io
import ipaddress
import logging

import pymysql

from ..core import tenant as tn
from ..core import RATE_LIMIT_RE, USERNAME_RE, get_db, is_valid_ip, is_valid_vlan

log = logging.getLogger(__name__)

# Reply attributes owned by the user forms; any other per-user radreply attribute is left untouched on edit.
USER_VLAN_REPLY_ATTRS = ("Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-Id")
USER_MANAGED_REPLY_ATTRS = USER_VLAN_REPLY_ATTRS + ("Framed-IP-Address", "Mikrotik-Rate-Limit")
USER_IMPORT_MAX_ROWS = 5000
USER_IMPORT_MAX_BYTES = 5 * 1024 * 1024
USER_PASSWORD_MAX_LEN = 253
USER_DESC_MAX_LEN = 255
RATE_LIMIT_OPTIONS = (
    ("5M/2M", "5 Mbps / 2 Mbps"),
    ("10M/5M", "10 Mbps / 5 Mbps"),
    ("25M/10M", "25 Mbps / 10 Mbps"),
    ("50M/20M", "50 Mbps / 20 Mbps"),
    ("100M/50M", "100 Mbps / 50 Mbps"),
)
# Cells starting with one of these are interpreted as formulas by spreadsheet applications (CSV injection)
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_IMPORT_HEADER_ALIASES = {
    "username": "username", "user": "username", "user_name": "username", "kullanici": "username",
    "kullanıcı": "username", "kullanici_adi": "username", "kullanıcı_adı": "username", "code": "username",
    "password": "password", "pass": "password", "sifre": "password", "şifre": "password",
    "vlan_id": "vlan", "vlan": "vlan", "vlanid": "vlan",
    "static_ip": "static_ip", "ip": "static_ip", "framed_ip": "static_ip", "statik_ip": "static_ip",
    "framed_ip_address": "static_ip",
    "rate_limit": "rate", "rate": "rate", "hiz": "rate", "hız": "rate", "hiz_limiti": "rate", "hız_limiti": "rate",
    "groupname": "group", "group": "group", "grup": "group",
    "description": "desc", "desc": "desc", "aciklama": "desc", "açıklama": "desc", "note": "desc", "not": "desc",
}
# Legacy header-less column order (users page help text and batch page help text)
_IMPORT_DEFAULT_COLUMNS = {"username": 0, "password": 1, "vlan": 2, "rate": 3, "desc": 4}


class ServiceError(Exception):
    """User-facing error (message is safe to flash)."""


def get_radius_group_names(cur):
    """All RADIUS group names = union of radgroupreply, radgroupcheck and radusergroup (sorted, case-insensitive)."""
    cur.execute("""
        SELECT groupname FROM radgroupreply
        UNION SELECT groupname FROM radgroupcheck
        UNION SELECT groupname FROM radusergroup
    """)
    names = {}
    for r in cur.fetchall():
        g = r.get("groupname")
        if g and str(g).strip():
            names.setdefault(str(g).lower(), str(g))
    return sorted(names.values(), key=lambda s: s.lower())


def _s(v):
    return "" if v is None else str(v).strip()


def validate_radius_user_fields(fields, group_names=None, check_username=True, password_required=True):
    """Server-side validation of a RADIUS user record.
    fields: dict with username, password, vlan, static_ip, rate, group, desc.
    Returns (error_message, None) or (None, cleaned_dict) — the group name is canonicalised to the stored spelling."""
    username = _s(fields.get("username"))
    password = _s(fields.get("password"))
    vlan = _s(fields.get("vlan"))
    static_ip = _s(fields.get("static_ip"))
    rate = _s(fields.get("rate"))
    group = _s(fields.get("group"))
    desc = _s(fields.get("desc"))

    if check_username:
        if not USERNAME_RE.fullmatch(username):
            return "Geçersiz kullanıcı adı! (1-64 karakter; harf, rakam ve . _ @ : + - kullanılabilir)", None
    elif not username or len(username) > 253:
        return "Geçersiz kullanıcı adı!", None
    if password_required and not password:
        return "Şifre zorunludur!", None
    if len(password) > USER_PASSWORD_MAX_LEN:
        return f"Şifre en fazla {USER_PASSWORD_MAX_LEN} karakter olabilir!", None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in password):
        return "Şifre kontrol karakteri içeremez!", None
    if vlan:
        if not (vlan.isascii() and is_valid_vlan(vlan)):
            return "VLAN ID 1-4094 arasında bir sayı olmalıdır!", None
        vlan = str(int(vlan))
    if static_ip:
        if not is_valid_ip(static_ip) or ipaddress.ip_address(static_ip).version != 4:
            return "Statik IP geçerli bir IPv4 adresi olmalıdır!", None
        static_ip = str(ipaddress.ip_address(static_ip))
    if rate and not RATE_LIMIT_RE.fullmatch(rate):
        return "Geçersiz hız limiti biçimi! (Örn: 10M/5M)", None
    if group:
        canon = {g.lower(): g for g in (group_names or [])}.get(group.lower())
        if not canon:
            return f"'{group[:64]}' adında bir grup bulunamadı!", None
        group = canon
    if len(desc) > USER_DESC_MAX_LEN:
        return f"Açıklama en fazla {USER_DESC_MAX_LEN} karakter olabilir!", None
    return None, {
        "username": username, "password": password, "vlan": vlan, "static_ip": static_ip,
        "rate": rate, "group": group, "desc": desc,
    }


def get_user_account(cur, username):
    """Canonical username of a regular RADIUS user (the scope of the users page) or None."""
    if not username or len(username) > 253:
        return None
    cur.execute("""
        SELECT c.username FROM radcheck c
        LEFT JOIN radius_meta m ON m.username = c.username
        WHERE c.username = %s AND c.attribute = 'Cleartext-Password'
          AND (m.account_type IS NULL OR m.account_type = 'user')
        LIMIT 1
    """, (username,))
    row = cur.fetchone()
    return row["username"] if row else None


def upsert_meta(cur, username, desc, static_ip, account_type="user"):
    """radius_meta upsert that does not depend on a unique key on username."""
    cur.execute("SELECT username FROM radius_meta WHERE username = %s LIMIT 1", (username,))
    if cur.fetchone():
        cur.execute("UPDATE radius_meta SET account_type = %s, description = %s, static_ip = %s WHERE username = %s",
                    (account_type, desc, static_ip, username))
    else:
        cur.execute("INSERT INTO radius_meta (username, account_type, description, static_ip) VALUES (%s, %s, %s, %s)",
                    (username, account_type, desc, static_ip))


def insert_reply_attrs(cur, username, vlan, static_ip, rate):
    if vlan:
        cur.execute("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Tunnel-Type', ':=', '13')", (username,))
        cur.execute("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Tunnel-Medium-Type', ':=', '6')", (username,))
        cur.execute("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Tunnel-Private-Group-Id', ':=', %s)", (username, vlan))
    if static_ip:
        cur.execute("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Framed-IP-Address', ':=', %s)", (username, static_ip))
    if rate:
        cur.execute("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)", (username, rate))


def delete_managed_reply(cur, username):
    ph = ",".join(["%s"] * len(USER_MANAGED_REPLY_ATTRS))
    cur.execute(f"DELETE FROM radreply WHERE username = %s AND attribute IN ({ph})", (username,) + USER_MANAGED_REPLY_ATTRS)


def csv_cell(value):
    """CSV/formula-injection safe cell (Excel/LibreOffice must not evaluate exported values)."""
    s = "" if value is None else str(value)
    if s and s[0] in _CSV_FORMULA_PREFIXES:
        return "'" + s
    return s


def csv_uncell(value):
    """Reverses csv_cell so an exported file can be re-imported without altering the values."""
    s = value or ""
    if len(s) >= 2 and s[0] == "'" and s[1] in _CSV_FORMULA_PREFIXES:
        return s[1:]
    return s


def _rollback(conn):
    try:
        conn.rollback()
    except Exception:
        pass


# ---------- users page ----------

def list_users():
    """(users, group_names) for the users page."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            # Correlated sub-selects instead of LEFT JOINs: duplicate attribute rows can no longer duplicate table rows.
            cur.execute("""
                SELECT c.username,
                       (SELECT r.value FROM radreply r WHERE r.username = c.username AND r.attribute = 'Tunnel-Private-Group-Id' ORDER BY r.id DESC LIMIT 1) AS vlan_id,
                       (SELECT r.value FROM radreply r WHERE r.username = c.username AND r.attribute = 'Framed-IP-Address' ORDER BY r.id DESC LIMIT 1) AS static_ip,
                       (SELECT r.value FROM radreply r WHERE r.username = c.username AND r.attribute = 'Mikrotik-Rate-Limit' ORDER BY r.id DESC LIMIT 1) AS rate_limit,
                       (SELECT t.value FROM radcheck t WHERE t.username = c.username AND t.attribute = 'Login-Time' ORDER BY t.id DESC LIMIT 1) AS login_time,
                       (SELECT t.value FROM radcheck t WHERE t.username = c.username AND t.attribute = 'Simultaneous-Use' ORDER BY t.id DESC LIMIT 1) AS sim_use,
                       EXISTS (SELECT 1 FROM radcheck t WHERE t.username = c.username AND t.attribute = 'Auth-Type' AND t.value = 'Reject') AS is_disabled,
                       (SELECT ug.groupname FROM radusergroup ug WHERE ug.username = c.username ORDER BY ug.priority ASC LIMIT 1) AS groupname,
                       m.description, m.created_at
                FROM (SELECT username, MAX(id) AS id FROM radcheck WHERE attribute = 'Cleartext-Password' GROUP BY username) c
                LEFT JOIN radius_meta m ON m.username = c.username
                WHERE (m.account_type IS NULL OR m.account_type = 'user')
                ORDER BY c.id DESC
            """)
            users = cur.fetchall()
            groups = get_radius_group_names(cur)
    finally:
        conn.close()
    return tn.filter_owned("radius_user", users, lambda u: u["username"]), groups


def edit_payload(u):
    """Data for the edit modal (never contains the password)."""
    return {
        "username": u["username"],
        "vlan_id": u["vlan_id"] or "",
        "static_ip": u["static_ip"] or "",
        "rate_limit": u["rate_limit"] or "",
        "groupname": u["groupname"] or "",
        "work_hours": bool(u["login_time"]),
        "single_device": str(u["sim_use"] or "") == "1",
        "description": u["description"] or "",
    }


def get_password(username):
    """(canonical_username, password) of a regular user, or (None, None)."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            canon = get_user_account(cur, username)
            if not canon:
                return None, None
            cur.execute("SELECT value FROM radcheck WHERE username = %s AND attribute = 'Cleartext-Password' "
                        "ORDER BY id DESC LIMIT 1", (canon,))
            row = cur.fetchone()
            return (canon, row["value"]) if row else (None, None)
    finally:
        conn.close()


def add_user(fields, work_hours, single_device):
    """Creates a user; returns the cleaned field dict. Raises ServiceError."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            err, d = validate_radius_user_fields(fields, group_names=get_radius_group_names(cur))
            if err:
                raise ServiceError(err)
            u = d["username"]
            # Any radcheck row (user, MAC, voucher...) means the name is taken
            cur.execute("SELECT username FROM radcheck WHERE username = %s LIMIT 1", (u,))
            if cur.fetchone():
                raise ServiceError(f"'{u}' kullanıcısı zaten mevcut!")

            conn.begin()
            # Orphan reply/group rows of a previously removed account must not leak into the new user
            delete_managed_reply(cur, u)
            cur.execute("DELETE FROM radusergroup WHERE username = %s", (u,))
            cur.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, 'Cleartext-Password', ':=', %s)", (u, d["password"]))
            if work_hours:
                cur.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, 'Login-Time', ':=', 'Wk0800-1800')", (u,))
            if single_device:
                cur.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, 'Simultaneous-Use', ':=', '1')", (u,))
            insert_reply_attrs(cur, u, d["vlan"], d["static_ip"], d["rate"])
            if d["group"]:
                cur.execute("INSERT INTO radusergroup (username, groupname, priority) VALUES (%s, %s, 1)", (u, d["group"]))
            upsert_meta(cur, u, d["desc"], d["static_ip"], "user")
            conn.commit()
            tn.set_owners("radius_user", [u])
            return d
    except pymysql.MySQLError as e:
        _rollback(conn)
        log.error("add_user: %s", e)
        raise ServiceError("Kullanıcı oluşturulamadı (veritabanı hatası).") from e
    finally:
        conn.close()


def edit_user(fields, work_hours, single_device):
    """Updates a regular user; returns (canonical_username, cleaned fields). Raises ServiceError."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            err, d = validate_radius_user_fields(fields, group_names=get_radius_group_names(cur),
                                                 check_username=False, password_required=False)
            if err:
                raise ServiceError(err)
            u = get_user_account(cur, d["username"])
            if not u:
                raise ServiceError("Düzenlenecek kullanıcı bulunamadı!")

            conn.begin()
            # Empty password field = keep the existing password
            if d["password"]:
                cur.execute("UPDATE radcheck SET value = %s WHERE username = %s AND attribute = 'Cleartext-Password'", (d["password"], u))

            # Work-hours: an existing (possibly custom) Login-Time is kept while the box stays checked
            cur.execute("SELECT id FROM radcheck WHERE username = %s AND attribute = 'Login-Time' LIMIT 1", (u,))
            has_login_time = cur.fetchone() is not None
            if not work_hours:
                cur.execute("DELETE FROM radcheck WHERE username = %s AND attribute = 'Login-Time'", (u,))
            elif not has_login_time:
                cur.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, 'Login-Time', ':=', 'Wk0800-1800')", (u,))

            # Single-device: only the '1' rule is managed by the checkbox; other Simultaneous-Use limits are kept
            if single_device:
                cur.execute("DELETE FROM radcheck WHERE username = %s AND attribute = 'Simultaneous-Use'", (u,))
                cur.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, 'Simultaneous-Use', ':=', '1')", (u,))
            else:
                cur.execute("DELETE FROM radcheck WHERE username = %s AND attribute = 'Simultaneous-Use' AND value = '1'", (u,))

            # Replace only the reply attributes managed by this form
            delete_managed_reply(cur, u)
            insert_reply_attrs(cur, u, d["vlan"], d["static_ip"], d["rate"])

            cur.execute("DELETE FROM radusergroup WHERE username = %s", (u,))
            if d["group"]:
                cur.execute("INSERT INTO radusergroup (username, groupname, priority) VALUES (%s, %s, 1)", (u, d["group"]))
            upsert_meta(cur, u, d["desc"], d["static_ip"], "user")
            conn.commit()
            return u, d
    except pymysql.MySQLError as e:
        _rollback(conn)
        log.error("edit_user: %s", e)
        raise ServiceError("Kullanıcı güncellenemedi (veritabanı hatası).") from e
    finally:
        conn.close()


_STATE_SQL = {
    # radcheck has no unique key: remove every Auth-Type row first so exactly one Reject rule exists
    "disable": (
        ("DELETE FROM radcheck WHERE username = %s AND attribute = 'Auth-Type'",
         "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, 'Auth-Type', ':=', 'Reject')",
         "UPDATE radius_meta SET status = 'disabled' WHERE username = %s"),
        "Kullanıcı askıya alınamadı (veritabanı hatası).",
    ),
    "enable": (
        ("DELETE FROM radcheck WHERE username = %s AND attribute = 'Auth-Type' AND value = 'Reject'",
         "UPDATE radius_meta SET status = 'active' WHERE username = %s"),
        "Kullanıcı aktif edilemedi (veritabanı hatası).",
    ),
    "delete": (
        ("DELETE FROM radcheck WHERE username = %s",
         "DELETE FROM radreply WHERE username = %s",
         "DELETE FROM radusergroup WHERE username = %s",
         "DELETE FROM radius_meta WHERE username = %s"),
        "Kullanıcı silinemedi (veritabanı hatası).",
    ),
}


def change_user_state(username, action):
    """action: disable / enable / delete. Returns the canonical username. Raises ServiceError."""
    statements, db_error = _STATE_SQL[action]
    conn = get_db()
    try:
        with conn.cursor() as cur:
            u = get_user_account(cur, username)
            if not u:
                raise ServiceError("Kullanıcı bulunamadı!")
            conn.begin()
            for sql in statements:
                cur.execute(sql, (u,))
            conn.commit()
            return u
    except pymysql.MySQLError as e:
        _rollback(conn)
        log.error("change_user_state(%s): %s", action, e)
        raise ServiceError(db_error) from e
    finally:
        conn.close()


def export_users_csv():
    """(csv_text_with_bom, user_count). Passwords are included; cells are formula-injection safe."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT c.username, p.value AS password,
                       (SELECT r.value FROM radreply r WHERE r.username = c.username AND r.attribute = 'Tunnel-Private-Group-Id' ORDER BY r.id DESC LIMIT 1) AS vlan_id,
                       (SELECT r.value FROM radreply r WHERE r.username = c.username AND r.attribute = 'Framed-IP-Address' ORDER BY r.id DESC LIMIT 1) AS static_ip,
                       (SELECT r.value FROM radreply r WHERE r.username = c.username AND r.attribute = 'Mikrotik-Rate-Limit' ORDER BY r.id DESC LIMIT 1) AS rate_limit,
                       (SELECT ug.groupname FROM radusergroup ug WHERE ug.username = c.username ORDER BY ug.priority ASC LIMIT 1) AS groupname,
                       m.description
                FROM (SELECT username, MAX(id) AS id FROM radcheck WHERE attribute = 'Cleartext-Password' GROUP BY username) c
                JOIN radcheck p ON p.id = c.id
                LEFT JOIN radius_meta m ON m.username = c.username
                WHERE (m.account_type IS NULL OR m.account_type = 'user')
                ORDER BY c.username ASC
            """)
            users = cur.fetchall()
    finally:
        conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["username", "password", "vlan_id", "static_ip", "rate_limit", "description", "groupname"])
    for u in users:
        writer.writerow([csv_cell(x) for x in (
            u["username"], u["password"], u["vlan_id"] or "", u["static_ip"] or "",
            u["rate_limit"] or "", u["description"] or "", u["groupname"] or ""
        )])
    # UTF-8 BOM so Excel shows Turkish characters correctly; the importer strips it (utf-8-sig)
    return "﻿" + output.getvalue(), len(users)


# ---------- CSV import ----------

def _norm_header(cell):
    return (cell or "").strip().strip("﻿").strip().strip('"').lower().replace(" ", "_").replace("-", "_")


def _meta_source_supported(cur):
    """True when radius_meta has a `source` column that accepts 'csv' (shown as 'Toplu CSV' on the batch page)."""
    try:
        cur.execute("SHOW COLUMNS FROM radius_meta LIKE 'source'")
        col = cur.fetchone()
    except pymysql.MySQLError:
        return False
    if not col:
        return False
    col_type = str(col.get("Type") or "").lower()
    return not col_type.startswith(("enum", "set")) or "'csv'" in col_type


def parse_import_csv(raw):
    """Decodes and splits an uploaded CSV. Returns (colmap, [(line_no, row), ...]). Raises ServiceError."""
    if len(raw) > USER_IMPORT_MAX_BYTES:
        raise ServiceError(f"CSV dosyası en fazla {USER_IMPORT_MAX_BYTES // (1024 * 1024)} MB olabilir!")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("cp1254", errors="replace")  # Excel (Türkçe Windows) çıktısı
    text = text.replace("\x00", "")

    first_line = text.split("\n", 1)[0]
    delimiter = ","
    if first_line.count(";") > first_line.count(","):
        delimiter = ";"
    elif "\t" in first_line and "," not in first_line:
        delimiter = "\t"

    rows = []
    try:
        reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter)
        for row in reader:
            if row and any((c or "").strip() for c in row):
                rows.append((reader.line_num, row))
    except csv.Error as e:
        raise ServiceError(f"CSV dosyası okunamadı: {str(e)[:120]}") from e

    if not rows:
        raise ServiceError("CSV dosyasında içe aktarılacak satır bulunamadı.")

    # Header detection: a first row naming the columns maps them by name, otherwise the legacy column order is used
    colmap = dict(_IMPORT_DEFAULT_COLUMNS)
    mapped = {}
    for i, cell in enumerate(rows[0][1]):
        key = _IMPORT_HEADER_ALIASES.get(_norm_header(cell))
        if key and key not in mapped:
            mapped[key] = i
    if "username" in mapped or "password" in mapped:
        if "username" not in mapped or "password" not in mapped:
            raise ServiceError("CSV başlık satırında 'username' ve 'password' sütunları bulunmalıdır!")
        colmap = mapped
        rows = rows[1:]

    if len(rows) > USER_IMPORT_MAX_ROWS:
        raise ServiceError(f"CSV dosyası en fazla {USER_IMPORT_MAX_ROWS} satır içerebilir (dosyada {len(rows)} satır var).")
    return colmap, rows


def import_users(colmap, rows, account_type):
    """Inserts the valid, not yet existing accounts in one transaction.
    Returns dict(imported, skipped, invalid, errors). Raises ServiceError on database failure."""
    def cell(row, key):
        i = colmap.get(key)
        if i is None or i >= len(row):
            return ""
        return csv_uncell(row[i] or "").strip()

    imported = skipped = invalid = 0
    errors = []
    conn = get_db()
    try:
        with conn.cursor() as cur:
            group_names = get_radius_group_names(cur)
            valid = []
            seen = set()
            for line_no, row in rows:
                err, d = validate_radius_user_fields({
                    "username": cell(row, "username"),
                    "password": cell(row, "password"),
                    "vlan": cell(row, "vlan"),
                    "static_ip": cell(row, "static_ip"),
                    "rate": cell(row, "rate"),
                    "group": cell(row, "group"),
                    "desc": cell(row, "desc"),
                }, group_names=group_names)
                if err:
                    invalid += 1
                    if len(errors) < 5:
                        errors.append(f"Satır {line_no}: {err}")
                    continue
                key = d["username"].lower()
                if key in seen:  # duplicate inside the file
                    skipped += 1
                    continue
                seen.add(key)
                if not d["desc"]:
                    d["desc"] = "CSV İçe Aktarıldı"
                valid.append(d)

            # Existing accounts (any radcheck row) are skipped; MariaDB compares usernames case-insensitively
            existing = set()
            meta_existing = set()
            names = [d["username"] for d in valid]
            for i in range(0, len(names), 500):
                part = names[i:i + 500]
                ph = ",".join(["%s"] * len(part))
                cur.execute(f"SELECT DISTINCT username FROM radcheck WHERE username IN ({ph})", part)
                existing.update(str(r["username"]).lower() for r in cur.fetchall())
                cur.execute(f"SELECT DISTINCT username FROM radius_meta WHERE username IN ({ph})", part)
                meta_existing.update(str(r["username"]).lower() for r in cur.fetchall())
            to_add = [d for d in valid if d["username"].lower() not in existing]
            skipped += len(valid) - len(to_add)

            if to_add:
                check_rows, reply_rows, group_rows, meta_new, meta_upd = [], [], [], [], []
                for d in to_add:
                    u = d["username"]
                    check_rows.append((u, "Cleartext-Password", ":=", d["password"]))
                    if d["vlan"]:
                        reply_rows.append((u, "Tunnel-Type", ":=", "13"))
                        reply_rows.append((u, "Tunnel-Medium-Type", ":=", "6"))
                        reply_rows.append((u, "Tunnel-Private-Group-Id", ":=", d["vlan"]))
                    if d["static_ip"]:
                        reply_rows.append((u, "Framed-IP-Address", ":=", d["static_ip"]))
                    if d["rate"]:
                        reply_rows.append((u, "Mikrotik-Rate-Limit", ":=", d["rate"]))
                    if d["group"]:
                        group_rows.append((u, d["group"], 1))
                    if u.lower() in meta_existing:
                        meta_upd.append((account_type, d["desc"], d["static_ip"], u))
                    else:
                        meta_new.append((u, account_type, d["desc"], d["static_ip"]))

                use_source = _meta_source_supported(cur)
                add_names = [d["username"] for d in to_add]
                attr_ph = ",".join(["%s"] * len(USER_MANAGED_REPLY_ATTRS))

                conn.begin()
                # Orphan reply/group rows of previously removed accounts must not leak into the new users
                for i in range(0, len(add_names), 500):
                    part = add_names[i:i + 500]
                    ph = ",".join(["%s"] * len(part))
                    cur.execute(f"DELETE FROM radreply WHERE username IN ({ph}) AND attribute IN ({attr_ph})",
                                tuple(part) + USER_MANAGED_REPLY_ATTRS)
                    cur.execute(f"DELETE FROM radusergroup WHERE username IN ({ph})", part)
                cur.executemany("INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)", check_rows)
                if reply_rows:
                    cur.executemany("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, %s, %s, %s)", reply_rows)
                if group_rows:
                    cur.executemany("INSERT INTO radusergroup (username, groupname, priority) VALUES (%s, %s, %s)", group_rows)
                if meta_new:
                    if use_source:
                        cur.executemany("INSERT INTO radius_meta (username, account_type, description, static_ip, source) "
                                        "VALUES (%s, %s, %s, %s, 'csv')", meta_new)
                    else:
                        cur.executemany("INSERT INTO radius_meta (username, account_type, description, static_ip) "
                                        "VALUES (%s, %s, %s, %s)", meta_new)
                if meta_upd:
                    cur.executemany("UPDATE radius_meta SET account_type = %s, description = %s, static_ip = %s "
                                    "WHERE username = %s", meta_upd)
                conn.commit()
                tn.set_owners("radius_user", add_names)
                imported = len(to_add)
    except pymysql.MySQLError as e:
        _rollback(conn)
        log.error("import_users: %s", e)
        raise ServiceError("CSV içe aktarma başarısız oldu (veritabanı hatası); hiçbir kayıt eklenmedi.") from e
    finally:
        conn.close()
    return {"imported": imported, "skipped": skipped, "invalid": invalid, "errors": errors}
