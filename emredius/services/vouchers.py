# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Batch / guest accounts and Wi-Fi vouchers (GUEST- codes): listing, generation, deletion, purging, print data."""
import logging
import re
import secrets
import string
from datetime import datetime, timedelta

import pymysql

from ..core import RATE_LIMIT_RE, format_seconds, get_db, is_valid_vlan, safe_int
from .radius_users import ServiceError

log = logging.getLogger(__name__)

# FreeRADIUS 'Expiration' attribute format is '%d %b %Y %H:%M:%S' with ENGLISH month abbreviations.
# strftime/strptime('%b') depend on the process locale, so an explicit table is used in both directions.
_RADIUS_MONTHS_EN = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_RADIUS_MONTH_LOOKUP = {m.lower(): i + 1 for i, m in enumerate(_RADIUS_MONTHS_EN)}
# Legacy values written under a Turkish locale (parse only, never written)
_RADIUS_MONTH_LOOKUP.update({
    "oca": 1, "şub": 2, "sub": 2, "nis": 4, "haz": 6, "tem": 7,
    "ağu": 8, "agu": 8, "eyl": 9, "eki": 10, "kas": 11, "ara": 12,
})

# Voucher duration / timing whitelists (form values == backend values)
VOUCHER_DURATIONS = {"1h": 3600, "4h": 14400, "1d": 86400, "3d": 259200, "7d": 604800, "30d": 2592000}
VOUCHER_DURATION_LABELS = (
    ("1h", "1 Saat"), ("4h", "4 Saat"), ("1d", "1 Gün (24 Saat)"),
    ("3d", "3 Gün"), ("7d", "1 Hafta (7 Gün)"), ("30d", "1 Ay (30 Gün)"),
)
VOUCHER_TIMING_MODES = {"first_login", "fixed"}
VOUCHER_RATE_OPTIONS = (
    ("", "Limitsiz"), ("5M/2M", "5 Mbps / 2 Mbps"), ("10M/5M", "10 Mbps / 5 Mbps"),
    ("25M/10M", "25 Mbps / 10 Mbps"), ("50M/20M", "50 Mbps / 20 Mbps"),
)
# radius_meta.account_type values that belong to the "Toplu & Misafir Kullanıcılar" page
BATCH_ACCOUNT_TYPES = ("voucher", "batch", "wireless", "guest")
_VOUCHER_CODE_PREFIXES = ("GUEST-", "VOUCHER-")
_VOUCHER_CODE_ALPHABET = string.ascii_uppercase + string.digits


def radius_expiration_str(dt):
    """datetime -> FreeRADIUS Expiration value, e.g. '09 Oct 2026 15:30:00' (locale independent)."""
    return (f"{dt.day:02d} {_RADIUS_MONTHS_EN[dt.month - 1]} {dt.year:04d} "
            f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}")


def parse_radius_expiration(value):
    """Parses a FreeRADIUS Expiration value without using the locale ('09 Oct 2026 15:30:00',
    'Oct 9 2026 15:30:00', '9 Oct 2026', legacy Turkish month names, ISO 'YYYY-MM-DD HH:MM:SS').
    Returns a naive local datetime or None."""
    if not value:
        return None
    s = str(value).strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?", s):
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            return None
    day = month = year = None
    hh = mm = ss = 0
    for tok in s.replace(",", " ").split():
        if ":" in tok:
            parts = tok.split(":")
            if len(parts) > 3 or not all(p.isascii() and p.isdigit() for p in parts):
                return None
            hh = int(parts[0])
            mm = int(parts[1]) if len(parts) > 1 else 0
            ss = int(parts[2]) if len(parts) > 2 else 0
        elif tok.isascii() and tok.isdigit():
            if len(tok) == 4 and year is None:
                year = int(tok)
            elif len(tok) <= 2 and day is None:
                day = int(tok)
            else:
                return None
        else:
            mon = _RADIUS_MONTH_LOOKUP.get(tok.lower()[:3])
            if mon is None or month is not None:
                return None
            month = mon
    if day is None or month is None or year is None:
        return None
    try:
        return datetime(year, month, day, hh, mm, ss)
    except ValueError:
        return None


def quota_label(seconds):
    """86400 -> '1 Gün', 14400 -> '4 Saat', 1800 -> '30 Dk'."""
    sec = safe_int(seconds, 0, 0) or 0
    if sec <= 0:
        return "Sınırsız"
    if sec % 86400 == 0:
        return f"{sec // 86400} Gün"
    if sec >= 3600:
        h, rem = divmod(sec, 3600)
        return f"{h} Saat {rem // 60} Dk" if rem >= 60 else f"{h} Saat"
    return f"{max(1, sec // 60)} Dk"


def wifi_qr_escape(value):
    """Escapes a value for the 'WIFI:' QR payload (ZXing spec: \\ ; , : \" are backslash-escaped)."""
    out = []
    for ch in str(value if value is not None else ""):
        if ch in '\\;,:"':
            out.append("\\")
        out.append(ch)
    return "".join(out)


def is_voucher_code(username):
    return str(username or "").upper().startswith(_VOUCHER_CODE_PREFIXES)


def _is_batch_account(cur, username):
    """True if `username` is an account shown on the batch/guest page (and may be deleted from it)."""
    cur.execute("SELECT account_type FROM radius_meta WHERE username = %s", (username,))
    types = {(r.get("account_type") or "").lower() for r in cur.fetchall()}
    if types & set(BATCH_ACCOUNT_TYPES):
        return True
    if not is_voucher_code(username):
        return False
    if types:
        return True
    cur.execute("SELECT 1 AS x FROM radcheck WHERE username = %s LIMIT 1", (username,))
    return cur.fetchone() is not None


def delete_radius_account_rows(cur, username):
    """Removes every FreeRADIUS / panel row of one account (radacct is kept for 5651 records)."""
    cur.execute("DELETE FROM radcheck WHERE username = %s", (username,))
    cur.execute("DELETE FROM radreply WHERE username = %s", (username,))
    cur.execute("DELETE FROM radusergroup WHERE username = %s", (username,))
    cur.execute("DELETE FROM radius_meta WHERE username = %s", (username,))


def _rollback(conn):
    try:
        conn.rollback()
    except Exception:
        pass


# ---------- batch page ----------

_BATCH_LIST_SQL = """
    SELECT c.username AS code,
           MAX(c.value) AS password,
           MAX(e.value) AS expires_at,
           MAX(max_s.value) AS max_all_session,
           MAX(r.value) AS vlan_id,
           MAX(rate.value) AS rate_limit,
           MAX(m.description) AS description, MAX(m.created_at) AS created_at,
           {source_col} AS source, MAX(m.account_type) AS account_type,
           (SELECT COUNT(*) FROM radacct a WHERE a.username = c.username AND a.acctstoptime IS NULL) AS is_online,
           (SELECT COALESCE(SUM(a2.acctsessiontime), 0) FROM radacct a2 WHERE a2.username = c.username) AS used_time,
           MAX(c.id) AS sort_id
    FROM radcheck c
    LEFT JOIN radcheck e ON e.username = c.username AND e.attribute = 'Expiration'
    LEFT JOIN radcheck max_s ON max_s.username = c.username AND max_s.attribute = 'Max-All-Session'
    LEFT JOIN radreply r ON r.username = c.username AND r.attribute = 'Tunnel-Private-Group-Id'
    LEFT JOIN radreply rate ON rate.username = c.username AND rate.attribute = 'Mikrotik-Rate-Limit'
    LEFT JOIN radius_meta m ON m.username = c.username
    WHERE c.attribute = 'Cleartext-Password'
      AND ((m.account_type IN ('voucher', 'batch', 'wireless', 'guest'))
           OR (c.username LIKE 'GUEST-%' OR c.username LIKE 'VOUCHER-%'))
    GROUP BY c.username
    ORDER BY sort_id DESC
"""


def _batch_row(v, now):
    """Adds the computed display fields (quota text, status, source category) to one account row."""
    uname = v.get("code") or ""
    exp_raw = v.get("expires_at")
    exp_dt = parse_radius_expiration(exp_raw) if exp_raw else None
    max_sec = safe_int(v.get("max_all_session"), None, 0)
    used_sec = safe_int(v.get("used_time"), 0, 0) or 0
    expired = bool((exp_dt and exp_dt < now) or (max_sec and used_sec >= max_sec))
    if exp_raw:
        quota = "Bitiş: " + (exp_dt.strftime("%d.%m.%Y %H:%M") if exp_dt else str(exp_raw))
    elif max_sec:
        quota = f"{quota_label(max_sec)} (İlk Girişte)"
        if used_sec:
            quota += f" · Kullanılan: {format_seconds(used_sec)}"
    else:
        quota = "Sınırsız"

    if v.get("is_online"):
        status = "online"
    elif expired:
        status = "expired"
    else:
        status = "active"

    src = (v.get("source") or "").lower()
    acc_type = (v.get("account_type") or "").lower()
    if src == "wireless" or acc_type == "wireless":
        source = "wireless"
    elif src == "csv" or "csv" in acc_type:
        source = "csv"
    elif is_voucher_code(uname) or acc_type == "voucher":
        source = "voucher"
    else:
        source = "radius"
    return dict(v, code=uname, quota=quota, status=status, source_cat=source, printable=acc_type == "voucher")


def list_batch_accounts():
    """Returns dict(accounts, group_count, online_count, expired_count)."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            try:
                cur.execute(_BATCH_LIST_SQL.format(source_col="MAX(m.source)"))
            except pymysql.MySQLError as e:
                # older radius_meta schemas have no 'source' column (1054 = unknown column)
                if not e.args or e.args[0] != 1054:
                    raise
                cur.execute(_BATCH_LIST_SQL.format(source_col="NULL"))
            vouchers = cur.fetchall()
            cur.execute("SELECT groupname FROM radgroupreply GROUP BY groupname")
            groups = [r["groupname"] for r in cur.fetchall()]
    finally:
        conn.close()
    now = datetime.now()
    accounts = [_batch_row(v, now) for v in vouchers]
    return {
        "accounts": accounts,
        "group_count": len(groups),
        "online_count": sum(1 for a in accounts if a.get("is_online")),
        "expired_count": sum(1 for a in accounts if a["status"] == "expired"),
    }


# ---------- generate / delete / purge ----------

def validate_generate(count_raw, duration, timing_mode, vlan, rate, desc):
    """Returns the cleaned parameters dict. Raises ServiceError."""
    count = safe_int(count_raw, None, 1, 500)
    duration = (duration or "1d").strip()
    timing_mode = (timing_mode or "first_login").strip()
    vlan = (vlan or "").strip()
    rate = (rate or "").strip()
    desc = (desc or "").strip() or "Misafir"
    if count is None:
        raise ServiceError("Kupon sayısı 1 ile 500 arasında bir tam sayı olmalıdır.")
    if duration not in VOUCHER_DURATIONS:
        raise ServiceError("Geçersiz kullanım süresi seçildi.")
    if timing_mode not in VOUCHER_TIMING_MODES:
        raise ServiceError("Geçersiz süre başlangıç modu seçildi.")
    if vlan and not is_valid_vlan(vlan):
        raise ServiceError("VLAN ID 1 ile 4094 arasında bir sayı olmalıdır.")
    if rate and not RATE_LIMIT_RE.match(rate):
        raise ServiceError("Geçersiz hız limiti formatı (örn: 10M/5M).")
    if len(desc) > 255:
        raise ServiceError("Açıklama en fazla 255 karakter olabilir.")
    if vlan:
        vlan = str(int(vlan))
    return {"count": count, "duration": duration, "timing_mode": timing_mode, "vlan": vlan, "rate": rate, "desc": desc}


def generate_vouchers(p):
    """p = validate_generate(...). Inserts `count` GUEST- vouchers in one transaction.
    Returns dict(codes, total_seconds, exp_str)."""
    total_seconds = VOUCHER_DURATIONS[p["duration"]]
    exp_str = radius_expiration_str(datetime.now() + timedelta(seconds=total_seconds))
    codes = []
    conn = get_db()
    try:
        with conn.cursor() as cur:
            # Every GUEST- name already in use (radcheck / radreply / radius_meta), compared case-insensitively
            cur.execute("""
                SELECT username FROM radcheck WHERE username LIKE 'GUEST-%'
                UNION SELECT username FROM radreply WHERE username LIKE 'GUEST-%'
                UNION SELECT username FROM radius_meta WHERE username LIKE 'GUEST-%'
            """)
            taken = {str(r["username"]).upper() for r in cur.fetchall()}

            check_rows, reply_rows, meta_rows = [], [], []
            for _ in range(p["count"]):
                for _attempt in range(50):
                    code = "GUEST-" + "".join(secrets.choice(_VOUCHER_CODE_ALPHABET) for _ in range(5))
                    if code not in taken:
                        break
                else:
                    raise RuntimeError("benzersiz kupon kodu üretilemedi")
                taken.add(code)
                codes.append(code)
                pin = "".join(secrets.choice(string.digits) for _ in range(6))

                check_rows.append((code, "Cleartext-Password", ":=", pin))
                if p["timing_mode"] == "first_login":
                    # total usage time counted from the first login (sqlcounter) + per-session upper limit
                    check_rows.append((code, "Max-All-Session", ":=", str(total_seconds)))
                    reply_rows.append((code, "Session-Timeout", ":=", str(total_seconds)))
                else:
                    check_rows.append((code, "Expiration", ":=", exp_str))
                if p["vlan"]:
                    reply_rows.append((code, "Tunnel-Type", ":=", "13"))
                    reply_rows.append((code, "Tunnel-Medium-Type", ":=", "6"))
                    reply_rows.append((code, "Tunnel-Private-Group-Id", ":=", p["vlan"]))
                if p["rate"]:
                    reply_rows.append((code, "Mikrotik-Rate-Limit", ":=", p["rate"]))
                meta_rows.append((code, "voucher", p["desc"]))

            conn.begin()
            cur.executemany("INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)", check_rows)
            if reply_rows:
                cur.executemany("INSERT INTO radreply (username, attribute, op, value) VALUES (%s, %s, %s, %s)", reply_rows)
            cur.executemany(
                "INSERT INTO radius_meta (username, account_type, description) VALUES (%s, %s, %s) "
                "ON DUPLICATE KEY UPDATE account_type = VALUES(account_type), description = VALUES(description)",
                meta_rows)
        conn.commit()
    except Exception as e:
        _rollback(conn)
        log.error("generate_vouchers: %s", e)
        raise ServiceError("Kuponlar üretilirken bir veritabanı hatası oluştu; hiçbir kupon kaydedilmedi.") from e
    finally:
        conn.close()
    return {"codes": codes, "total_seconds": total_seconds, "exp_str": exp_str}


def delete_voucher(code):
    code = (code or "").strip()
    if not code or len(code) > 64:
        raise ServiceError("Geçersiz kupon / kullanıcı kodu.")
    conn = get_db()
    try:
        with conn.cursor() as cur:
            if not _is_batch_account(cur, code):
                raise ServiceError(f"'{code}' bulunamadı veya bir kupon / toplu hesap değil.")
            conn.begin()
            delete_radius_account_rows(cur, code)
        conn.commit()
    except ServiceError:
        raise
    except Exception as e:
        _rollback(conn)
        log.error("delete_voucher: %s", e)
        raise ServiceError("Kupon silinirken bir veritabanı hatası oluştu.") from e
    finally:
        conn.close()
    return code


# Voucher accounts eligible for automatic purging (explicit 'voucher' type, or GUEST-/VOUCHER- codes
# that are not registered as regular users / MAC devices)
_VOUCHER_PURGE_SCOPE_SQL = """
    (m.account_type = 'voucher'
     OR ((x.username LIKE 'GUEST-%' OR x.username LIKE 'VOUCHER-%')
         AND (m.account_type IS NULL OR m.account_type NOT IN ('user', 'mac'))))
"""


def purge_expired_vouchers():
    """Deletes fixed-expiry vouchers past their date and first-login vouchers whose quota is used up.
    Returns (expired_fixed, expired_quota) username lists."""
    now = datetime.now()
    expired_fixed = []
    expired_quota = []
    conn = get_db()
    try:
        with conn.cursor() as cur:
            # (a) fixed expiry: Expiration in the past
            cur.execute(f"""
                SELECT DISTINCT x.username, x.value
                FROM radcheck x
                LEFT JOIN radius_meta m ON m.username = x.username
                WHERE x.attribute = 'Expiration' AND {_VOUCHER_PURGE_SCOPE_SQL}
            """)
            seen = set()
            for r in cur.fetchall():
                u = r["username"]
                exp_dt = parse_radius_expiration(r.get("value"))
                if exp_dt is not None and exp_dt < now and u not in seen:
                    seen.add(u)
                    expired_fixed.append(u)

            # (b) first-login vouchers: total usage (radacct) >= Max-All-Session
            cur.execute(f"""
                SELECT DISTINCT x.username, x.value
                FROM radcheck x
                LEFT JOIN radius_meta m ON m.username = x.username
                WHERE x.attribute = 'Max-All-Session' AND {_VOUCHER_PURGE_SCOPE_SQL}
            """)
            quotas = {}
            for r in cur.fetchall():
                q = safe_int(r.get("value"), None, 1)
                if q and r["username"] not in seen:
                    quotas[r["username"]] = q
            names = list(quotas.keys())
            for i in range(0, len(names), 500):
                part = names[i:i + 500]
                placeholders = ",".join(["%s"] * len(part))
                cur.execute(
                    f"SELECT username, COALESCE(SUM(acctsessiontime), 0) AS used FROM radacct "
                    f"WHERE username IN ({placeholders}) GROUP BY username", part)
                for r in cur.fetchall():
                    u = r["username"]
                    used = safe_int(r.get("used"), 0, 0) or 0
                    # radacct usernames compare case-insensitively in MariaDB; map back to the radcheck key
                    key = u if u in quotas else next((n for n in part if n.lower() == str(u).lower()), None)
                    if key and key not in seen and used >= quotas[key]:
                        seen.add(key)
                        expired_quota.append(key)

            if expired_fixed or expired_quota:
                conn.begin()
                for u in expired_fixed + expired_quota:
                    delete_radius_account_rows(cur, u)
        conn.commit()
    except Exception as e:
        _rollback(conn)
        log.error("purge_expired_vouchers: %s", e)
        raise ServiceError("Süresi dolmuş kuponlar temizlenirken bir veritabanı hatası oluştu.") from e
    finally:
        conn.close()
    return expired_fixed, expired_quota


# ---------- print ----------

def printable_vouchers(only_code, limit, ssid):
    """Voucher cards for the print page: list of dicts (code, password, timing, qr_id, qr_payload)."""
    sql = """
        SELECT c.username AS code, MAX(c.value) AS password,
               MAX(e.value) AS expires_at, MAX(max_s.value) AS max_all_session,
               MAX(m.description) AS description, MAX(c.id) AS sort_id
        FROM radcheck c
        JOIN radius_meta m ON m.username = c.username AND m.account_type = 'voucher'
        LEFT JOIN radcheck e ON e.username = c.username AND e.attribute = 'Expiration'
        LEFT JOIN radcheck max_s ON max_s.username = c.username AND max_s.attribute = 'Max-All-Session'
        WHERE c.attribute = 'Cleartext-Password'
    """
    params = []
    if only_code:
        sql += " AND c.username = %s"
        params.append(only_code)
    sql += " GROUP BY c.username ORDER BY sort_id DESC LIMIT %s"
    params.append(limit)

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            vouchers = cur.fetchall()
    finally:
        conn.close()

    cards = []
    for idx, v in enumerate(vouchers, 1):
        if v.get("expires_at"):
            exp_dt = parse_radius_expiration(v["expires_at"])
            timing = "Bitiş: " + (exp_dt.strftime("%d.%m.%Y %H:%M") if exp_dt else str(v["expires_at"]))
        elif safe_int(v.get("max_all_session"), 0, 0):
            timing = f"{quota_label(v['max_all_session'])} (İlk Girişte)"
        else:
            timing = "Süresiz"
        cards.append({
            "code": v.get("code"),
            "password": v.get("password"),
            "timing": timing,
            "qr_id": f"qrcode-{idx}",
            "qr_payload": f"WIFI:S:{wifi_qr_escape(ssid)};T:WPA;P:{wifi_qr_escape(v.get('password'))};;",
        })
    return cards
