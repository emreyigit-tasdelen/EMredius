# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Law 5651 accounting search (radacct), CSV export and verification of the signed daily archive.

Archive layout (written daily by scripts/maintenance.py):
  5651_YYYY-MM-DD.csv, 5651_YYYY-MM-DD.csv.sha256 (hex only), optional 5651_YYYY-MM-DD.csv.tsr (RFC 3161),
  chain.log: lines `YYYY-MM-DD <file_sha256> <chain_sha256>`, chain = sha256(prev_chain_hex + file_sha_hex).
  5651_YYYY-MM-DD.clock.json: clock trust record taken at archive time (chrony sync, offset, source, stratum,
  measurement time UTC) holding the day's csv_sha256 + chain_sha256; clock_chain.log chains the records the same way
  (`YYYY-MM-DD <clock_json_sha256> <link_sha256>`). Days archived before clock records existed have none (YOK)."""
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import re
import urllib.parse
from datetime import datetime, timedelta, timezone

import pymysql

from ..core import get_db, is_valid_ip

log = logging.getLogger(__name__)

PAGE_SIZE = 100
EXPORT_MAX_ROWS = 1000000
FILE_RE = re.compile(r"^5651_\d{4}-\d{2}-\d{2}\.(csv(\.sha256|\.tsr)?|clock\.json)$")
CLOCK_CHAIN = "clock_chain.log"
CHAIN_FILES = ("chain.log", CLOCK_CHAIN)
_CSV_RE = re.compile(r"^5651_(\d{4}-\d{2}-\d{2})\.csv$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
# Same column order as the daily signed archive written by maintenance.py
COLUMNS = ["username", "framedipaddress", "callingstationid", "nasipaddress", "acctstarttime",
           "acctstoptime", "acctsessiontime", "acctinputoctets", "acctoutputoctets", "acctsessionid"]
_FILTER_KEYS = ("ip", "mac", "username", "start", "end")


# ---------- search filters ----------

def parse_date(raw, label, errors):
    v = (raw or "").strip()
    if not v:
        return None
    try:
        d = datetime.strptime(v, "%Y-%m-%d")
    except ValueError:
        errors.append(f"{label} geçersiz (YYYY-AA-GG biçiminde olmalı).")
        return None
    if not (1970 <= d.year <= 2100):
        errors.append(f"{label} 1970-2100 aralığında olmalı.")
        return None
    return d


def parse_filters(args):
    """Reads and validates the search filters from a mapping (request.args). Returns (filters, errors)."""
    f = {
        "ip": (args.get("ip") or "").strip()[:64],
        "mac": (args.get("mac") or "").strip()[:64],
        "username": (args.get("username") or "").strip()[:128],
        "start": (args.get("start") or "").strip()[:32],
        "end": (args.get("end") or "").strip()[:32],
    }
    errors = []
    f["start_dt"] = parse_date(f["start"], "Başlangıç tarihi", errors)
    f["end_dt"] = parse_date(f["end"], "Bitiş tarihi", errors)
    if f["start_dt"]:
        f["start"] = f["start_dt"].strftime("%Y-%m-%d")
    if f["end_dt"]:
        f["end"] = f["end_dt"].strftime("%Y-%m-%d")
    if f["start_dt"] and f["end_dt"] and f["start_dt"] > f["end_dt"]:
        errors.append("Başlangıç tarihi bitiş tarihinden sonra olamaz.")
    f["active"] = any(f[k] for k in _FILTER_KEYS)
    return f, errors


def _like(value):
    """%value% LIKE pattern with the LIKE wildcards in the user input escaped."""
    v = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{v}%"


def build_where(f):
    """Parameterized WHERE clause for radacct. The date range selects every session that was active
    at some point inside [start 00:00, end 23:59:59] (what a 5651 'who had this IP then' lookup needs)."""
    sql = " WHERE 1=1"
    params = []
    if f["ip"]:
        if is_valid_ip(f["ip"]):
            sql += " AND framedipaddress = %s"
            params.append(str(ipaddress.ip_address(f["ip"])))
        else:
            sql += " AND framedipaddress LIKE %s"
            params.append(_like(f["ip"]))
    if f["mac"]:
        hex_only = re.sub(r"[^0-9a-fA-F]", "", f["mac"]).lower()
        if hex_only and re.fullmatch(r"[0-9A-Fa-f:.\- ]+", f["mac"]):
            # separator-insensitive: aa:bb.., AA-BB-.., aabb.cc.. all match
            sql += " AND REPLACE(REPLACE(REPLACE(LOWER(callingstationid), ':', ''), '-', ''), '.', '') LIKE %s"
            params.append(f"%{hex_only}%")
        else:
            sql += " AND callingstationid LIKE %s"
            params.append(_like(f["mac"]))
    if f["username"]:
        sql += " AND username LIKE %s"
        params.append(_like(f["username"]))
    if f["start_dt"]:
        sql += " AND (acctstoptime IS NULL OR acctstoptime >= %s)"
        params.append(f["start_dt"])
    if f["end_dt"]:
        sql += " AND acctstarttime < %s"
        params.append(f["end_dt"] + timedelta(days=1))
    return sql, params


def query_string(f, **extra):
    items = [(k, f[k]) for k in _FILTER_KEYS if f.get(k)]
    items += [(k, v) for k, v in extra.items() if v not in (None, "")]
    return urllib.parse.urlencode(items)


def filter_summary(f):
    return ", ".join(f"{k}={f[k]}" for k in _FILTER_KEYS if f.get(k))[:500]


def csv_cell(value):
    """CSV cell value that cannot be interpreted as a spreadsheet formula."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    s = str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r", "\n"):
        s = "'" + s
    return s


def search(f, page):
    """Returns (rows, total, pages, page). Raises pymysql errors to the caller."""
    where, params = build_where(f)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM radacct" + where, tuple(params))
            total = int((cur.fetchone() or {}).get("c") or 0)
            pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
            page = min(page, pages)
            cur.execute(
                "SELECT radacctid, username, framedipaddress, callingstationid, nasipaddress, acctstarttime,"
                " acctstoptime, acctsessiontime, acctinputoctets, acctoutputoctets, acctterminatecause"
                " FROM radacct" + where + " ORDER BY radacctid DESC LIMIT %s OFFSET %s",
                tuple(params) + (PAGE_SIZE, (page - 1) * PAGE_SIZE),
            )
            rows = cur.fetchall()
    finally:
        conn.close()
    return rows, total, pages, page


def export_csv_stream(f):
    """Generator of CSV chunks for the filter set (unbuffered cursor: the result is never held in memory)."""
    where, params = build_where(f)
    sql = "SELECT " + ", ".join(COLUMNS) + " FROM radacct" + where + " ORDER BY radacctid LIMIT %s"
    params = tuple(params) + (EXPORT_MAX_ROWS,)
    conn = get_db()

    def _generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        try:
            writer.writerow(COLUMNS)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)
            cur = conn.cursor(pymysql.cursors.SSDictCursor)
            cur.execute(sql, params)
            while True:
                batch = cur.fetchmany(1000)
                if not batch:
                    break
                for r in batch:
                    writer.writerow([csv_cell(r.get(c)) for c in COLUMNS])
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)
        except Exception as ex:
            log.error("5651 CSV export: %s", ex)
        finally:
            try:
                conn.close()
            except Exception:
                pass
    return _generate()


# ---------- signed daily archive ----------

def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_sha_file(path):
    """Hex digest stored in a .sha256 file ('' when malformed, None when unreadable)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            tokens = fh.read(512).strip().split()
    except OSError:
        return None
    tok = (tokens[0] if tokens else "").lower()
    return tok if _HEX64_RE.fullmatch(tok) else ""


def list_archive(archive_dir):
    """Returns {"days": [...], "has_chain": bool} or {"error": msg} / None when the directory does not exist."""
    if not os.path.isdir(archive_dir):
        return None
    try:
        names = set(os.listdir(archive_dir))
    except OSError as e:
        return {"error": f"Arşiv dizini okunamadı: {e}"}
    days = []
    for n in names:
        m = _CSV_RE.fullmatch(n)
        if not m:
            continue
        try:
            st = os.stat(os.path.join(archive_dir, n))
        except OSError:
            continue
        days.append({
            "date": m.group(1), "name": n, "size": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
            "has_sha": (n + ".sha256") in names, "has_tsr": (n + ".tsr") in names,
            "has_clock": f"5651_{m.group(1)}.clock.json" in names,
        })
    days.sort(key=lambda x: x["date"], reverse=True)
    return {"days": days, "has_chain": "chain.log" in names}


def parse_chain(path):
    """Recomputes the hash chain. Returns (entries, error); entries is None when chain.log is missing/unreadable.
    chain_sha = sha256(prev_chain_hex + file_sha_hex), prev of the first line = 64 zeros. Every link is checked
    against the previous RECORDED value so a single tampered line is pinpointed."""
    label = os.path.basename(path)
    if not os.path.isfile(path):
        return None, f"{label} bulunamadı."
    entries = []
    prev = "0" * 64
    last_date = ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line:
                    continue
                parts = line.split()
                e = {"lineno": lineno, "date": "", "file_sha": "", "chain_sha": "", "expected": "",
                     "link_ok": False, "order_ok": True, "malformed": False, "raw": line[:200]}
                if (len(parts) != 3 or not _DATE_RE.fullmatch(parts[0])
                        or not _HEX64_RE.fullmatch(parts[1]) or not _HEX64_RE.fullmatch(parts[2])):
                    e["malformed"] = True
                    entries.append(e)
                    continue
                file_sha, chain_sha = parts[1].lower(), parts[2].lower()
                expected = hashlib.sha256((prev + file_sha).encode()).hexdigest()
                e.update(date=parts[0], file_sha=file_sha, chain_sha=chain_sha, expected=expected,
                         link_ok=hmac.compare_digest(expected, chain_sha), order_ok=parts[0] > last_date)
                entries.append(e)
                prev = chain_sha
                last_date = parts[0]
    except OSError as ex:
        return None, f"{label} okunamadı: {ex}"
    return entries, None


def verify_archive(archive_dir, date_from=None, date_to=None):
    names = set(os.listdir(archive_dir))
    csv_by_date = {}
    for n in names:
        m = _CSV_RE.fullmatch(n)
        if m:
            csv_by_date[m.group(1)] = n

    chain_entries, chain_err = parse_chain(os.path.join(archive_dir, "chain.log"))
    chain_by_date = {}
    for e in chain_entries or []:
        if not e["malformed"]:
            chain_by_date.setdefault(e["date"], []).append(e)

    clock_path = os.path.join(archive_dir, CLOCK_CHAIN)
    clock_present = os.path.isfile(clock_path)
    clock_entries, clock_err = parse_chain(clock_path) if clock_present else ([], None)
    clock_by_date = {}
    for e in clock_entries or []:
        if not e["malformed"]:
            clock_by_date.setdefault(e["date"], []).append(e)
    clock_files = {n[5:15] for n in names if n.endswith(".clock.json") and FILE_RE.fullmatch(n)}

    rows = []
    for day in sorted(set(csv_by_date) | set(chain_by_date) | set(clock_by_date) | clock_files, reverse=True):
        if (date_from and day < date_from) or (date_to and day > date_to):
            continue
        problems = []
        csv_name = csv_by_date.get(day)
        size = None
        actual = None
        if csv_name:
            try:
                p = os.path.join(archive_dir, csv_name)
                size = os.path.getsize(p)
                actual = _sha256_file(p)
            except OSError:
                problems.append("CSV dosyası okunamadı")
        else:
            problems.append("CSV dosyası yok (silinmiş olabilir)")

        sha_name = f"5651_{day}.csv.sha256"
        if sha_name in names:
            stored = _read_sha_file(os.path.join(archive_dir, sha_name))
            if not stored:
                sha_status = "FAIL"
                problems.append(".sha256 dosyası okunamadı / bozuk")
            elif actual and hmac.compare_digest(stored, actual):
                sha_status = "OK"
            else:
                sha_status = "FAIL"
                if actual:
                    problems.append("SHA-256 özeti .sha256 dosyası ile eşleşmiyor")
        else:
            sha_status = "YOK"
            problems.append(".sha256 dosyası yok")

        ce = chain_by_date.get(day) or []
        if chain_entries is None:
            chain_status = "YOK"
            problems.append("chain.log yok")
        elif not ce:
            chain_status = "YOK"
            problems.append("Hash zincirinde bu güne ait kayıt yok")
        else:
            ok = True
            e = ce[-1]
            if len(ce) > 1:
                ok = False
                problems.append(f"Zincirde bu gün için {len(ce)} kayıt var")
            for x in ce:
                if not x["link_ok"]:
                    ok = False
                    problems.append(f"Zincir halkası bozuk (chain.log satır {x['lineno']})")
                if not x["order_ok"]:
                    ok = False
                    problems.append(f"Zincir tarih sırası bozuk (chain.log satır {x['lineno']})")
            if actual and not hmac.compare_digest(e["file_sha"], actual):
                ok = False
                problems.append("Zincirdeki dosya özeti CSV ile eşleşmiyor")
            chain_status = "OK" if ok else "FAIL"

        clock_status, clock, clock_problems = _verify_clock(archive_dir, day, names, clock_by_date.get(day) or [],
                                                            clock_entries is None, actual, ce[-1] if ce else None)
        problems += clock_problems

        rows.append({
            "date": day, "csv": csv_name, "size": size, "actual": actual,
            "sha_status": sha_status, "chain_status": chain_status, "clock_status": clock_status, "clock": clock,
            "tsr": f"5651_{day}.csv.tsr" in names, "problems": problems, "ok": not problems,
        })

    valid_entries = [e for e in (chain_entries or []) if not e["malformed"]]
    clock_valid = [e for e in (clock_entries or []) if not e["malformed"]]
    return {
        "rows": rows,
        "chain_err": chain_err,
        "chain_total": len(chain_entries or []),
        "chain_broken": [e for e in valid_entries if not e["link_ok"] or not e["order_ok"]],
        "chain_malformed": [e for e in (chain_entries or []) if e["malformed"]],
        "chain_head": valid_entries[-1]["chain_sha"] if valid_entries else "",
        "clock_present": clock_present,
        "clock_err": clock_err,
        "clock_total": len(clock_entries or []),
        "clock_broken": [e for e in clock_valid if not e["link_ok"] or not e["order_ok"]],
        "clock_malformed": [e for e in (clock_entries or []) if e["malformed"]],
        "clock_head": clock_valid[-1]["chain_sha"] if clock_valid else "",
    }


def _verify_clock(archive_dir, day, names, entries, chain_unreadable, actual, data_entry):
    """(status, record, problems) of the day's clock record. status: OK, WARN (intact, but the clock was not
    NTP-synced when archiving), FAIL, or YOK when the day has none (archived before clock records: not an error)."""
    name = f"5651_{day}.clock.json"
    if name not in names and not entries:
        return "YOK", None, []
    problems = []
    rec = None
    if name not in names:
        problems.append("Saat kaydı (.clock.json) yok ama clock_chain.log içinde var")
    else:
        sha = None
        try:
            with open(os.path.join(archive_dir, name), "rb") as fh:
                data = fh.read(65536)
            sha = hashlib.sha256(data).hexdigest()
            rec = json.loads(data.decode("utf-8"))
            if not isinstance(rec, dict):
                raise ValueError("not an object")
        except (OSError, ValueError) as ex:
            problems.append(f"Saat kaydı okunamadı / bozuk ({type(ex).__name__})")
            rec = None
        if chain_unreadable:
            problems.append("clock_chain.log okunamadı")
        elif not entries:
            problems.append("Saat kaydı clock_chain.log içinde yok")
        else:
            if len(entries) > 1:
                problems.append(f"Saat zincirinde bu gün için {len(entries)} kayıt var")
            for x in entries:
                if not x["link_ok"]:
                    problems.append(f"Saat zinciri halkası bozuk (clock_chain.log satır {x['lineno']})")
                if not x["order_ok"]:
                    problems.append(f"Saat zinciri tarih sırası bozuk (clock_chain.log satır {x['lineno']})")
            if sha and not hmac.compare_digest(entries[-1]["file_sha"], sha):
                problems.append("Saat kaydı özeti clock_chain.log ile eşleşmiyor")
        if rec is not None:
            if rec.get("day") != day:
                problems.append("Saat kaydındaki gün farklı")
            if actual and not hmac.compare_digest(str(rec.get("csv_sha256", "")), actual):
                problems.append("Saat kaydındaki CSV özeti dosya ile eşleşmiyor")
            if data_entry and not hmac.compare_digest(str(rec.get("chain_sha256", "")), data_entry["chain_sha"]):
                problems.append("Saat kaydındaki zincir özeti chain.log ile eşleşmiyor")
    if problems:
        return "FAIL", rec, problems
    return ("OK" if rec.get("synced") is True else "WARN"), rec, []


def clock_record(tracking, evaluated, ignore_clock=False, now=None):
    """Clock trust snapshot for the archive: chrony.tracking_info() + timesync.evaluate() at archive time."""
    synced = bool(tracking.get("is_synced"))
    now = now or datetime.now(timezone.utc)
    return {
        "version": 1,
        "measured_at_utc": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "synced": synced, "level": evaluated.get("level"), "message": evaluated.get("message"),
        "offset_s": evaluated.get("offset_s"), "ref_id": tracking.get("ref_id", "-"),
        "source": tracking.get("source", "-"), "stratum": tracking.get("stratum", "-"),
        "leap_status": tracking.get("leap_status", "-"), "last_offset": tracking.get("last_offset", "-"),
        "rms_offset": tracking.get("rms_offset", "-"), "forced": bool(ignore_clock and not synced),
    }


def archive_file_path(archive_dir, filename):
    """Absolute path of a downloadable archive file, or None for an invalid / missing name."""
    name = os.path.basename(filename or "")
    if name != filename or not (name in CHAIN_FILES or FILE_RE.fullmatch(name)):
        return None
    base = os.path.realpath(archive_dir)
    path = os.path.realpath(os.path.join(base, name))
    if os.path.dirname(path) != base or not os.path.isfile(path):
        return None
    return path


def _last_chain(path):
    """(last_date, last_chain_sha) of chain.log; ('', 64 zeros) when the file is missing or empty."""
    last = ("", "0" * 64)
    if not os.path.isfile(path):
        return last
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            parts = raw.split()
            if len(parts) == 3 and _DATE_RE.fullmatch(parts[0]) and _HEX64_RE.fullmatch(parts[2]):
                last = (parts[0], parts[2].lower())
    return last


def pending_days(archive_dir, until, max_days=62):
    """Days to archive, oldest first: every day after the last archived one up to `until` (YYYY-MM-DD), so a day
    skipped while the host slept or the clock jumped is caught up. Only `until` when nothing is archived yet."""
    last_date, _ = _last_chain(os.path.join(archive_dir, "chain.log"))
    end = datetime.strptime(until, "%Y-%m-%d")
    if not last_date:
        return [until]
    day = datetime.strptime(last_date, "%Y-%m-%d") + timedelta(days=1)
    days = []
    while day <= end and len(days) < max_days:
        days.append(day.strftime("%Y-%m-%d"))
        day += timedelta(days=1)
    return days


def write_daily_archive(archive_dir, day, rows, clock=None):
    """Writes 5651_<day>.csv (+ .sha256) from `rows` (dicts with COLUMNS) and appends the day to chain.log.
    `clock` (clock_record()) adds 5651_<day>.clock.json bound to the day's hashes and chained in clock_chain.log.
    Returns the CSV path, or None when the day is already archived. Days must be archived in date order."""
    if not _DATE_RE.fullmatch(day):
        raise ValueError("day must be YYYY-MM-DD")
    os.makedirs(archive_dir, mode=0o700, exist_ok=True)
    csv_path = os.path.join(archive_dir, f"5651_{day}.csv")
    chain_path = os.path.join(archive_dir, "chain.log")
    last_date, prev = _last_chain(chain_path)
    if os.path.exists(csv_path) or last_date == day:
        return None
    if last_date and day < last_date:
        raise ValueError(f"{day} is older than the last archived day {last_date}")
    tmp = csv_path + ".part"
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(COLUMNS)
        for r in rows:
            writer.writerow([csv_cell(r.get(c)) for c in COLUMNS])
    os.replace(tmp, csv_path)
    file_sha = _sha256_file(csv_path)
    with open(csv_path + ".sha256", "w", encoding="utf-8") as fh:
        fh.write(file_sha + "\n")
    chain_sha = hashlib.sha256((prev + file_sha).encode()).hexdigest()
    clock_sha = None
    if clock is not None:
        data = (json.dumps(dict(clock, day=day, csv_sha256=file_sha, chain_sha256=chain_sha), sort_keys=True,
                           ensure_ascii=False, indent=1) + "\n").encode("utf-8")
        clock_path = os.path.join(archive_dir, f"5651_{day}.clock.json")
        with open(clock_path + ".part", "wb") as fh:
            fh.write(data)
        os.replace(clock_path + ".part", clock_path)
        clock_sha = hashlib.sha256(data).hexdigest()
    with open(chain_path, "a", encoding="utf-8") as fh:
        fh.write(f"{day} {file_sha} {chain_sha}\n")
    if clock_sha:
        clock_chain = os.path.join(archive_dir, CLOCK_CHAIN)
        _, cprev = _last_chain(clock_chain)
        with open(clock_chain, "a", encoding="utf-8") as fh:
            fh.write(f"{day} {clock_sha} {hashlib.sha256((cprev + clock_sha).encode()).hexdigest()}\n")
    return csv_path


def day_rows(day):
    """Unbuffered iterator over radacct sessions that started on `day` (YYYY-MM-DD)."""
    start = datetime.strptime(day, "%Y-%m-%d")
    conn = get_db()
    try:
        cur = conn.cursor(pymysql.cursors.SSDictCursor)
        cur.execute("SELECT " + ", ".join(COLUMNS) + " FROM radacct WHERE acctstarttime >= %s AND acctstarttime < %s"
                    " ORDER BY radacctid", (start, start + timedelta(days=1)))
        while True:
            batch = cur.fetchmany(1000)
            if not batch:
                break
            yield from batch
    finally:
        conn.close()
