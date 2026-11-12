# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Syslog page data: reads syslog_msgs written by the collector (nms/syslogd). Search, filters, paging, CSV, settings."""
import csv
import io
import time
from datetime import datetime

from nms.syslogd import acl as allow, store
from nms.syslogd.parser import FACILITIES, SEVERITIES

from ..core import get_nms_db

PAGE_SIZE = 50
CSV_LIMIT = 50000


def _conn():
    conn = get_nms_db()
    conn.executescript(store.SCHEMA)
    return conn


def _ts(value):
    """'2026-10-21T14:30' (datetime-local) -> epoch seconds; empty/invalid -> None."""
    try:
        return int(datetime.strptime(value.strip()[:16], "%Y-%m-%dT%H:%M").timestamp()) if value else None
    except (ValueError, AttributeError):
        return None


def parse_filters(args):
    """Whitelisted filter dict from request args (everything bounded / validated)."""
    def _int(key, lo, hi):
        try:
            v = int(args.get(key, ""))
        except (TypeError, ValueError):
            return None
        return v if lo <= v <= hi else None
    return {"src_ip": (args.get("src_ip") or "").strip()[:45], "severity": _int("severity", 0, 7),
            "facility": _int("facility", 0, 23), "since": _ts(args.get("since", "")),
            "until": _ts(args.get("until", "")), "q": (args.get("q") or "").strip()[:200],
            "page": _int("page", 1, 10 ** 6) or 1}


def _where(f):
    where, a = ["1=1"], []
    if f["src_ip"]:
        where.append("src_ip = ?")
        a.append(f["src_ip"])
    if f["severity"] is not None:  # "this severity or worse"
        where.append("severity <= ?")
        a.append(f["severity"])
    if f["facility"] is not None:
        where.append("facility = ?")
        a.append(f["facility"])
    if f["since"]:
        where.append("ts >= ?")
        a.append(f["since"])
    if f["until"]:
        where.append("ts <= ?")
        a.append(f["until"])
    if f["q"]:
        esc = f["q"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        where.append("(msg LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' OR app LIKE ? ESCAPE '\\')")
        a += ["%" + esc + "%"] * 3
    return " AND ".join(where), a


def _row(r):
    d = dict(r)
    d["facility_name"] = FACILITIES[d["facility"]] if 0 <= d["facility"] < len(FACILITIES) else str(d["facility"])
    d["severity_name"] = SEVERITIES[d["severity"]] if 0 <= d["severity"] < 8 else str(d["severity"])
    d["time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d["ts"]))
    return d


def search(f):
    """Returns (data, error). Never raises: the page must open even if the collector never ran."""
    try:
        conn = _conn()
    except Exception as e:  # noqa: BLE001
        return None, str(e)
    try:
        where, a = _where(f)
        total = conn.execute(f"SELECT COUNT(*) FROM syslog_msgs WHERE {where}", a).fetchone()[0]
        pages = max(1, -(-total // PAGE_SIZE))
        page = min(f["page"], pages)
        rows = conn.execute(f"SELECT id, ts, src_ip, facility, severity, host, app, msg FROM syslog_msgs WHERE {where} "
                            f"ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?", a + [PAGE_SIZE, (page - 1) * PAGE_SIZE]).fetchall()
        sources = [r[0] for r in conn.execute("SELECT DISTINCT src_ip FROM syslog_msgs ORDER BY src_ip LIMIT 500")]
        count_all = conn.execute("SELECT COUNT(*) FROM syslog_msgs").fetchone()[0]
        last = conn.execute("SELECT MAX(ts) FROM syslog_msgs").fetchone()[0]
    except Exception as e:  # noqa: BLE001
        return None, "Syslog verisi okunamadı: " + str(e)
    finally:
        conn.close()
    return {"rows": [_row(r) for r in rows], "total": total, "page": page, "pages": pages, "page_size": PAGE_SIZE,
            "sources": sources, "count_all": count_all, "last_ts": last}, None


def _safe(v):
    """Neutralises spreadsheet formula injection in CSV cells."""
    v = str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def export_csv(f):
    conn = _conn()
    try:
        where, a = _where(f)
        rows = conn.execute(f"SELECT id, ts, src_ip, facility, severity, host, app, msg FROM syslog_msgs WHERE {where} "
                            f"ORDER BY ts DESC, id DESC LIMIT ?", a + [CSV_LIMIT]).fetchall()
    finally:
        conn.close()
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["time", "source_ip", "facility", "severity", "host", "app", "message"])
    for r in rows:
        d = _row(r)
        w.writerow([d["time"], d["src_ip"], d["facility_name"], d["severity_name"], _safe(d["host"]), _safe(d["app"]),
                    _safe(d["msg"])])
    return out.getvalue()


def get_settings():
    try:
        conn = _conn()
    except Exception:  # noqa: BLE001
        return {"retention_days": store.DEFAULT_RETENTION_DAYS, "allowed_sources": ""}
    try:
        return {"retention_days": store.retention_days(conn), "allowed_sources": store.get_cfg(conn, "allowed_sources")}
    finally:
        conn.close()


def save_settings(retention, sources):
    """Validates and stores retention days + sender allow-list. Returns an error message or None."""
    try:
        days = int(retention)
    except (TypeError, ValueError):
        return "Saklama süresi sayı olmalı."
    if not 1 <= days <= store.MAX_RETENTION_DAYS:
        return "Saklama süresi 1-%d gün olmalı." % store.MAX_RETENTION_DAYS
    try:
        nets = allow.parse(sources)
    except ValueError:
        return "İzin verilen kaynaklar geçersiz (örn. 10.0.0.0/24, 192.168.1.5)."
    conn = _conn()
    try:
        with conn:
            conn.execute("INSERT INTO syslog_cfg(k,v) VALUES('retention_days',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                         (str(days),))
            conn.execute("INSERT INTO syslog_cfg(k,v) VALUES('allowed_sources',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                         (", ".join(str(n) for n in nets),))
    finally:
        conn.close()
    return None
