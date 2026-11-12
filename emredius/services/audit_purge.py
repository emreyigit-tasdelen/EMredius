# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Law 5651 retention clean-up of `radacct`: only days past the retention period, whose signed archive verifies
OK and whose archived row count covers the database rows, are deleted. Archive files / chain.log are never touched."""
import csv
import logging
import os
from datetime import date, datetime, timedelta

import pymysql

from ..core import get_db, get_setting, safe_int, set_setting
from . import audit5651
from .radius_users import ServiceError

log = logging.getLogger(__name__)

SETTING_KEY = "retention_days_5651"
MIN_RETENTION_DAYS = 730      # 2 years: legal minimum, the setting cannot go below it
DEFAULT_RETENTION_DAYS = 730
MAX_RETENTION_DAYS = 3650
CONFIRM_TEXT = "SİL"
DELETE_BATCH = 5000


def get_retention_days():
    days = safe_int(get_setting(SETTING_KEY, ""), DEFAULT_RETENTION_DAYS, 1, 100000) or DEFAULT_RETENTION_DAYS
    return max(days, MIN_RETENTION_DAYS)


def save_retention_days(raw):
    days = safe_int(raw, None, 1, 100000)
    if days is None:
        raise ServiceError("Saklama süresi gün olarak sayı olmalıdır.")
    if days < MIN_RETENTION_DAYS:
        raise ServiceError(f"Saklama süresi en az {MIN_RETENTION_DAYS} gün olmalıdır.")
    if days > MAX_RETENTION_DAYS:
        raise ServiceError(f"Saklama süresi en fazla {MAX_RETENTION_DAYS} gün olabilir.")
    set_setting(SETTING_KEY, str(days))
    return days


def cutoff_date(retention_days, today=None):
    """Days strictly before this date (YYYY-MM-DD) are past retention."""
    return (today or date.today()) - timedelta(days=max(retention_days, MIN_RETENTION_DAYS))


def _csv_rows(path):
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return max(sum(1 for _ in csv.reader(fh)) - 1, 0)


def _db_counts(cutoff):
    """{ 'YYYY-MM-DD': row count } of radacct sessions that started before `cutoff`."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT DATE(acctstarttime) AS d, COUNT(*) AS n FROM radacct "
                        "WHERE acctstarttime IS NOT NULL AND acctstarttime < %s GROUP BY DATE(acctstarttime) "
                        "ORDER BY d", (datetime.combine(cutoff, datetime.min.time()),))
            return {r["d"].strftime("%Y-%m-%d"): int(r["n"]) for r in cur.fetchall()}
    finally:
        conn.close()


def build_plan(archive_dir, retention_days, today=None):
    """Returns {cutoff, retention_days, days: [{date, db_rows, archive_rows, eligible, reason}], eligible_rows,
    blocked_days, eligible_days}. Never deletes anything."""
    cutoff = cutoff_date(retention_days, today)
    try:
        counts = _db_counts(cutoff)
    except pymysql.MySQLError as e:
        log.error("purge plan: %s", e)
        raise ServiceError("Veritabanı sorgulanamadı.") from e
    verified = {}
    if counts:
        if not os.path.isdir(archive_dir):
            raise ServiceError("5651 arşiv dizini bulunamadı; doğrulanmış arşiv olmadan silme yapılamaz.")
        res = audit5651.verify_archive(archive_dir)
        chain_ok = (not res["chain_err"]) and not res["chain_broken"] and not res["chain_malformed"]
        if res.get("clock_present"):
            chain_ok = chain_ok and not (res["clock_err"] or res["clock_broken"] or res["clock_malformed"])
        verified = {r["date"]: r for r in res["rows"]}
    else:
        chain_ok = True
    days = []
    for day, n in sorted(counts.items()):
        item = {"date": day, "db_rows": n, "archive_rows": None, "eligible": False, "reason": ""}
        vr = verified.get(day)
        if not chain_ok:
            item["reason"] = "Hash zinciri doğrulanamadı"
        elif not vr or not vr["csv"]:
            item["reason"] = "Bu güne ait arşiv dosyası yok"
        elif not vr["ok"]:
            item["reason"] = "Arşiv doğrulaması başarısız: " + "; ".join(vr["problems"])
        else:
            try:
                item["archive_rows"] = _csv_rows(os.path.join(archive_dir, vr["csv"]))
            except OSError:
                item["reason"] = "Arşiv CSV'si okunamadı"
            else:
                if n > item["archive_rows"]:
                    item["reason"] = f"Veritabanında arşivden fazla kayıt var ({n} > {item['archive_rows']})"
                else:
                    item["eligible"] = True
        days.append(item)
    return {
        "cutoff": cutoff.isoformat(), "retention_days": retention_days, "days": days,
        "eligible_days": sum(1 for d in days if d["eligible"]),
        "blocked_days": sum(1 for d in days if not d["eligible"]),
        "eligible_rows": sum(d["db_rows"] for d in days if d["eligible"]),
        "total_rows": sum(d["db_rows"] for d in days),
    }


def execute(archive_dir, retention_days, today=None):
    """Re-builds the plan (never trusts a previous preview) and deletes only the eligible days.
    Returns {"deleted": n, "days": [..], "blocked_days": n}."""
    plan = build_plan(archive_dir, retention_days, today)
    deleted = 0
    done = []
    conn = get_db()
    try:
        with conn.cursor() as cur:
            for d in plan["days"]:
                if not d["eligible"]:
                    continue
                start = datetime.strptime(d["date"], "%Y-%m-%d")
                end = start + timedelta(days=1)
                while True:
                    cur.execute("DELETE FROM radacct WHERE acctstarttime >= %s AND acctstarttime < %s LIMIT %s",
                                (start, end, DELETE_BATCH))
                    n = cur.rowcount
                    deleted += n
                    if n < DELETE_BATCH:
                        break
                done.append(d["date"])
    except pymysql.MySQLError as e:
        log.error("purge execute: %s", e)
        raise ServiceError(f"Silme sırasında veritabanı hatası; {deleted} kayıt silindi, işlem durduruldu.") from e
    finally:
        conn.close()
    return {"deleted": deleted, "days": done, "blocked_days": plan["blocked_days"]}
