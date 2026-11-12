# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Erişilebilirlik: Servis Sağlığı yoklamalarından durum değişimleri NMS veritabanında saklanır; 24 saat / 7 / 30 gün
erişilebilirlik yüzdesi ve kesinti listesi hesaplanır. Yalnızca up/down kaydedilir (unknown süreye katılmaz)."""
import threading
import time
from datetime import datetime

from ..core import get_nms_db
from . import svchealth

SCHEMA = """
CREATE TABLE IF NOT EXISTS avail_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, svc_key TEXT NOT NULL, status TEXT NOT NULL, ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_avail_svc_ts ON avail_events(svc_key, ts);
"""
WINDOWS = (("24 saat", 86400), ("7 gün", 7 * 86400), ("30 gün", 30 * 86400))
_schema_ok = set()
_last = {}
_lock = threading.Lock()


def _conn():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        conn.commit()
        _schema_ok.add(key)
    return conn


def record(rows, now=None):
    """svchealth yoklama sonucu: yalnız durum değiştiğinde (veya ilk kez) satır yazar."""
    now = now or time.time()
    changed = []
    with _lock:
        for r in rows:
            st = r["status"]
            if st in ("up", "down") and _last.get(r["key"]) != st:
                _last[r["key"]] = st
                changed.append((r["key"], st, now))
    if not changed:
        return 0
    conn = _conn()
    try:
        conn.executemany("INSERT INTO avail_events(svc_key,status,ts) VALUES (?,?,?)", changed)
        conn.commit()
    finally:
        conn.close()
    return len(changed)


def compute(events, since, now):
    """events: [(status, ts)] artan sırada (since öncesi son kayıt dahil). -> (up_s, down_s, outages[(start,end)])"""
    up = down = 0.0
    outages = []
    for i, (st, ts) in enumerate(events):
        start = max(ts, since)
        end = events[i + 1][1] if i + 1 < len(events) else now
        if end <= start:
            continue
        if st == "up":
            up += end - start
        else:
            down += end - start
            outages.append((start, end))
    return up, down, outages


def report(now=None):
    now = now or time.time()
    conn = _conn()
    try:
        out = []
        for c in svchealth.CHECKS:
            key = c["key"]
            row = {"key": key, "name": c["name"], "windows": [], "outages": []}
            for label, secs in WINDOWS:
                since = now - secs
                evs = [(r["status"], r["ts"]) for r in conn.execute(
                    "SELECT status, ts FROM avail_events WHERE svc_key=? AND ts>=? ORDER BY ts", (key, since))]
                prev = conn.execute("SELECT status, ts FROM avail_events WHERE svc_key=? AND ts<? ORDER BY ts DESC LIMIT 1",
                                    (key, since)).fetchone()
                if prev:
                    evs.insert(0, (prev["status"], prev["ts"]))
                up, down, outages = compute(evs, since, now)
                tot = up + down
                row["windows"].append({"label": label, "pct": round(100.0 * up / tot, 3) if tot else None,
                                       "down_min": round(down / 60.0, 1)})
                if secs == WINDOWS[-1][1]:
                    row["outages"] = [{"start": datetime.fromtimestamp(a).strftime("%d.%m.%Y %H:%M:%S"),
                                       "minutes": round((b - a) / 60.0, 1)} for a, b in outages[-10:]]
            out.append(row)
        return out
    finally:
        conn.close()


def purge_old(days=90, now=None):
    conn = _conn()
    try:
        conn.execute("DELETE FROM avail_events WHERE ts<?", ((now or time.time()) - days * 86400,))
        conn.commit()
    finally:
        conn.close()


def register():
    svchealth.add_listener(record)
