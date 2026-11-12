# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""SQLite storage for syslog messages + collector settings (retention, allowed sources)."""
from __future__ import annotations

import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS syslog_msgs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, src_ip TEXT NOT NULL,
    facility INTEGER NOT NULL, severity INTEGER NOT NULL, host TEXT NOT NULL DEFAULT '',
    app TEXT NOT NULL DEFAULT '', msg TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_syslog_ts ON syslog_msgs(ts);
CREATE INDEX IF NOT EXISTS idx_syslog_src ON syslog_msgs(src_ip, ts);
CREATE TABLE IF NOT EXISTS syslog_cfg (k TEXT PRIMARY KEY, v TEXT NOT NULL DEFAULT '');
"""
DEFAULT_RETENTION_DAYS = 30
MAX_RETENTION_DAYS = 3650


def connect(path):
    conn = sqlite3.connect(path, timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(SCHEMA)
    return conn


def get_cfg(conn, key, default=""):
    row = conn.execute("SELECT v FROM syslog_cfg WHERE k=?", (key,)).fetchone()
    return row[0] if row else default


def retention_days(conn):
    try:
        d = int(get_cfg(conn, "retention_days", DEFAULT_RETENTION_DAYS))
    except (ValueError, TypeError, sqlite3.Error):
        return DEFAULT_RETENTION_DAYS
    return d if 1 <= d <= MAX_RETENTION_DAYS else DEFAULT_RETENTION_DAYS


def insert(conn, rows):
    with conn:
        conn.executemany("INSERT INTO syslog_msgs(ts,src_ip,facility,severity,host,app,msg) VALUES(?,?,?,?,?,?,?)",
                         [(r["ts"], r["src_ip"], r["facility"], r["severity"], r["host"], r["app"], r["msg"])
                          for r in rows])
    return len(rows)


def purge(conn, days=None, now=None):
    days = days or retention_days(conn)
    cutoff = int(now or time.time()) - days * 86400
    with conn:
        return conn.execute("DELETE FROM syslog_msgs WHERE ts < ?", (cutoff,)).rowcount
