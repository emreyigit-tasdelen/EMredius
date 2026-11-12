# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""SQLite storage for aggregated flows: one row per (minute, exporter, 5-tuple-without-ports-ephemeral) bucket."""
from __future__ import annotations

import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS flow_acl (k TEXT PRIMARY KEY, v TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS flow_agg (
    bucket INTEGER NOT NULL, exporter TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL,
    sport INTEGER NOT NULL, dport INTEGER NOT NULL, proto INTEGER NOT NULL,
    bytes INTEGER NOT NULL DEFAULT 0, pkts INTEGER NOT NULL DEFAULT 0, flows INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, exporter, src, dst, sport, dport, proto)
);
CREATE INDEX IF NOT EXISTS idx_flow_agg_bucket ON flow_agg(bucket);
CREATE TABLE IF NOT EXISTS flow_exporters (
    ip TEXT PRIMARY KEY, version INTEGER, first_seen INTEGER, last_seen INTEGER,
    packets INTEGER NOT NULL DEFAULT 0, flows INTEGER NOT NULL DEFAULT 0
);
"""
RETENTION_DAYS = 7


def connect(path):
    conn = sqlite3.connect(path, timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(SCHEMA)
    return conn


class Aggregator:
    """Collects flows in memory; flush() upserts them in one transaction."""

    def __init__(self):
        self.rows = {}
        self.exporters = {}

    def add(self, exporter, version, flows, now=None):
        now = int(now or time.time())
        ex = self.exporters.setdefault(exporter, [version, 0, 0])
        ex[0], ex[1], ex[2] = version, ex[1] + 1, ex[2] + len(flows)
        for f in flows:
            # low port = service side; the ephemeral side is dropped so one conversation stays one row
            sport, dport = f["sport"], f["dport"]
            if f["proto"] in (6, 17) and sport > 1023 and dport <= 1023:
                sport = 0
            elif f["proto"] in (6, 17) and dport > 1023 and sport <= 1023:
                dport = 0
            elif f["proto"] in (6, 17) and sport > 1023 and dport > 1023:
                sport = 0
            key = ((f.get("ts") or now) // 60 * 60, exporter, f["src"], f["dst"], sport, dport, f["proto"])
            r = self.rows.setdefault(key, [0, 0, 0])
            r[0] += f["bytes"]; r[1] += f["pkts"]; r[2] += 1

    def flush(self, conn, now=None):
        now = int(now or time.time())
        if not self.rows and not self.exporters:
            return 0
        rows, exps = self.rows, self.exporters
        self.rows, self.exporters = {}, {}
        with conn:
            conn.executemany(
                "INSERT INTO flow_agg(bucket,exporter,src,dst,sport,dport,proto,bytes,pkts,flows) "
                "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(bucket,exporter,src,dst,sport,dport,proto) "
                "DO UPDATE SET bytes=bytes+excluded.bytes, pkts=pkts+excluded.pkts, flows=flows+excluded.flows",
                [k + tuple(v) for k, v in rows.items()])
            for ip, (ver, packets, flows) in exps.items():
                conn.execute(
                    "INSERT INTO flow_exporters(ip,version,first_seen,last_seen,packets,flows) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(ip) DO UPDATE SET version=excluded.version, last_seen=excluded.last_seen, "
                    "packets=packets+excluded.packets, flows=flows+excluded.flows",
                    (ip, ver, now, now, packets, flows))
        return len(rows)


def purge(conn, days=RETENTION_DAYS, now=None):
    cutoff = int(now or time.time()) - days * 86400
    with conn:
        return conn.execute("DELETE FROM flow_agg WHERE bucket < ?", (cutoff,)).rowcount
