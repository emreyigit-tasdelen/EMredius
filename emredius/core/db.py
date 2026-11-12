# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Database access.

MariaDB (`radius`): small thread-safe connection pool. `get_db()` returns a pooled connection with the same API
as a PyMySQL connection (DictCursor, autocommit=True); `close()` hands it back to the pool instead of closing it.
A transaction left open (conn.begin() without commit) is rolled back before reuse.

NMS (SQLite, WAL): `get_nms_db()` opens a short-lived connection to the database shared with the TACACS+/SNMP
daemons. Both work without an application context, so background threads can use them too."""
import collections
import logging
import os
import sqlite3
import threading
import time

import pymysql
import pymysql.cursors
from pymysql.constants import SERVER_STATUS

log = logging.getLogger(__name__)

_IDLE_PING_AFTER = 30.0  # seconds a pooled connection may idle before it is pinged on checkout


class _Pool:
    def __init__(self):
        self._lock = threading.Lock()
        self._idle = collections.deque()
        self._params = None
        self._max_idle = 8

    def configure(self, params, max_idle):
        with self._lock:
            old, self._idle = list(self._idle), collections.deque()
            self._params = dict(params)
            self._max_idle = max(0, int(max_idle))
        for raw, _ in old:
            _quiet_close(raw)

    @property
    def params(self):
        if self._params is None:
            raise RuntimeError("database pool is not configured (call core.db.configure first)")
        return self._params

    def acquire(self):
        while True:
            with self._lock:
                item = self._idle.pop() if self._idle else None
            if item is None:
                return pymysql.connect(**self.params)
            raw, released_at = item
            if time.monotonic() - released_at < _IDLE_PING_AFTER:
                return raw
            try:
                raw.ping(reconnect=False)
                return raw
            except Exception:
                _quiet_close(raw)

    def release(self, raw):
        try:
            if not raw.open:
                return
            if raw.server_status & SERVER_STATUS.SERVER_STATUS_IN_TRANS:
                raw.rollback()
            if not raw.get_autocommit():
                raw.autocommit(True)
        except Exception:
            _quiet_close(raw)
            return
        with self._lock:
            if len(self._idle) < self._max_idle:
                self._idle.append((raw, time.monotonic()))
                return
        _quiet_close(raw)

    def close_all(self):
        with self._lock:
            items, self._idle = list(self._idle), collections.deque()
        for raw, _ in items:
            _quiet_close(raw)


def _quiet_close(raw):
    try:
        raw.close()
    except Exception:
        pass


_pool = _Pool()


class PooledConnection:
    """Proxy around a PyMySQL connection; close() (or leaving a `with` block) returns it to the pool."""

    __slots__ = ("_raw",)

    def __init__(self, raw):
        self._raw = raw

    def __getattr__(self, name):
        if name == "_raw":  # slot not initialised (constructor failed)
            raise AttributeError(name)
        raw = self._raw
        if raw is None:
            raise pymysql.err.InterfaceError(0, "connection already returned to the pool")
        return getattr(raw, name)

    def close(self):
        raw, self._raw = self._raw, None
        if raw is not None:
            _pool.release(raw)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def __del__(self):
        # A connection that was never closed explicitly still goes back to the pool.
        try:
            self.close()
        except Exception:
            pass


def configure(cfg):
    """Configures the MariaDB pool from the app config dict (DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME)."""
    params = {
        "host": cfg.get("DB_HOST", "127.0.0.1"),
        "port": int(cfg.get("DB_PORT", 3306)),
        "user": cfg.get("DB_USER", "radius"),
        "password": cfg.get("DB_PASSWORD", ""),
        "database": cfg.get("DB_NAME", "radius"),
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
        "autocommit": True,
        "connect_timeout": 5,
    }
    _pool.configure(params, cfg.get("DB_POOL_SIZE", 8))
    global NMS_DB_PATH
    NMS_DB_PATH = cfg.get("NMS_DB_PATH") or NMS_DB_PATH
    # NMS API blueprints resolve their database from $NMS_DB_PATH: publish one path for the panel and its APIs.
    os.environ["NMS_DB_PATH"] = NMS_DB_PATH


def get_db():
    return PooledConnection(_pool.acquire())


def connect_direct(**overrides):
    """Unpooled connection (e.g. for maintenance tasks that change session settings)."""
    params = dict(_pool.params)
    params.update(overrides)
    return pymysql.connect(**params)


def close_pool():
    _pool.close_all()


NMS_DB_PATH = os.environ.get("NMS_DB_PATH", "")


def get_nms_db():
    if not NMS_DB_PATH:
        raise RuntimeError("NMS_DB_PATH is not configured")
    db_dir = os.path.dirname(NMS_DB_PATH)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(NMS_DB_PATH, timeout=5.0)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        conn.close()
        raise
    return conn
