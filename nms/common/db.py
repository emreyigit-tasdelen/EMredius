# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Database connection factory, schema migration, and seeding for Enterprise TACACS+ NMS."""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
from typing import Optional

DEFAULT_DB_PATH = "data/enterprise_nms.db"


class ClosingConnection(sqlite3.Connection):
    """SQLite connection subclass that automatically closes when exiting a 'with' block."""

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            super().__exit__(exc_type, exc_val, exc_tb)
        finally:
            self.close()


def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = os.urandom(16).hex()
    iterations = 100_000
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    ).hex()
    return f"pbkdf2:sha256:{iterations}${salt}${derived}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verifies a plain password against a stored PBKDF2 hash or plain text."""
    if not stored_hash:
        return False
    if stored_hash.startswith("pbkdf2:sha256:"):
        try:
            parts = stored_hash.split("$")
            iterations = int(parts[0].split(":")[2])
            salt = parts[1]
            expected_hash = parts[2]
            derived = hashlib.pbkdf2_hmac(
                "sha256",
                plain_password.encode("utf-8"),
                salt.encode("utf-8"),
                iterations,
            ).hex()
            return hmac.compare_digest(derived, expected_hash)
        except Exception:
            return False
    # Fallback to direct constant-time comparison for test fixtures or plain tokens
    return hmac.compare_digest(plain_password, stored_hash)


def get_db_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Returns an SQLite connection configured with WAL mode and high-concurrency pragmas."""
    dir_path = os.path.dirname(db_path)
    if dir_path and not os.path.exists(dir_path):
        os.makedirs(dir_path, exist_ok=True)

    conn = sqlite3.connect(db_path, timeout=5.0, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initializes the database schema and performs idempotent default seeding."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            # 1. Groups Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(64) UNIQUE NOT NULL,
                    priv_lvl INTEGER NOT NULL DEFAULT 1 CHECK(priv_lvl BETWEEN 0 AND 15),
                    default_policy VARCHAR(16) NOT NULL DEFAULT 'deny' CHECK(default_policy IN ('permit', 'deny')),
                    description TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )

            # 2. Users Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username VARCHAR(64) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    enable_password_hash VARCHAR(255) DEFAULT '',
                    chap_secret VARCHAR(255) DEFAULT '',
                    priv_lvl INTEGER DEFAULT 1 CHECK(priv_lvl BETWEEN 0 AND 15),
                    group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
                    enabled BOOLEAN NOT NULL DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )

            # 3. TACACS+ Clients Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tacacs_clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(64) NOT NULL,
                    ip_cidr VARCHAR(45) UNIQUE NOT NULL,
                    shared_secret VARCHAR(128) NOT NULL,
                    vendor VARCHAR(32) NOT NULL DEFAULT 'cisco',
                    description TEXT DEFAULT '',
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )

            # 4. TACACS+ Rules Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tacacs_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
                    priority INTEGER NOT NULL DEFAULT 100,
                    pattern TEXT NOT NULL,
                    action VARCHAR(10) NOT NULL CHECK(action IN ('permit', 'deny')),
                    description TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )

            # 5. TACACS+ Accounting Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tacacs_accounting (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    device_ip VARCHAR(45) NOT NULL,
                    client_ip VARCHAR(45) DEFAULT '',
                    username VARCHAR(64) NOT NULL,
                    priv_lvl INTEGER NOT NULL DEFAULT 1,
                    cmd TEXT NOT NULL,
                    status VARCHAR(16) NOT NULL DEFAULT 'PERMITTED'
                );
                """
            )

            # 6. Daemon Status Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS daemon_status (
                    daemon_name VARCHAR(64) PRIMARY KEY,
                    last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    pid INTEGER,
                    status VARCHAR(32) DEFAULT 'RUNNING',
                    metrics_json TEXT DEFAULT '{}'
                );
                """
            )

            # 7. SNMP Devices Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snmp_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip VARCHAR(45) UNIQUE NOT NULL,
                    port INTEGER NOT NULL DEFAULT 161,
                    version VARCHAR(10) NOT NULL DEFAULT 'v2c' CHECK(version IN ('v2c', 'v3')),
                    community VARCHAR(64) DEFAULT 'public',
                    v3_user VARCHAR(64) DEFAULT '',
                    v3_auth_proto VARCHAR(20) DEFAULT '',
                    v3_auth_key VARCHAR(128) DEFAULT '',
                    v3_priv_proto VARCHAR(20) DEFAULT '',
                    v3_priv_key VARCHAR(128) DEFAULT '',
                    vendor VARCHAR(64) DEFAULT 'Generic',
                    sys_name VARCHAR(128) DEFAULT '',
                    sys_descr TEXT DEFAULT '',
                    status VARCHAR(20) DEFAULT 'ONLINE' CHECK(status IN ('ONLINE', 'OFFLINE', 'WARNING')),
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )

            # 8. SNMP Interfaces Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snmp_interfaces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL REFERENCES snmp_devices(id) ON DELETE CASCADE,
                    if_index INTEGER NOT NULL,
                    if_descr VARCHAR(128) DEFAULT '',
                    if_name VARCHAR(64) DEFAULT '',
                    if_type INTEGER DEFAULT 6,
                    if_speed BIGINT DEFAULT 0,
                    if_admin_status INTEGER DEFAULT 1,
                    if_oper_status INTEGER DEFAULT 1,
                    if_mac VARCHAR(20) DEFAULT '',
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(device_id, if_index)
                );
                """
            )

            # 9. SNMP Telemetry Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snmp_telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    device_id INTEGER NOT NULL REFERENCES snmp_devices(id) ON DELETE CASCADE,
                    if_index INTEGER NOT NULL,
                    in_bps REAL DEFAULT 0.0,
                    out_bps REAL DEFAULT 0.0,
                    in_pps REAL DEFAULT 0.0,
                    out_pps REAL DEFAULT 0.0,
                    in_errors REAL DEFAULT 0.0,
                    out_errors REAL DEFAULT 0.0
                );
                """
            )

            # 10. SNMP Health Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snmp_health (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    device_id INTEGER NOT NULL REFERENCES snmp_devices(id) ON DELETE CASCADE,
                    cpu_percent REAL DEFAULT 0.0,
                    memory_percent REAL DEFAULT 0.0,
                    temperature_c REAL DEFAULT NULL,
                    uptime_seconds BIGINT DEFAULT 0
                );
                """
            )

            # 11. Alarms Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alarms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    device_id INTEGER NOT NULL REFERENCES snmp_devices(id) ON DELETE CASCADE,
                    if_index INTEGER DEFAULT NULL,
                    alarm_type VARCHAR(64) NOT NULL,
                    severity VARCHAR(20) NOT NULL CHECK(severity IN ('INFO', 'WARNING', 'CRITICAL')),
                    message TEXT NOT NULL,
                    resolved BOOLEAN DEFAULT 0,
                    resolved_at TIMESTAMP DEFAULT NULL
                );
                """
            )

            # Indices
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tacacs_clients_ip ON tacacs_clients(ip_cidr);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tacacs_rules_group_prio ON tacacs_rules(group_id, priority ASC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tacacs_acct_timestamp ON tacacs_accounting(timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tacacs_acct_username ON tacacs_accounting(username);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tacacs_acct_device_ip ON tacacs_accounting(device_ip);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_snmp_devices_ip ON snmp_devices(ip);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_snmp_devices_status ON snmp_devices(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_snmp_interfaces_dev_idx ON snmp_interfaces(device_id, if_index);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_snmp_telemetry_dev_if_ts ON snmp_telemetry(device_id, if_index, timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_snmp_health_dev_ts ON snmp_health(device_id, timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alarms_active ON alarms(resolved, device_id, timestamp DESC);")

            # Migration: Ensure chap_secret column exists in users table (idempotent migration)
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(users);")
            user_columns = {row["name"] for row in cursor.fetchall()}
            if "chap_secret" not in user_columns and len(user_columns) > 0:
                conn.execute("ALTER TABLE users ADD COLUMN chap_secret VARCHAR(255) DEFAULT '';")

            # Seed Groups
            default_groups = [
                ("admin", 15, "permit", "Full Administrator Access"),
                ("operator", 7, "deny", "Network Operations Access"),
                ("helpdesk", 1, "deny", "Read-Only Diagnostics Access"),
            ]
            for name, priv, policy, desc in default_groups:
                conn.execute(
                    """
                    INSERT INTO groups (name, priv_lvl, default_policy, description)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        priv_lvl = excluded.priv_lvl,
                        default_policy = excluded.default_policy,
                        description = excluded.description
                    """,
                    (name, priv, policy, desc),
                )

            # Fetch group IDs
            group_ids = {}
            cursor = conn.cursor()
            cursor.execute("SELECT id, name FROM groups")
            for row in cursor.fetchall():
                group_ids[row["name"]] = row["id"]

            # Seed Users
            default_users = [
                ("admin", hash_password("Admin123!"), hash_password("Enable123!"), "Admin123!", 15, group_ids.get("admin")),
                ("operator", hash_password("Operator123!"), "", "Operator123!", 7, group_ids.get("operator")),
                ("helpdesk", hash_password("Guest123!"), "", "Guest123!", 1, group_ids.get("helpdesk")),
            ]
            for uname, phash, ehash, csec, priv, gid in default_users:
                conn.execute(
                    """
                    INSERT INTO users (username, password_hash, enable_password_hash, chap_secret, priv_lvl, group_id, enabled)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(username) DO UPDATE SET
                        password_hash = excluded.password_hash,
                        enable_password_hash = excluded.enable_password_hash,
                        chap_secret = excluded.chap_secret,
                        priv_lvl = excluded.priv_lvl,
                        group_id = excluded.group_id
                    """,
                    (uname, phash, ehash, csec, priv, gid),
                )

            # Seed Rules
            helpdesk_id = group_ids.get("helpdesk")
            operator_id = group_ids.get("operator")
            admin_id = group_ids.get("admin")

            default_rules = [
                # Helpdesk
                (helpdesk_id, 10, r"^show(\s.*)?$", "permit", "Diagnostic inspections"),
                (helpdesk_id, 20, r"^ping(\s.*)?$", "permit", "Reachability verification"),
                (helpdesk_id, 30, r"^traceroute(\s.*)?$", "permit", "Hop tracing"),
                (helpdesk_id, 100, r".*", "deny", "Explicit fallback denial"),
                # Operator
                (operator_id, 10, r"^reload(\s.*)?$", "deny", "Prohibit reboot"),
                (operator_id, 20, r"^format(\s.*)?$", "deny", "Prohibit disk formatting"),
                (operator_id, 30, r"^erase(\s.*)?$", "deny", "Prohibit nvram wipe"),
                (operator_id, 40, r"^config(ure)?(\s.*)?$", "deny", "Prohibit configuration changes"),
                (operator_id, 50, r"^show(\s.*)?$", "permit", "Allow all show commands"),
                (operator_id, 60, r"^ping(\s.*)?$", "permit", "Allow ping diagnostics"),
                (operator_id, 70, r"^traceroute(\s.*)?$", "permit", "Allow traceroute"),
                (operator_id, 80, r"^clear(\s.*)?$", "permit", "Allow counter resets"),
                (operator_id, 100, r".*", "deny", "Explicit fallback denial"),
                # Admin
                (admin_id, 10, r"^format(\s.*)?$", "deny", "Safety lock against accidental disk wipe"),
            ]

            for gid, prio, pattern, action, desc in default_rules:
                if gid is None:
                    continue
                cursor.execute(
                    "SELECT id FROM tacacs_rules WHERE group_id = ? AND pattern = ? AND priority = ?",
                    (gid, pattern, prio),
                )
                if not cursor.fetchone():
                    cursor.execute(
                        """
                        INSERT INTO tacacs_rules (group_id, priority, pattern, action, description)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (gid, prio, pattern, action, desc),
                    )

            # Seed Default Client (localhost)
            conn.execute(
                """
                INSERT INTO tacacs_clients (name, ip_cidr, shared_secret, vendor, description, is_active)
                VALUES (?, ?, ?, ?, ?, 1)
                ON CONFLICT(ip_cidr) DO UPDATE SET
                    shared_secret = excluded.shared_secret,
                    vendor = excluded.vendor,
                    name = excluded.name
                """,
                ("localhost_test", "127.0.0.1/32", "testing123", "cisco", "Default localhost test client"),
            )
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        raise
