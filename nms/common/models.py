# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Data models and dataclasses for Enterprise TACACS+ NMS."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import sqlite3
from typing import Any, Dict, Optional


@dataclass
class Group:
    id: Optional[int] = None
    name: str = ""
    priv_lvl: int = 1
    default_policy: str = "deny"
    description: str = ""
    created_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Group":
        return cls(
            id=row["id"],
            name=row["name"],
            priv_lvl=row["priv_lvl"],
            default_policy=row["default_policy"],
            description=row["description"] or "",
            created_at=row["created_at"] if "created_at" in row.keys() else None,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class User:
    id: Optional[int] = None
    username: str = ""
    password_hash: str = ""
    enable_password_hash: str = ""
    chap_secret: str = ""
    priv_lvl: int = 1
    group_id: Optional[int] = None
    enabled: bool = True
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "User":
        keys = row.keys()
        return cls(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            enable_password_hash=row["enable_password_hash"] or "" if "enable_password_hash" in keys else "",
            chap_secret=row["chap_secret"] or "" if "chap_secret" in keys else "",
            priv_lvl=row["priv_lvl"],
            group_id=row["group_id"],
            enabled=bool(row["enabled"]),
            created_at=row["created_at"] if "created_at" in keys else None,
            updated_at=row["updated_at"] if "updated_at" in keys else None,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TacacsClient:
    id: Optional[int] = None
    name: str = ""
    ip_cidr: str = ""
    shared_secret: str = ""
    vendor: str = "cisco"
    description: str = ""
    is_active: bool = True
    created_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "TacacsClient":
        return cls(
            id=row["id"],
            name=row["name"],
            ip_cidr=row["ip_cidr"],
            shared_secret=row["shared_secret"],
            vendor=row["vendor"] or "cisco",
            description=row["description"] or "",
            is_active=bool(row["is_active"]),
            created_at=row["created_at"] if "created_at" in row.keys() else None,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TacacsRule:
    id: Optional[int] = None
    group_id: Optional[int] = None
    priority: int = 100
    pattern: str = ""
    action: str = "permit"
    description: str = ""
    created_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "TacacsRule":
        return cls(
            id=row["id"],
            group_id=row["group_id"],
            priority=row["priority"],
            pattern=row["pattern"],
            action=row["action"],
            description=row["description"] or "",
            created_at=row["created_at"] if "created_at" in row.keys() else None,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TacacsAccountingRecord:
    id: Optional[int] = None
    timestamp: Optional[str] = None
    device_ip: str = ""
    client_ip: str = ""
    username: str = ""
    priv_lvl: int = 1
    cmd: str = ""
    status: str = "PERMITTED"

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "TacacsAccountingRecord":
        return cls(
            id=row["id"],
            timestamp=row["timestamp"] if "timestamp" in row.keys() else None,
            device_ip=row["device_ip"],
            client_ip=row["client_ip"] or "",
            username=row["username"],
            priv_lvl=row["priv_lvl"],
            cmd=row["cmd"],
            status=row["status"],
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DaemonStatus:
    daemon_name: str
    last_heartbeat: Optional[str] = None
    pid: Optional[int] = None
    status: str = "RUNNING"
    metrics_json: str = "{}"

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "DaemonStatus":
        return cls(
            daemon_name=row["daemon_name"],
            last_heartbeat=row["last_heartbeat"] if "last_heartbeat" in row.keys() else None,
            pid=row["pid"],
            status=row["status"],
            metrics_json=row["metrics_json"] or "{}",
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SnmpDevice:
    id: Optional[int] = None
    ip: str = ""
    port: int = 161
    version: str = "v2c"
    community: str = "public"
    v3_user: str = ""
    v3_auth_proto: str = ""
    v3_auth_key: str = ""
    v3_priv_proto: str = ""
    v3_priv_key: str = ""
    vendor: str = "Generic"
    sys_name: str = ""
    sys_descr: str = ""
    status: str = "ONLINE"
    last_seen: Optional[str] = None
    created_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "SnmpDevice":
        keys = row.keys()
        return cls(
            id=row["id"],
            ip=row["ip"],
            port=row["port"],
            version=row["version"],
            community=row["community"] or "public",
            v3_user=row["v3_user"] or "" if "v3_user" in keys else "",
            v3_auth_proto=row["v3_auth_proto"] or "" if "v3_auth_proto" in keys else "",
            v3_auth_key=row["v3_auth_key"] or "" if "v3_auth_key" in keys else "",
            v3_priv_proto=row["v3_priv_proto"] or "" if "v3_priv_proto" in keys else "",
            v3_priv_key=row["v3_priv_key"] or "" if "v3_priv_key" in keys else "",
            vendor=row["vendor"] or "Generic" if "vendor" in keys else "Generic",
            sys_name=row["sys_name"] or "" if "sys_name" in keys else "",
            sys_descr=row["sys_descr"] or "" if "sys_descr" in keys else "",
            status=row["status"] or "ONLINE" if "status" in keys else "ONLINE",
            last_seen=row["last_seen"] if "last_seen" in keys else None,
            created_at=row["created_at"] if "created_at" in keys else None,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SnmpInterface:
    id: Optional[int] = None
    device_id: int = 0
    if_index: int = 0
    if_descr: str = ""
    if_name: str = ""
    if_type: int = 6
    if_speed: int = 0
    if_admin_status: int = 1
    if_oper_status: int = 1
    if_mac: str = ""
    last_updated: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "SnmpInterface":
        keys = row.keys()
        return cls(
            id=row["id"],
            device_id=row["device_id"],
            if_index=row["if_index"],
            if_descr=row["if_descr"] or "" if "if_descr" in keys else "",
            if_name=row["if_name"] or "" if "if_name" in keys else "",
            if_type=row["if_type"] if "if_type" in keys else 6,
            if_speed=row["if_speed"] if "if_speed" in keys else 0,
            if_admin_status=row["if_admin_status"] if "if_admin_status" in keys else 1,
            if_oper_status=row["if_oper_status"] if "if_oper_status" in keys else 1,
            if_mac=row["if_mac"] or "" if "if_mac" in keys else "",
            last_updated=row["last_updated"] if "last_updated" in keys else None,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SnmpTelemetry:
    id: Optional[int] = None
    timestamp: Optional[str] = None
    device_id: int = 0
    if_index: int = 0
    in_bps: float = 0.0
    out_bps: float = 0.0
    in_pps: float = 0.0
    out_pps: float = 0.0
    in_errors: float = 0.0
    out_errors: float = 0.0

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "SnmpTelemetry":
        keys = row.keys()
        return cls(
            id=row["id"],
            timestamp=row["timestamp"] if "timestamp" in keys else None,
            device_id=row["device_id"],
            if_index=row["if_index"],
            in_bps=float(row["in_bps"] or 0.0),
            out_bps=float(row["out_bps"] or 0.0),
            in_pps=float(row["in_pps"] or 0.0) if "in_pps" in keys else 0.0,
            out_pps=float(row["out_pps"] or 0.0) if "out_pps" in keys else 0.0,
            in_errors=float(row["in_errors"] or 0.0) if "in_errors" in keys else 0.0,
            out_errors=float(row["out_errors"] or 0.0) if "out_errors" in keys else 0.0,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SnmpHealth:
    id: Optional[int] = None
    timestamp: Optional[str] = None
    device_id: int = 0
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    temperature_c: Optional[float] = None
    uptime_seconds: int = 0

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "SnmpHealth":
        keys = row.keys()
        return cls(
            id=row["id"],
            timestamp=row["timestamp"] if "timestamp" in keys else None,
            device_id=row["device_id"],
            cpu_percent=float(row["cpu_percent"] or 0.0),
            memory_percent=float(row["memory_percent"] or 0.0),
            temperature_c=float(row["temperature_c"]) if row["temperature_c"] is not None else None,
            uptime_seconds=int(row["uptime_seconds"] or 0),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Alarm:
    id: Optional[int] = None
    timestamp: Optional[str] = None
    device_id: int = 0
    if_index: Optional[int] = None
    alarm_type: str = ""
    severity: str = "INFO"
    message: str = ""
    resolved: bool = False
    resolved_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Alarm":
        keys = row.keys()
        return cls(
            id=row["id"],
            timestamp=row["timestamp"] if "timestamp" in keys else None,
            device_id=row["device_id"],
            if_index=row["if_index"] if "if_index" in keys else None,
            alarm_type=row["alarm_type"],
            severity=row["severity"],
            message=row["message"] or "",
            resolved=bool(row["resolved"]),
            resolved_at=row["resolved_at"] if "resolved_at" in keys else None,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
