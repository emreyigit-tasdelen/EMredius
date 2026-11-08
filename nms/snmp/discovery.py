# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Auto-Discovery CIDR Scanner, Multi-Credential Waterfall Probing,
Vendor Hardware Fingerprinting, and RFC 2863 IF-MIB Interface Walk.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import ipaddress
import logging
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from nms.common.db import DEFAULT_DB_PATH, get_db_connection

logger = logging.getLogger("snmp.discovery")

# Standard RFC 1213 System Group OIDs
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

# RFC 2863 IF-MIB Base OIDs
IF_TABLE_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TABLE_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_TABLE_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_TABLE_PHYS = "1.3.6.1.2.1.2.2.1.6"
IF_TABLE_ADMIN = "1.3.6.1.2.1.2.2.1.7"
IF_TABLE_OPER = "1.3.6.1.2.1.2.2.1.8"
IF_XTABLE_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_XTABLE_HIGHSPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_XTABLE_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

# Vendor Enterprise SMI OID Prefixes
VENDOR_OID_PREFIXES: List[Tuple[str, str]] = [
    ("1.3.6.1.4.1.9.", "Cisco"),
    ("1.3.6.1.4.1.14988.", "MikroTik"),
    ("1.3.6.1.4.1.2011.", "Huawei"),
    ("1.3.6.1.4.1.2636.", "Juniper"),
    ("1.3.6.1.4.1.12356.", "Fortinet"),
    ("1.3.6.1.4.1.25506.", "HP_Aruba"),  # HPE / H3C Comware
    ("1.3.6.1.4.1.47196.", "HP_Aruba"),  # Aruba CX
    ("1.3.6.1.4.1.11.", "HP_Aruba"),     # HP ProCurve / ArubaOS-Switch
    ("1.3.6.1.4.1.14823.", "HP_Aruba"),  # Aruba Mobility Controller
]

# Fallback Vendor sysDescr Regex Patterns
VENDOR_DESCR_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\b(cisco|ios-xe|nx-os|c2960|catalyst|ios)\b", re.IGNORECASE), "Cisco"),
    (re.compile(r"\b(routeros|mikrotik)\b", re.IGNORECASE), "MikroTik"),
    (re.compile(r"\b(huawei|vrp|versatile routing platform)\b", re.IGNORECASE), "Huawei"),
    (re.compile(r"\b(junos|juniper)\b", re.IGNORECASE), "Juniper"),
    (re.compile(r"\b(fortigate|fortios|fortinet)\b", re.IGNORECASE), "Fortinet"),
    (re.compile(r"\b(procurve|comware|arubaos|aruba|h3c|hp networking)\b", re.IGNORECASE), "HP_Aruba"),
]


@dataclass
class SnmpCredentialProfile:
    """SNMP credential profile for discovery and polling."""
    version: str = "v2c"                  # 'v2c' or 'v3'
    community: str = "public"             # for v2c
    v3_user: str = ""                     # for v3
    v3_auth_proto: str = ""               # 'MD5', 'SHA', 'SHA256'
    v3_auth_key: str = ""
    v3_priv_proto: str = ""               # 'DES', 'AES', 'AES128', 'AES256'
    v3_priv_key: str = ""
    v3_context_name: str = ""


@dataclass
class DiscoveredInterface:
    """Enumerated network interface discovered from agent."""
    if_index: int
    if_descr: str = ""
    if_name: str = ""
    if_type: int = 6                      # 6 = ethernetCsmacd
    if_speed: int = 0                     # effective speed in bps
    if_admin_status: int = 1              # 1=up, 2=down
    if_oper_status: int = 1               # 1=up, 2=down, 7=lowerLayerDown
    if_mac: str = ""                      # Formatted XX:XX:XX:XX:XX:XX


@dataclass
class DiscoveredDevice:
    """Fully fingerprinted network device ready for persistence."""
    ip: str
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
    sys_object_id: str = ""
    sys_uptime: int = 0
    interfaces: List[DiscoveredInterface] = field(default_factory=list)


@dataclass
class DiscoveryScanConfig:
    """Configuration parameter bundle for a discovery sweep."""
    targets: Union[str, List[str]]
    port: int = 161
    v2c_communities: List[str] = field(default_factory=lambda: ["public", "private"])
    v3_credentials: List[SnmpCredentialProfile] = field(default_factory=list)
    concurrency: int = 50
    timeout: float = 1.0
    retries: int = 1
    walk_interfaces: bool = True
    persist_db: bool = True
    db_path: str = DEFAULT_DB_PATH
    allow_loopback: bool = False


@dataclass
class DiscoveryScanResult:
    """Summary result returned after discovery scan completion."""
    scanned_ips: int = 0
    discovered_devices: List[DiscoveredDevice] = field(default_factory=list)
    failed_ips: int = 0
    duration_seconds: float = 0.0


def _is_valid_target_ip(ip_obj: ipaddress.IPv4Address, allow_loopback: bool = False) -> bool:
    """Validates that an IP is a legitimate target (not loopback, multicast, etc.)."""
    if allow_loopback and ip_obj.is_loopback:
        return True
    return not (
        ip_obj.is_loopback
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
        or ip_obj.is_link_local
    )


def parse_targets(
    targets: Union[str, List[str]],
    max_hosts: int = 65536,
    allow_loopback: bool = False,
) -> List[str]:
    """Parses CIDR specifications, IP ranges, single IPs, and comma-separated lists."""
    raw_tokens: List[str] = []
    if isinstance(targets, str):
        parts = targets.replace("\n", ",").replace(";", ",").split(",")
        raw_tokens = [p.strip() for p in parts if p.strip()]
    elif isinstance(targets, (list, tuple)):
        for item in targets:
            if isinstance(item, str):
                parts = item.replace("\n", ",").replace(";", ",").split(",")
                raw_tokens.extend([p.strip() for p in parts if p.strip()])

    result_ips: List[str] = []
    seen: set = set()

    for token in raw_tokens:
        try:
            # 1. Range format: IP1 - IP2
            if "-" in token:
                range_parts = token.split("-")
                if len(range_parts) == 2:
                    start_str = range_parts[0].strip()
                    end_str = range_parts[1].strip()
                    start_ip = ipaddress.IPv4Address(start_str)

                    if "." not in end_str:
                        start_octets = start_str.split(".")
                        end_str = f"{start_octets[0]}.{start_octets[1]}.{start_octets[2]}.{end_str}"
                    end_ip = ipaddress.IPv4Address(end_str)

                    start_int = int(start_ip)
                    end_int = int(end_ip)
                    if start_int <= end_int:
                        for ip_int in range(start_int, end_int + 1):
                            ip_obj = ipaddress.IPv4Address(ip_int)
                            ip_str = str(ip_obj)
                            if _is_valid_target_ip(ip_obj, allow_loopback) and ip_str not in seen:
                                seen.add(ip_str)
                                result_ips.append(ip_str)
                                if len(result_ips) >= max_hosts:
                                    return result_ips
                    continue

            # 2. CIDR Network format: 192.168.1.0/24
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    if net.prefixlen == 32:
                        ip_str = str(net.network_address)
                        if _is_valid_target_ip(net.network_address, allow_loopback) and ip_str not in seen:
                            seen.add(ip_str)
                            result_ips.append(ip_str)
                    elif net.prefixlen == 31:
                        for addr in (net.network_address, net.broadcast_address):
                            ip_str = str(addr)
                            if _is_valid_target_ip(addr, allow_loopback) and ip_str not in seen:
                                seen.add(ip_str)
                                result_ips.append(ip_str)
                    else:
                        for host in net.hosts():
                            ip_str = str(host)
                            if _is_valid_target_ip(host, allow_loopback) and ip_str not in seen:
                                seen.add(ip_str)
                                result_ips.append(ip_str)
                                if len(result_ips) >= max_hosts:
                                    return result_ips
                continue

            # 3. Single IP Address
            single_ip = ipaddress.ip_address(token)
            if isinstance(single_ip, ipaddress.IPv4Address):
                ip_str = str(single_ip)
                if _is_valid_target_ip(single_ip, allow_loopback) and ip_str not in seen:
                    seen.add(ip_str)
                    result_ips.append(ip_str)
                    if len(result_ips) >= max_hosts:
                        return result_ips

        except Exception as exc:
            logger.warning("Failed to parse IP target token '%s': %s", token, exc)

    return result_ips


def fingerprint_vendor(sys_object_id: str, sys_descr: str = "") -> str:
    """Fingerprints network equipment vendor using sysObjectID prefix and sysDescr regex fallback."""
    if sys_object_id:
        clean_oid = sys_object_id.strip().lstrip(".")
        for prefix, vendor in VENDOR_OID_PREFIXES:
            clean_prefix = prefix.strip().lstrip(".")
            if clean_oid.startswith(clean_prefix):
                return vendor

    if sys_descr:
        for pattern, vendor in VENDOR_DESCR_PATTERNS:
            if pattern.search(sys_descr):
                return vendor

    return "Generic"


def format_mac_address(raw_mac: Union[bytes, str]) -> str:
    """Formats raw binary MAC octets or string into standard uppercase XX:XX:XX:XX:XX:XX format."""
    if not raw_mac:
        return ""
    if isinstance(raw_mac, (bytes, bytearray)):
        if len(raw_mac) == 6:
            return ":".join(f"{b:02X}" for b in raw_mac)
        try:
            raw_mac = raw_mac.decode("utf-8", errors="replace")
        except Exception:
            return ""

    if isinstance(raw_mac, str):
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", raw_mac)
        if len(cleaned) == 12:
            return ":".join(cleaned[i : i + 2].upper() for i in range(0, 12, 2))
        return raw_mac.upper()

    return ""


async def probe_credentials(
    ip: str,
    port: int,
    client: Any,
    v3_credentials: List[SnmpCredentialProfile],
    v2c_communities: List[str],
    timeout: float = 1.0,
    retries: int = 1,
) -> Optional[Tuple[SnmpCredentialProfile, Dict[str, Any]]]:
    """Executes multi-credential waterfall probing against target IP.

    Waterfall order:
    1. SNMPv3 USM profiles (strongest authPriv down to noAuthNoPriv).
    2. SNMPv2c communities ('public', 'private', etc.).
    """
    # 1. Test SNMPv3 Credentials
    for v3_prof in v3_credentials:
        try:
            varbinds = await client.get(
                ip=ip,
                port=port,
                oids=[SYS_OBJECT_ID],
                version="v3",
                v3_user=v3_prof.v3_user,
                v3_auth_proto=v3_prof.v3_auth_proto,
                v3_auth_key=v3_prof.v3_auth_key,
                v3_priv_proto=v3_prof.v3_priv_proto,
                v3_priv_key=v3_prof.v3_priv_key,
                v3_context_name=v3_prof.v3_context_name,
                timeout=timeout,
                retries=retries,
            )
            if varbinds and SYS_OBJECT_ID in varbinds:
                return v3_prof, dict(varbinds.items())
        except Exception:
            continue

    # 2. Test SNMPv2c Communities
    for comm in v2c_communities:
        try:
            varbinds = await client.get(
                ip=ip,
                port=port,
                oids=[SYS_OBJECT_ID],
                version="v2c",
                community=comm,
                timeout=timeout,
                retries=retries,
            )
            if varbinds and SYS_OBJECT_ID in varbinds:
                profile = SnmpCredentialProfile(version="v2c", community=comm)
                return profile, dict(varbinds.items())
        except Exception:
            continue

    return None


async def discover_interfaces(
    ip: str,
    port: int,
    cred: SnmpCredentialProfile,
    client: Any,
) -> List[DiscoveredInterface]:
    """Walks RFC 2863 IF-MIB interface tables to enumerate network interfaces."""
    interfaces_map: Dict[int, DiscoveredInterface] = {}

    common_kwargs: Dict[str, Any] = {
        "ip": ip,
        "port": port,
        "version": cred.version,
    }
    if cred.version == "v2c":
        common_kwargs["community"] = cred.community
    else:
        common_kwargs.update({
            "v3_user": cred.v3_user,
            "v3_auth_proto": cred.v3_auth_proto,
            "v3_auth_key": cred.v3_auth_key,
            "v3_priv_proto": cred.v3_priv_proto,
            "v3_priv_key": cred.v3_priv_key,
            "v3_context_name": cred.v3_context_name,
        })

    try:
        # Walk ifTable (32-bit legacy)
        if_rows = await client.walk(root_oid="1.3.6.1.2.1.2.2.1", **common_kwargs)
        for oid, val in if_rows:
            parts = oid.split(".")
            if len(parts) >= 11:
                col = parts[9]
                try:
                    idx = int(parts[10])
                except ValueError:
                    continue

                if idx not in interfaces_map:
                    interfaces_map[idx] = DiscoveredInterface(if_index=idx)
                iface = interfaces_map[idx]

                if col == "2":      # ifDescr
                    iface.if_descr = str(val or "")
                elif col == "3":    # ifType
                    iface.if_type = int(val or 6)
                elif col == "5":    # ifSpeed
                    iface.if_speed = int(val or 0)
                elif col == "6":    # ifPhysAddress
                    iface.if_mac = format_mac_address(val)
                elif col == "7":    # ifAdminStatus
                    iface.if_admin_status = int(val or 1)
                elif col == "8":    # ifOperStatus
                    iface.if_oper_status = int(val or 1)
    except Exception as exc:
        logger.warning("Error walking ifTable on %s: %s", ip, exc)

    try:
        # Walk ifXTable (64-bit HC names and high-speed indicators)
        ifx_rows = await client.walk(root_oid="1.3.6.1.2.1.31.1.1.1", **common_kwargs)
        for oid, val in ifx_rows:
            parts = oid.split(".")
            if len(parts) >= 12:
                col = parts[10]
                try:
                    idx = int(parts[11])
                except ValueError:
                    continue

                if idx in interfaces_map:
                    iface = interfaces_map[idx]
                    if col == "1":    # ifName
                        iface.if_name = str(val or "")
                    elif col == "15":  # ifHighSpeed (in Mbps)
                        high_speed = int(val or 0)
                        if high_speed > 0:
                            iface.if_speed = high_speed * 1_000_000
    except Exception as exc:
        logger.debug("Device %s did not respond to ifXTable: %s", ip, exc)

    # Ensure if_name fallbacks to if_descr
    for iface in interfaces_map.values():
        if not iface.if_name:
            iface.if_name = iface.if_descr or f"eth{iface.if_index}"

    return sorted(interfaces_map.values(), key=lambda i: i.if_index)


async def discover_single_device(
    ip: str,
    config: DiscoveryScanConfig,
    client: Any,
) -> Optional[DiscoveredDevice]:
    """Probes, fingerprints, and walks a single IP address."""
    probe_res = await probe_credentials(
        ip=ip,
        port=config.port,
        client=client,
        v3_credentials=config.v3_credentials,
        v2c_communities=config.v2c_communities,
        timeout=config.timeout,
        retries=config.retries,
    )
    if probe_res is None:
        return None

    cred, initial_varbinds = probe_res
    sys_object_id = str(initial_varbinds.get(SYS_OBJECT_ID, ""))

    sys_descr = ""
    sys_name = ""
    sys_uptime = 0

    try:
        common_kwargs: Dict[str, Any] = {
            "ip": ip,
            "port": config.port,
            "oids": [SYS_DESCR, SYS_NAME, SYS_UPTIME],
            "version": cred.version,
            "timeout": config.timeout,
            "retries": config.retries,
        }
        if cred.version == "v2c":
            common_kwargs["community"] = cred.community
        else:
            common_kwargs.update({
                "v3_user": cred.v3_user,
                "v3_auth_proto": cred.v3_auth_proto,
                "v3_auth_key": cred.v3_auth_key,
                "v3_priv_proto": cred.v3_priv_proto,
                "v3_priv_key": cred.v3_priv_key,
                "v3_context_name": cred.v3_context_name,
            })

        sys_varbinds = await client.get(**common_kwargs)
        if sys_varbinds:
            sys_descr = str(sys_varbinds.get(SYS_DESCR, ""))
            sys_name = str(sys_varbinds.get(SYS_NAME, ""))
            sys_uptime = int(sys_varbinds.get(SYS_UPTIME, 0))
    except Exception as exc:
        logger.warning("Failed to retrieve full system group on %s: %s", ip, exc)

    vendor = fingerprint_vendor(sys_object_id, sys_descr)

    interfaces: List[DiscoveredInterface] = []
    if config.walk_interfaces:
        interfaces = await discover_interfaces(ip, config.port, cred, client)

    return DiscoveredDevice(
        ip=ip,
        port=config.port,
        version=cred.version,
        community=cred.community,
        v3_user=cred.v3_user,
        v3_auth_proto=cred.v3_auth_proto,
        v3_auth_key=cred.v3_auth_key,
        v3_priv_proto=cred.v3_priv_proto,
        v3_priv_key=cred.v3_priv_key,
        vendor=vendor,
        sys_name=sys_name,
        sys_descr=sys_descr,
        sys_object_id=sys_object_id,
        sys_uptime=sys_uptime,
        interfaces=interfaces,
    )


def _notify_new_device(conn: sqlite3.Connection, device: DiscoveredDevice) -> None:
    """Panel bildirim gelen kutusuna 'yeni cihaz' satırı yazar (tablo panelce oluşturulur; yoksa sessizce atlanır)."""
    try:
        import time
        key = f"snmp:{device.ip}"
        if conn.execute("SELECT 1 FROM notifications WHERE dedupe_key = ?", (key,)).fetchone():
            return
        conn.execute(
            "INSERT INTO notifications (tenant_id, page_key, target_user, ntype, severity, title, body, link, dedupe_key, created_ts) "
            "VALUES (1, 'snmp', '', 'new_device', 'warning', ?, ?, '/snmp', ?, ?)",
            ("SNMP ile yeni cihaz bulundu", f"{device.ip} {device.sys_name or ''}".strip(), key, time.time()))
    except sqlite3.Error:
        pass


def persist_discovered_device(conn: sqlite3.Connection, device: DiscoveredDevice) -> int:
    """Inserts or updates discovered device and interfaces into SQLite WAL tables."""
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM snmp_devices WHERE ip = ?", (device.ip,))
    is_new = cursor.fetchone() is None
    cursor.execute(
        """
        INSERT INTO snmp_devices (
            ip, port, version, community, v3_user, v3_auth_proto, v3_auth_key,
            v3_priv_proto, v3_priv_key, vendor, sys_name, sys_descr, status, last_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ONLINE', CURRENT_TIMESTAMP)
        ON CONFLICT(ip) DO UPDATE SET
            port = excluded.port,
            version = excluded.version,
            community = excluded.community,
            v3_user = excluded.v3_user,
            v3_auth_proto = excluded.v3_auth_proto,
            v3_auth_key = excluded.v3_auth_key,
            v3_priv_proto = excluded.v3_priv_proto,
            v3_priv_key = excluded.v3_priv_key,
            vendor = excluded.vendor,
            sys_name = excluded.sys_name,
            sys_descr = excluded.sys_descr,
            status = 'ONLINE',
            last_seen = CURRENT_TIMESTAMP
        """,
        (
            device.ip,
            device.port,
            device.version,
            device.community,
            device.v3_user,
            device.v3_auth_proto,
            device.v3_auth_key,
            device.v3_priv_proto,
            device.v3_priv_key,
            device.vendor,
            device.sys_name,
            device.sys_descr,
        ),
    )

    cursor.execute("SELECT id FROM snmp_devices WHERE ip = ?", (device.ip,))
    row = cursor.fetchone()
    device_id = row[0] if row else cursor.lastrowid
    if is_new:
        _notify_new_device(conn, device)

    # Persist interfaces
    for iface in device.interfaces:
        cursor.execute(
            """
            INSERT INTO snmp_interfaces (
                device_id, if_index, if_descr, if_name, if_type, if_speed,
                if_admin_status, if_oper_status, if_mac
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id, if_index) DO UPDATE SET
                if_descr = excluded.if_descr,
                if_name = excluded.if_name,
                if_type = excluded.if_type,
                if_speed = excluded.if_speed,
                if_admin_status = excluded.if_admin_status,
                if_oper_status = excluded.if_oper_status,
                if_mac = excluded.if_mac
            """,
            (
                device_id,
                iface.if_index,
                iface.if_descr,
                iface.if_name,
                iface.if_type,
                iface.if_speed,
                iface.if_admin_status,
                iface.if_oper_status,
                iface.if_mac,
            ),
        )

    return device_id


async def scan_network(config: DiscoveryScanConfig, client: Any = None) -> DiscoveryScanResult:
    """Executes high-speed parallel auto-discovery scan across configured target IPs."""
    start_time = time.time()
    target_ips = parse_targets(config.targets, allow_loopback=config.allow_loopback)
    if not target_ips:
        return DiscoveryScanResult(duration_seconds=0.0)

    if client is None:
        from nms.snmp.engine import SnmpClient
        client = SnmpClient()

    semaphore = asyncio.Semaphore(config.concurrency)
    discovered: List[DiscoveredDevice] = []
    failed_ips: int = 0
    lock = asyncio.Lock()

    async def _worker(ip: str) -> None:
        nonlocal failed_ips
        async with semaphore:
            try:
                res = await discover_single_device(ip, config, client)
                if res is not None:
                    async with lock:
                        discovered.append(res)
                else:
                    async with lock:
                        failed_ips += 1
            except Exception as err:
                logger.debug("Exception scanning %s: %s", ip, err)
                async with lock:
                    failed_ips += 1

    tasks = [_worker(ip) for ip in target_ips]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Database persistence
    if config.persist_db and discovered:
        conn = get_db_connection(config.db_path)
        try:
            with conn:
                for dev in discovered:
                    persist_discovered_device(conn, dev)
        finally:
            conn.close()

    duration = time.time() - start_time
    return DiscoveryScanResult(
        scanned_ips=len(target_ips),
        discovered_devices=discovered,
        failed_ips=failed_ips,
        duration_seconds=round(duration, 2),
    )
