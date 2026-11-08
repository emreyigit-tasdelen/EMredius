# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Milestone M2 Universal Multi-Vendor SNMPv2c/v3 Engine Package."""

from nms.snmp.alarms import AlarmEngine, FlapRecord
from nms.snmp.discovery import (
    DiscoveredDevice,
    DiscoveredInterface,
    DiscoveryScanConfig,
    DiscoveryScanResult,
    SnmpCredentialProfile,
    discover_interfaces,
    discover_single_device,
    fingerprint_vendor,
    format_mac_address,
    parse_targets,
    probe_credentials,
    scan_network,
)
from nms.snmp.engine import (
    Asn1Codec,
    Asn1Tag,
    EngineCache,
    Pdu,
    SnmpClient,
    SnmpEngine,
    SnmpMessageCodec,
    SnmpResponse,
    SnmpV3Credentials,
    UsmCrypto,
    VarBind,
)
from nms.snmp.mibs import (
    IF_TABLE_COLUMNS,
    IF_X_TABLE_COLUMNS,
    RFC1213_SYS_GROUP,
    VENDOR_OIDS,
    CiscoAdapter,
    DeviceHealthMetrics,
    FortinetAdapter,
    GenericAdapter,
    HpArubaAdapter,
    HuaweiAdapter,
    JuniperAdapter,
    MikrotikAdapter,
    VendorAdapter,
    get_vendor_adapter,
)
from nms.snmp.poller import PollerDaemonMetrics, SnmpPollerDaemon
from nms.snmp.telemetry import (
    WRAP_32,
    WRAP_64,
    InterfaceRates,
    InterfaceSample,
    TelemetryEngine,
    calculate_counter_delta,
)
from nms.snmp.webhooks import (
    SlackDispatcher,
    TelegramDispatcher,
    WebhookManager,
    async_http_post,
)

__all__ = [
    # Engine & ASN.1
    "Asn1Codec",
    "Asn1Tag",
    "VarBind",
    "Pdu",
    "SnmpResponse",
    "SnmpV3Credentials",
    "SnmpEngine",
    "SnmpClient",
    "UsmCrypto",
    "EngineCache",
    "SnmpMessageCodec",
    # MIBs & Adapters
    "RFC1213_SYS_GROUP",
    "IF_TABLE_COLUMNS",
    "IF_X_TABLE_COLUMNS",
    "VENDOR_OIDS",
    "DeviceHealthMetrics",
    "VendorAdapter",
    "CiscoAdapter",
    "MikrotikAdapter",
    "HuaweiAdapter",
    "JuniperAdapter",
    "FortinetAdapter",
    "HpArubaAdapter",
    "GenericAdapter",
    "get_vendor_adapter",
    # Discovery
    "parse_targets",
    "fingerprint_vendor",
    "format_mac_address",
    "probe_credentials",
    "discover_interfaces",
    "discover_single_device",
    "scan_network",
    "DiscoveryScanConfig",
    "DiscoveryScanResult",
    "DiscoveredDevice",
    "DiscoveredInterface",
    "SnmpCredentialProfile",
    # Telemetry
    "InterfaceSample",
    "InterfaceRates",
    "calculate_counter_delta",
    "TelemetryEngine",
    "WRAP_32",
    "WRAP_64",
    # Alarms
    "FlapRecord",
    "AlarmEngine",
    # Webhooks
    "async_http_post",
    "TelegramDispatcher",
    "SlackDispatcher",
    "WebhookManager",
    # Poller Daemon
    "SnmpPollerDaemon",
    "PollerDaemonMetrics",
]
