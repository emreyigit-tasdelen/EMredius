# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Standard RFC 1213 MIB-II, RFC 2863 IF-MIB (32-bit and 64-bit HC),
and 6-Vendor Enterprise OID Catalogs and Normalized Health Metric Adapters.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("snmp.mibs")

# =====================================================================
# RFC 1213 MIB-II System Group
# =====================================================================

RFC1213_SYS_GROUP = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysServices": "1.3.6.1.2.1.1.7.0",
}

# =====================================================================
# RFC 2863 IF-MIB Column Base OIDs
# =====================================================================

# Legacy 32-bit ifTable column base OIDs:
IF_TABLE_COLUMNS = {
    "ifIndex": "1.3.6.1.2.1.2.2.1.1",
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifType": "1.3.6.1.2.1.2.2.1.3",
    "ifMtu": "1.3.6.1.2.1.2.2.1.4",
    "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
    "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
    "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifLastChange": "1.3.6.1.2.1.2.2.1.9",
    "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
    "ifInUcastPkts": "1.3.6.1.2.1.2.2.1.11",
    "ifInDiscards": "1.3.6.1.2.1.2.2.1.13",
    "ifInErrors": "1.3.6.1.2.1.2.2.1.14",
    "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
    "ifOutUcastPkts": "1.3.6.1.2.1.2.2.1.17",
    "ifOutDiscards": "1.3.6.1.2.1.2.2.1.19",
    "ifOutErrors": "1.3.6.1.2.1.2.2.1.20",
}

# 64-bit High Capacity ifXTable column base OIDs:
IF_X_TABLE_COLUMNS = {
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifInMulticastPkts": "1.3.6.1.2.1.31.1.1.1.2",
    "ifInBroadcastPkts": "1.3.6.1.2.1.31.1.1.1.3",
    "ifOutMulticastPkts": "1.3.6.1.2.1.31.1.1.1.4",
    "ifOutBroadcastPkts": "1.3.6.1.2.1.31.1.1.1.5",
    "ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6",
    "ifHCInUcastPkts": "1.3.6.1.2.1.31.1.1.1.7",
    "ifHCInMulticastPkts": "1.3.6.1.2.1.31.1.1.1.8",
    "ifHCInBroadcastPkts": "1.3.6.1.2.1.31.1.1.1.9",
    "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
    "ifHCOutUcastPkts": "1.3.6.1.2.1.31.1.1.1.11",
    "ifHCOutMulticastPkts": "1.3.6.1.2.1.31.1.1.1.12",
    "ifHCOutBroadcastPkts": "1.3.6.1.2.1.31.1.1.1.13",
    "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
    "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
}

# =====================================================================
# 6-Vendor Enterprise OID Catalogs
# =====================================================================

VENDOR_OIDS: Dict[str, Dict[str, str]] = {
    "cisco": {
        "cpu_5min": "1.3.6.1.4.1.9.9.109.1.1.1.1.8",        # cpmCPUTotal5minRev
        "cpu_fallback": "1.3.6.1.4.1.9.2.1.58.0",           # avgBusy5
        "mem_pool_used": "1.3.6.1.4.1.9.9.221.1.1.1.1.7",    # cempMemPoolUsed
        "mem_pool_free": "1.3.6.1.4.1.9.9.221.1.1.1.1.8",    # cempMemPoolFree
        "temp_sensor": "1.3.6.1.4.1.9.9.13.1.3.1.3",        # ciscoEnvMonTemperatureStatusValue
    },
    "mikrotik": {
        "cpu_load": "1.3.6.1.2.1.25.3.3.1.2",               # hrProcessorLoad (per core)
        "cpu_single": "1.3.6.1.4.1.14988.1.1.3.14.0",       # mtxHlCpuUsage
        "mem_total": "1.3.6.1.4.1.14988.1.1.1.1.0",         # mtxrTotalMemory
        "mem_size": "1.3.6.1.2.1.25.2.3.1.5",               # hrStorageSize
        "mem_used": "1.3.6.1.2.1.25.2.3.1.6",               # hrStorageUsed
        "temp_board": "1.3.6.1.4.1.14988.1.1.3.10.0",       # mtxHlTemperature
        "temp_cpu": "1.3.6.1.4.1.14988.1.1.3.11.0",         # mtxHlProcessorTemperature
        "voltage": "1.3.6.1.4.1.14988.1.1.3.8.0",           # mtxHlVoltage (0.1V units)
    },
    "huawei": {
        "cpu_usage": "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5",   # hwEntityCpuUsage
        "mem_usage": "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7",   # hwEntityMemUsage
        "temp": "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11",       # hwEntityTemperature
    },
    "juniper": {
        "cpu": "1.3.6.1.4.1.2636.3.1.13.1.8",               # jnxOperatingCPU
        "mem_buffer": "1.3.6.1.4.1.2636.3.1.13.1.11",       # jnxOperatingBuffer
        "temp": "1.3.6.1.4.1.2636.3.1.13.1.12",             # jnxOperatingTemp
    },
    "fortinet": {
        "cpu": "1.3.6.1.4.1.12356.101.4.1.3.0",             # fgSysCpuUsage
        "mem": "1.3.6.1.4.1.12356.101.4.1.4.0",             # fgSysMemUsage
        "sessions": "1.3.6.1.4.1.12356.101.4.1.8.0",        # fgSysSesCount
        "session_rate": "1.3.6.1.4.1.12356.101.4.1.11.0",    # fgSysSesRate
    },
    "hp_aruba": {
        # HPE Comware:
        "hh3c_cpu": "1.3.6.1.4.1.25506.2.6.1.1.1.1.6",      # hh3cEntityExtCpuUsage
        "hh3c_mem": "1.3.6.1.4.1.25506.2.6.1.1.1.1.8",      # hh3cEntityExtMemUsage
        "hh3c_temp": "1.3.6.1.4.1.25506.2.6.1.1.1.1.12",    # hh3cEntityExtTemperature
        # HP ProCurve / ArubaOS-Switch:
        "hp_cpu": "1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0",      # hpGlobalCpuTotal
        "hp_mem_total": "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5.1",
        "hp_mem_alloc": "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7.1",
    },
}


# =====================================================================
# Normalized Health Metric Model & Adapters
# =====================================================================

@dataclass
class DeviceHealthMetrics:
    """Normalized hardware health indicators across all vendors."""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    temperature_c: Optional[float] = None
    extra_metrics: Dict[str, Any] = field(default_factory=dict)


def _find_val(varbinds: Dict[str, Any], prefix: str, default: Any = None) -> Any:
    """Finds first matching value where varbind OID starts with prefix."""
    clean_pfx = prefix.lstrip(".")
    for oid, val in varbinds.items():
        clean_oid = oid.lstrip(".")
        if clean_oid == clean_pfx or clean_oid.startswith(clean_pfx + "."):
            return val
    return default


def _find_all_vals(varbinds: Dict[str, Any], prefix: str) -> List[Any]:
    """Finds all matching values where varbind OID starts with prefix."""
    clean_pfx = prefix.lstrip(".")
    results = []
    for oid, val in varbinds.items():
        clean_oid = oid.lstrip(".")
        if clean_oid == clean_pfx or clean_oid.startswith(clean_pfx + "."):
            results.append(val)
    return results


class VendorAdapter(ABC):
    """Abstract Base Class for Multi-Vendor Hardware Health Metric Adapters."""

    @abstractmethod
    def get_health_oids(self) -> List[str]:
        """Returns list of OIDs or prefixes to poll for health metrics."""
        ...

    @abstractmethod
    def parse_health_metrics(self, varbinds: Dict[str, Any]) -> DeviceHealthMetrics:
        """Parses raw SNMP varbind dict into normalized DeviceHealthMetrics."""
        ...


class CiscoAdapter(VendorAdapter):
    """Cisco Systems (IOS, IOS-XE, NX-OS) Health Metric Adapter."""

    def get_health_oids(self) -> List[str]:
        return [
            VENDOR_OIDS["cisco"]["cpu_5min"] + ".1",
            VENDOR_OIDS["cisco"]["cpu_fallback"],
            VENDOR_OIDS["cisco"]["mem_pool_used"] + ".1.1",
            VENDOR_OIDS["cisco"]["mem_pool_free"] + ".1.1",
            VENDOR_OIDS["cisco"]["temp_sensor"] + ".1",
        ]

    def parse_health_metrics(self, varbinds: Dict[str, Any]) -> DeviceHealthMetrics:
        # CPU
        cpu_val = _find_val(varbinds, VENDOR_OIDS["cisco"]["cpu_5min"])
        if cpu_val is None:
            cpu_val = _find_val(varbinds, VENDOR_OIDS["cisco"]["cpu_fallback"], 0.0)
        cpu_pct = float(cpu_val or 0.0)

        # Memory (Used & Free bytes)
        used = float(_find_val(varbinds, VENDOR_OIDS["cisco"]["mem_pool_used"], 0.0) or 0.0)
        free = float(_find_val(varbinds, VENDOR_OIDS["cisco"]["mem_pool_free"], 0.0) or 0.0)
        mem_pct = round((used / (used + free)) * 100.0, 2) if (used + free) > 0 else 0.0

        # Temperature
        temp_val = _find_val(varbinds, VENDOR_OIDS["cisco"]["temp_sensor"])
        temp_c = float(temp_val) if temp_val is not None else None

        return DeviceHealthMetrics(
            cpu_percent=cpu_pct,
            memory_percent=mem_pct,
            temperature_c=temp_c,
        )


class MikrotikAdapter(VendorAdapter):
    """MikroTik RouterOS (v6 & v7) Health Metric Adapter."""

    def get_health_oids(self) -> List[str]:
        return [
            VENDOR_OIDS["mikrotik"]["cpu_single"],
            VENDOR_OIDS["mikrotik"]["cpu_load"],
            VENDOR_OIDS["mikrotik"]["mem_total"],
            VENDOR_OIDS["mikrotik"]["mem_size"],
            VENDOR_OIDS["mikrotik"]["mem_used"],
            VENDOR_OIDS["mikrotik"]["temp_board"],
            VENDOR_OIDS["mikrotik"]["temp_cpu"],
            VENDOR_OIDS["mikrotik"]["voltage"],
        ]

    def parse_health_metrics(self, varbinds: Dict[str, Any]) -> DeviceHealthMetrics:
        # CPU: single gauge or average of per-core loads
        cpu_val = _find_val(varbinds, VENDOR_OIDS["mikrotik"]["cpu_single"])
        if cpu_val is not None:
            cpu_pct = float(cpu_val)
        else:
            cores = _find_all_vals(varbinds, VENDOR_OIDS["mikrotik"]["cpu_load"])
            cpu_pct = round(sum(float(c) for c in cores) / len(cores), 2) if cores else 0.0

        # Memory: hrStorage or total memory
        used_val = _find_val(varbinds, VENDOR_OIDS["mikrotik"]["mem_used"])
        size_val = _find_val(varbinds, VENDOR_OIDS["mikrotik"]["mem_size"])
        if used_val is not None and size_val is not None and float(size_val) > 0:
            mem_pct = round((float(used_val) / float(size_val)) * 100.0, 2)
        else:
            mem_pct = 0.0

        # Temperature: CPU or board (in °C, sometimes deci-Celsius if > 100)
        temp_val = _find_val(varbinds, VENDOR_OIDS["mikrotik"]["temp_cpu"])
        if temp_val is None:
            temp_val = _find_val(varbinds, VENDOR_OIDS["mikrotik"]["temp_board"])
        temp_c = None
        if temp_val is not None:
            t = float(temp_val)
            temp_c = (t / 10.0) if t > 100.0 else t

        extra = {}
        volt = _find_val(varbinds, VENDOR_OIDS["mikrotik"]["voltage"])
        if volt is not None:
            extra["voltage_v"] = round(float(volt) / 10.0, 1)

        return DeviceHealthMetrics(
            cpu_percent=cpu_pct,
            memory_percent=mem_pct,
            temperature_c=temp_c,
            extra_metrics=extra,
        )


class HuaweiAdapter(VendorAdapter):
    """Huawei VRP Health Metric Adapter."""

    def get_health_oids(self) -> List[str]:
        return [
            VENDOR_OIDS["huawei"]["cpu_usage"] + ".1",
            VENDOR_OIDS["huawei"]["mem_usage"] + ".1",
            VENDOR_OIDS["huawei"]["temp"] + ".1",
        ]

    def parse_health_metrics(self, varbinds: Dict[str, Any]) -> DeviceHealthMetrics:
        cpu_val = _find_val(varbinds, VENDOR_OIDS["huawei"]["cpu_usage"], 0.0)
        mem_val = _find_val(varbinds, VENDOR_OIDS["huawei"]["mem_usage"], 0.0)
        temp_val = _find_val(varbinds, VENDOR_OIDS["huawei"]["temp"])

        temp_c = float(temp_val) if temp_val is not None else None

        return DeviceHealthMetrics(
            cpu_percent=float(cpu_val or 0.0),
            memory_percent=float(mem_val or 0.0),
            temperature_c=temp_c,
        )


class JuniperAdapter(VendorAdapter):
    """Juniper JunOS Health Metric Adapter."""

    def get_health_oids(self) -> List[str]:
        return [
            VENDOR_OIDS["juniper"]["cpu"] + ".9.1",
            VENDOR_OIDS["juniper"]["mem_buffer"] + ".9.1",
            VENDOR_OIDS["juniper"]["temp"] + ".9.1",
        ]

    def parse_health_metrics(self, varbinds: Dict[str, Any]) -> DeviceHealthMetrics:
        cpu_val = _find_val(varbinds, VENDOR_OIDS["juniper"]["cpu"], 0.0)
        mem_val = _find_val(varbinds, VENDOR_OIDS["juniper"]["mem_buffer"], 0.0)
        temp_val = _find_val(varbinds, VENDOR_OIDS["juniper"]["temp"])

        temp_c = float(temp_val) if temp_val is not None else None

        return DeviceHealthMetrics(
            cpu_percent=float(cpu_val or 0.0),
            memory_percent=float(mem_val or 0.0),
            temperature_c=temp_c,
        )


class FortinetAdapter(VendorAdapter):
    """Fortinet FortiGate FortiOS Health Metric Adapter."""

    def get_health_oids(self) -> List[str]:
        return [
            VENDOR_OIDS["fortinet"]["cpu"],
            VENDOR_OIDS["fortinet"]["mem"],
            VENDOR_OIDS["fortinet"]["sessions"],
            VENDOR_OIDS["fortinet"]["session_rate"],
        ]

    def parse_health_metrics(self, varbinds: Dict[str, Any]) -> DeviceHealthMetrics:
        cpu_val = _find_val(varbinds, VENDOR_OIDS["fortinet"]["cpu"], 0.0)
        mem_val = _find_val(varbinds, VENDOR_OIDS["fortinet"]["mem"], 0.0)
        ses_val = _find_val(varbinds, VENDOR_OIDS["fortinet"]["sessions"])

        extra = {}
        if ses_val is not None:
            extra["sessions"] = int(ses_val)
        ses_rate = _find_val(varbinds, VENDOR_OIDS["fortinet"]["session_rate"])
        if ses_rate is not None:
            extra["session_rate"] = int(ses_rate)

        return DeviceHealthMetrics(
            cpu_percent=float(cpu_val or 0.0),
            memory_percent=float(mem_val or 0.0),
            temperature_c=None,
            extra_metrics=extra,
        )


class HpArubaAdapter(VendorAdapter):
    """HPE Comware and HP ProCurve / ArubaOS Health Metric Adapter."""

    def get_health_oids(self) -> List[str]:
        return [
            VENDOR_OIDS["hp_aruba"]["hh3c_cpu"] + ".1",
            VENDOR_OIDS["hp_aruba"]["hh3c_mem"] + ".1",
            VENDOR_OIDS["hp_aruba"]["hh3c_temp"] + ".1",
            VENDOR_OIDS["hp_aruba"]["hp_cpu"],
            VENDOR_OIDS["hp_aruba"]["hp_mem_total"],
            VENDOR_OIDS["hp_aruba"]["hp_mem_alloc"],
        ]

    def parse_health_metrics(self, varbinds: Dict[str, Any]) -> DeviceHealthMetrics:
        # Comware OIDs first
        cpu_val = _find_val(varbinds, VENDOR_OIDS["hp_aruba"]["hh3c_cpu"])
        mem_val = _find_val(varbinds, VENDOR_OIDS["hp_aruba"]["hh3c_mem"])
        temp_val = _find_val(varbinds, VENDOR_OIDS["hp_aruba"]["hh3c_temp"])

        # ProCurve fallback
        if cpu_val is None:
            cpu_val = _find_val(varbinds, VENDOR_OIDS["hp_aruba"]["hp_cpu"], 0.0)
        if mem_val is None:
            total = float(_find_val(varbinds, VENDOR_OIDS["hp_aruba"]["hp_mem_total"], 0.0) or 0.0)
            alloc = float(_find_val(varbinds, VENDOR_OIDS["hp_aruba"]["hp_mem_alloc"], 0.0) or 0.0)
            mem_pct = round((alloc / total) * 100.0, 2) if total > 0 else 0.0
        else:
            mem_pct = float(mem_val or 0.0)

        temp_c = float(temp_val) if temp_val is not None else None

        return DeviceHealthMetrics(
            cpu_percent=float(cpu_val or 0.0),
            memory_percent=mem_pct,
            temperature_c=temp_c,
        )


class GenericAdapter(VendorAdapter):
    """Generic RFC 2790 Host Resources MIB Health Metric Adapter."""

    def get_health_oids(self) -> List[str]:
        return [
            "1.3.6.1.2.1.25.3.3.1.2.1",  # hrProcessorLoad
        ]

    def parse_health_metrics(self, varbinds: Dict[str, Any]) -> DeviceHealthMetrics:
        cpu_val = _find_val(varbinds, "1.3.6.1.2.1.25.3.3.1.2", 0.0)
        return DeviceHealthMetrics(
            cpu_percent=float(cpu_val or 0.0),
            memory_percent=0.0,
            temperature_c=None,
        )


_ADAPTER_REGISTRY: Dict[str, VendorAdapter] = {
    "cisco": CiscoAdapter(),
    "mikrotik": MikrotikAdapter(),
    "huawei": HuaweiAdapter(),
    "juniper": JuniperAdapter(),
    "fortinet": FortinetAdapter(),
    "hp_aruba": HpArubaAdapter(),
    "generic": GenericAdapter(),
}


def get_vendor_adapter(vendor: str) -> VendorAdapter:
    """Returns the VendorAdapter corresponding to vendor name string."""
    norm = vendor.strip().lower().replace(" ", "_").replace("-", "_")
    return _ADAPTER_REGISTRY.get(norm, _ADAPTER_REGISTRY["generic"])
