# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Input validation helpers and MAC vendor lookup."""
import ipaddress
import re

from . import oui

USERNAME_RE = re.compile(r"^[A-Za-z0-9._@:+\-]{1,64}$")
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
RATE_LIMIT_RE = re.compile(r"^[0-9A-Za-z/ .:\-]{1,64}$")
GROUPNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")


def is_valid_ip(value, allow_cidr=False):
    try:
        v = str(value).strip()
        if allow_cidr and "/" in v:
            ipaddress.ip_network(v, strict=False)
        else:
            ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def is_valid_vlan(value):
    v = str(value)
    return v.isascii() and v.isdigit() and 1 <= int(v) <= 4094


def safe_int(value, default=None, min_value=None, max_value=None):
    try:
        v = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    if min_value is not None and v < min_value:
        return default
    if max_value is not None and v > max_value:
        return default
    return v


def normalize_mac(raw):
    """Returns aa:bb:cc:dd:ee:ff or None."""
    cleaned = re.sub(r"[^a-fA-F0-9]", "", raw or "").lower()
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))


# OUI vendor dictionary (most common enterprise brands)
OUI_DATABASE = {
    "00:1A:2B": "Apple", "00:03:93": "Apple", "F0:18:98": "Apple", "AC:DE:48": "Apple", "3C:D9:2B": "Apple",
    "00:0C:29": "VMware", "00:50:56": "VMware", "00:15:5D": "Microsoft Hyper-V",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "AC:67:B2": "HP / Aruba", "00:26:08": "HP", "D8:80:39": "HP / Aruba",
    "00:1E:13": "Cisco", "00:24:D7": "Cisco", "70:69:79": "Cisco", "00:40:96": "Cisco",
    "00:0E:8E": "Mikrotik", "CC:2D:E0": "Mikrotik", "D4:CA:6D": "Mikrotik", "48:8F:5A": "Mikrotik",
    "F0:9F:C2": "Ubiquiti UniFi", "80:2A:A8": "Ubiquiti UniFi", "FC:EC:DA": "Ubiquiti UniFi", "24:5A:4C": "Ubiquiti UniFi",
    "A4:14:37": "Hikvision IP Kamera", "48:EA:63": "Hikvision IP Kamera", "C0:56:E3": "Hikvision IP Kamera",
    "E0:50:8B": "Dahua Kamera", "3C:EF:8C": "Dahua Kamera", "A0:BD:1D": "Dahua Kamera",
    "00:1A:11": "Dell", "00:21:70": "Dell", "B8:AC:6F": "Dell",
    "00:1B:21": "Intel", "00:1F:3B": "Intel", "00:13:02": "Intel",
    "24:0A:C4": "Espressif IoT", "30:AE:A4": "Espressif IoT", "A4:CF:12": "Espressif IoT",
    "EC:08:6B": "TP-Link", "50:C7:BF": "TP-Link", "70:4F:57": "TP-Link",
    "00:23:D7": "Samsung", "50:01:D9": "Samsung", "A0:0B:BA": "Samsung",
    "00:14:D1": "Trendsnet", "00:18:E7": "Cameo", "00:1D:7E": "Cisco-Linksys",
}


def lookup_mac_vendor(mac_str):
    """Curated OUI_DATABASE entries win, then the IEEE table (data/oui.tsv, see core/oui.py)."""
    if not mac_str:
        return "Bilinmeyen Cihaz"
    return oui.lookup(mac_str, OUI_DATABASE)

