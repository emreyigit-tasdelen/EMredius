# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""NAS clients (FreeRADIUS `nas` table): validation, listing with live ping, add / delete."""
import ipaddress
import logging
import re
from concurrent.futures import ThreadPoolExecutor

from ..core import tenant as tn
from ..core import get_db, is_valid_ip, ping_host, safe_int
from .radius_users import ServiceError

log = logging.getLogger(__name__)

# Allowed NAS vendor types (value stored in nas.type, label shown in the UI)
NAS_TYPE_CHOICES = [
    ("other", "Diğer / Standart"),
    ("cisco", "Cisco"),
    ("mikrotik", "Mikrotik"),
    ("juniper", "Juniper"),
    ("huawei", "Huawei"),
    ("aruba", "Aruba"),
    ("hp", "HP / HPE"),
    ("fortinet", "Fortinet"),
    ("ubiquiti", "Ubiquiti UniFi"),
    ("ruckus", "Ruckus"),
    ("paloalto", "Palo Alto"),
]
_NAS_TYPES = {k for k, _ in NAS_TYPE_CHOICES}
_NAS_TYPE_ALIASES = {"unifi": "ubiquiti"}  # value used by the old form
_NAS_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,128}$")
_NAS_SHORTNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_NAS_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_NAS_PING_MAX_WORKERS = 32


def normalize_nasname(raw):
    """Validates a NAS address (IP, CIDR block or hostname). Returns the normalized form or None."""
    v = (raw or "").strip()
    if not v or len(v) > 128:
        return None
    if "/" in v:
        if not is_valid_ip(v, allow_cidr=True):
            return None
        return str(ipaddress.ip_network(v, strict=False))
    if is_valid_ip(v):
        return str(ipaddress.ip_address(v))
    if not _NAS_HOST_RE.fullmatch(v):
        return None
    # dotted-numeric strings that are not valid IPs (e.g. 999.1.1.1), leading '-' / '.', empty labels
    if re.fullmatch(r"[0-9.]+", v) or v.startswith(("-", ".")) or v.endswith("-") or ".." in v:
        return None
    return v.lower()


def ping_target(nasname):
    """Host to ping for a NAS row, or None for multi-address CIDR blocks (pinging the network address is meaningless)."""
    v = str(nasname or "").strip()
    if not v:
        return None
    if "/" in v:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            return None
        return str(net.network_address) if net.num_addresses == 1 else None
    return v


def ping_all(hosts):
    """Pings all hosts concurrently; total time is ~one ping instead of one ping per device."""
    hosts = sorted({h for h in hosts if h})
    if not hosts:
        return {}
    results = {}
    try:
        with ThreadPoolExecutor(max_workers=min(_NAS_PING_MAX_WORKERS, len(hosts))) as ex:
            for host, ok in zip(hosts, ex.map(ping_host, hosts)):
                results[host] = bool(ok)
    except Exception as e:
        log.warning("NAS ping error: %s", e)
    return results


def list_nas():
    """NAS rows with `reach` = 'up' / 'down' / 'block' (CIDR block, not pinged) and the CoA port."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, nasname, shortname, type, ports, secret, description FROM nas ORDER BY id DESC")
            nas_list = cur.fetchall()
    finally:
        conn.close()
    nas_list = tn.filter_owned("nas", nas_list, lambda n: n["nasname"])
    targets = {n["id"]: ping_target(n["nasname"]) for n in nas_list}
    results = ping_all(targets.values())
    for n in nas_list:
        target = targets.get(n["id"])
        n["reach"] = "block" if target is None else ("up" if results.get(target) else "down")
        n["coa_port"] = safe_int(n.get("ports"), 3799, 1, 65535)
        n["id"] = int(n["id"])
    return nas_list


def validate_nas(form):
    """form: mapping with shortname, nasname, secret, type, ports, description.
    Returns (errors, cleaned_dict)."""
    shortname = (form.get("shortname") or "").strip()
    secret = (form.get("secret") or "").strip()
    ntype = (form.get("type") or "other").strip().lower()
    ntype = _NAS_TYPE_ALIASES.get(ntype, ntype)
    ports_raw = (form.get("ports") or "").strip() or "3799"
    desc = _NAS_CTRL_RE.sub("", (form.get("description") or "")).strip()

    errors = []
    if not _NAS_SHORTNAME_RE.fullmatch(shortname):
        errors.append("Cihaz kısa adı 1-32 karakter olmalı ve yalnızca harf, rakam, nokta, alt çizgi ve tire içermelidir.")
    nasname = normalize_nasname(form.get("nasname"))
    if not nasname:
        errors.append("Geçersiz NAS adresi. Geçerli bir IP adresi, CIDR bloğu (örn. 192.168.1.0/24) veya host adı girin.")
    if not secret:
        errors.append("Shared secret zorunludur.")
    elif not (4 <= len(secret) <= 60):
        errors.append("Shared secret 4 ile 60 karakter arasında olmalıdır.")
    elif re.search(r"\s", secret) or _NAS_CTRL_RE.search(secret):
        errors.append("Shared secret boşluk veya kontrol karakteri içeremez.")
    if ntype not in _NAS_TYPES:
        errors.append("Geçersiz cihaz tipi seçildi.")
    port = safe_int(ports_raw, None, 1, 65535)
    if port is None:
        errors.append("CoA portu 1 ile 65535 arasında bir sayı olmalıdır.")
    if len(desc) > 200:
        errors.append("Açıklama en fazla 200 karakter olabilir.")
    return errors, {"shortname": shortname, "nasname": nasname, "secret": secret, "type": ntype, "port": port,
                    "description": desc}


def add_nas(d):
    """d = cleaned dict from validate_nas. Raises ServiceError (duplicate address / database error)."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, nasname FROM nas")
            for row in cur.fetchall():
                existing = (row.get("nasname") or "").strip()
                if existing == d["nasname"] or (normalize_nasname(existing) or existing.lower()) == d["nasname"]:
                    raise ServiceError(f"'{d['nasname']}' adresi zaten kayıtlı bir NAS cihazına ait.")
            cur.execute(
                "INSERT INTO nas (nasname, shortname, type, ports, secret, description) VALUES (%s, %s, %s, %s, %s, %s)",
                (d["nasname"], d["shortname"], d["type"], d["port"], d["secret"], d["description"]),
            )
        tn.set_owners("nas", [d["nasname"]])
    except ServiceError:
        raise
    except Exception as e:
        log.error("add_nas: %s", e)
        raise ServiceError("NAS cihazı kaydedilemedi (veritabanı hatası).") from e
    finally:
        conn.close()


def delete_nas(nas_id):
    """Deletes one NAS row; returns the deleted row (nasname, shortname) or None if not found."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, nasname, shortname FROM nas WHERE id = %s", (nas_id,))
            row = cur.fetchone()
            if row:
                cur.execute("DELETE FROM nas WHERE id = %s", (nas_id,))
            return row
    finally:
        conn.close()
