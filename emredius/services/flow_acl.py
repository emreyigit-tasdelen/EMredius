# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Kaynak IP izin listesi (UDP akış toplayıcıları için). Liste boşsa herkese açık (eski davranış)."""
from __future__ import annotations

import ipaddress
import re
import time

TABLE = "CREATE TABLE IF NOT EXISTS flow_acl (k TEXT PRIMARY KEY, v TEXT NOT NULL DEFAULT '')"
KEY = "allowed_sources"
MAX_ENTRIES = 200


def parse(text):
    """'10.0.0.0/24, 192.168.1.5' -> [ip_network]; geçersiz girdi ValueError."""
    nets = []
    for part in re.split(r"[\s,;]+", text or ""):
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    if len(nets) > MAX_ENTRIES:
        raise ValueError("En fazla %d kayıt." % MAX_ENTRIES)
    return nets


def permits(nets, ip):
    if not nets:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets if n.version == addr.version)


def load(conn):
    try:
        row = conn.execute("SELECT v FROM flow_acl WHERE k=?", (KEY,)).fetchone()
        return parse(row[0] if row else "")
    except Exception:  # noqa: BLE001 (tablo yok / bozuk kayıt: kısıt yok sayılır)
        return []


class Acl:
    """Periyodik yenilenen izin listesi önbelleği."""

    def __init__(self, loader, ttl=10.0):
        self.loader, self.ttl, self._nets, self._at = loader, ttl, [], 0.0

    def allows(self, ip, now=None):
        now = time.monotonic() if now is None else now
        if now - self._at > self.ttl:
            self._at = now
            try:
                self._nets = self.loader()
            except Exception:  # noqa: BLE001
                pass
        return permits(self._nets, ip)