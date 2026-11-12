# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Sender allow-list for the syslog collector. Empty list = everyone."""
from __future__ import annotations

import ipaddress
import re
import time

MAX_ENTRIES = 200


def parse(text):
    """'10.0.0.0/24, 192.168.1.5' -> [ip_network]; invalid input raises ValueError."""
    nets = [ipaddress.ip_network(p, strict=False) for p in re.split(r"[\s,;]+", text or "") if p]
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


class Acl:
    """Allow-list cache refreshed every `ttl` seconds."""

    def __init__(self, loader, ttl=10.0):
        self.loader, self.ttl, self._nets, self._at = loader, ttl, [], -1e9

    def allows(self, ip, now=None):
        now = time.monotonic() if now is None else now
        if now - self._at > self.ttl:
            self._at = now
            try:
                self._nets = self.loader()
            except Exception:  # noqa: BLE001
                pass
        return permits(self._nets, ip)
