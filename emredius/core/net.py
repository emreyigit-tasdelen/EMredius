# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Client / server address helpers."""
import socket
import time

from flask import request

from .system import run_cmd
from .validators import is_valid_ip


def get_client_ip():
    """Real client IP. nginx's X-Real-IP is only trusted when the request arrives from the local reverse proxy;
    client-supplied X-Forwarded-For is never trusted."""
    try:
        remote = request.remote_addr or "127.0.0.1"
        if remote in ("127.0.0.1", "::1"):
            real = (request.headers.get("X-Real-IP") or "").strip()
            if real and is_valid_ip(real):
                return real
        return remote
    except Exception:
        return "127.0.0.1"


_server_ip_cache = {"t": 0.0, "v": None}
FALLBACK_SERVER_IP = "192.0.2.10"


def get_server_ip():
    """Active IPv4 address of this server (cached 5 minutes)."""
    now = time.time()
    if _server_ip_cache["v"] and now - _server_ip_cache["t"] < 300:
        return _server_ip_cache["v"]
    ip_found = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            ip_found = ip
    except Exception:
        pass
    if not ip_found:
        try:
            ip = socket.gethostbyname(socket.gethostname())
            if ip and not ip.startswith("127."):
                ip_found = ip
        except Exception:
            pass
    if ip_found:
        _server_ip_cache.update({"t": now, "v": ip_found})
        return ip_found
    return FALLBACK_SERVER_IP


def ping_host(host, port=1812, timeout=0.8):
    """ICMP reachability check (RADIUS is UDP, so a TCP probe to 1812 is meaningless)."""
    host = str(host or "").split("/")[0].strip()
    if not host or host.startswith("-"):
        return False
    rc, _, _ = run_cmd(["ping", "-c", "1", "-W", "1", host], timeout=2)
    return rc == 0
