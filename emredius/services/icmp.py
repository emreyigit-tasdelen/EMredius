# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""ICMP echo sweep over one socket: no `ping` process per address. Packets are sent back to back at a fixed rate
and replies are collected by a receiver thread as they arrive, so a dead address costs no waiting of its own;
the sweep waits `timeout` once, after the last packet.

Socket choice (Linux): an unprivileged ICMP datagram socket (needs the process group inside
net.ipv4.ping_group_range), else a raw socket (needs root / CAP_NET_RAW). open_socket() raises OSError when
neither is allowed; the caller then falls back to the `ping` command."""
import ipaddress
import os
import socket
import struct
import threading
import time

ECHO_REQUEST = {4: 8, 6: 128}
ECHO_REPLY = {4: 0, 6: 129}
_PROTO = {4: socket.IPPROTO_ICMP, 6: getattr(socket, "IPPROTO_ICMPV6", 58)}
_FAMILY = {4: socket.AF_INET, 6: socket.AF_INET6}
_PAYLOAD = struct.Struct("!8sd")  # scan token, send time (time.monotonic)
_HEADER = struct.Struct("!BBHHH")  # type, code, checksum, identifier, sequence


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_echo(version, ident, seq, payload):
    kind = ECHO_REQUEST[version]
    raw = _HEADER.pack(kind, 0, 0, ident, seq) + payload
    # ICMPv6 checksums include a pseudo-header and are always filled in by the kernel
    csum = checksum(raw) if version == 4 else 0
    return _HEADER.pack(kind, 0, csum, ident, seq) + payload


def parse_reply(version, data, raw_socket, token):
    """Returns the send time carried by an echo reply that belongs to this sweep, else None."""
    if version == 4 and raw_socket and data:
        data = data[(data[0] & 0x0F) * 4:]  # IPv4 raw sockets deliver the IP header too
    if len(data) < _HEADER.size + _PAYLOAD.size or data[0] != ECHO_REPLY[version]:
        return None
    got_token, sent = _PAYLOAD.unpack_from(data, _HEADER.size)
    return sent if got_token == token else None


def open_socket(version):
    """(socket, is_raw). Tries the unprivileged datagram socket first."""
    try:
        return socket.socket(_FAMILY[version], socket.SOCK_DGRAM, _PROTO[version]), False
    except OSError:
        return socket.socket(_FAMILY[version], socket.SOCK_RAW, _PROTO[version]), True


def sweep(hosts, version, on_reply, on_sent, cancel, rate=2000, timeout=1.0, sock_factory=open_socket):
    """Pings every address from the `hosts` iterator once.
    on_reply(ip, rtt_ms) runs on the receiver thread for each answering host (once per host);
    on_sent(n) reports progress; cancel is a threading.Event. Raises OSError if no ICMP socket can be opened."""
    sock, is_raw = sock_factory(version)
    token = os.urandom(8)
    ident = int.from_bytes(os.urandom(2), "big")  # the kernel replaces it on datagram sockets
    stop = threading.Event()
    answered = set()

    sock.settimeout(0.2)  # lets the receiver notice `stop`; sends never block that long in practice

    def receive():
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                if stop.is_set():
                    return
                continue
            sent = parse_reply(version, data, is_raw, token)
            ip = str(ipaddress.ip_address(addr[0].split("%")[0]))
            if sent is None or ip in answered:
                continue
            answered.add(ip)
            on_reply(ip, round((time.monotonic() - sent) * 1000, 2))

    receiver = threading.Thread(target=receive, daemon=True, name="icmp-recv")
    receiver.start()
    try:
        interval = 1.0 / max(1, rate)
        next_send = time.monotonic()
        count = 0
        for ip in hosts:
            if cancel.is_set():
                break
            delay = next_send - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            next_send = max(next_send + interval, time.monotonic() - 0.05)  # no burst after a stall
            packet = build_echo(version, ident, count & 0xFFFF, _PAYLOAD.pack(token, time.monotonic()))
            for _ in range(3):
                try:
                    sock.sendto(packet, (ip, 0))
                    break
                except (BlockingIOError, socket.timeout):  # send buffer full: retry shortly
                    time.sleep(0.01)
                except OSError:
                    break  # unreachable / no route: the address simply does not answer
            count += 1
            if count % 64 == 0:
                on_sent(count)
        on_sent(count)
        deadline = time.monotonic() + timeout
        while not cancel.is_set() and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        stop.set()
        receiver.join(1.0)
        sock.close()
    return count
