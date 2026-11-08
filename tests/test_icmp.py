# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import queue
import socket
import struct
import threading

from emredius.services import icmp


class FakeIcmpSocket:
    """Datagram-ICMP stand-in: answers echo requests sent to `alive` addresses."""

    def __init__(self, alive=(), version=4):
        self.alive, self.version, self.sent, self._q, self.timeout = set(alive), version, [], queue.Queue(), None

    def settimeout(self, t):
        self.timeout = t

    def sendto(self, packet, addr):
        self.sent.append(addr[0])
        if addr[0] in self.alive:
            reply = bytes([icmp.ECHO_REPLY[self.version]]) + packet[1:]
            self._q.put((reply, (addr[0], 0)))
            self._q.put((reply, (addr[0], 0)))  # duplicate reply must be counted once

    def recvfrom(self, size):
        try:
            return self._q.get(timeout=self.timeout)
        except queue.Empty:
            raise socket.timeout()

    def close(self):
        pass


def test_checksum_and_echo_packet():
    pkt = icmp.build_echo(4, 0x1234, 1, b"abcd")
    assert pkt[0] == 8 and icmp.checksum(pkt) == 0  # a correct checksum sums to zero
    assert icmp.build_echo(6, 1, 1, b"x")[0] == 128


def test_parse_reply_filters_foreign_and_raw_header():
    token = b"T" * 8
    payload = struct.pack("!8sd", token, 12.5)
    reply = bytes([0, 0, 0, 0, 0, 1, 0, 1]) + payload
    assert icmp.parse_reply(4, reply, False, token) == 12.5
    assert icmp.parse_reply(4, reply, False, b"X" * 8) is None  # another scan's / process's packet
    assert icmp.parse_reply(4, bytes([8]) + reply[1:], False, token) is None  # an echo request, not a reply
    ip_header = bytes([0x45]) + bytes(19)
    assert icmp.parse_reply(4, ip_header + reply, True, token) == 12.5


def test_sweep_reports_each_alive_host_once():
    fake = FakeIcmpSocket(alive={"10.0.0.2", "10.0.0.5"})
    replies, progress = [], []
    n = icmp.sweep(iter(f"10.0.0.{i}" for i in range(1, 9)), 4, lambda ip, rtt: replies.append(ip), progress.append,
                   threading.Event(), rate=10000, timeout=0.3, sock_factory=lambda v: (fake, False))
    assert n == 8 and progress[-1] == 8 and sorted(replies) == ["10.0.0.2", "10.0.0.5"]


def test_sweep_cancel_stops_sending():
    cancel = threading.Event()
    fake = FakeIcmpSocket()
    sent = icmp.sweep(iter(f"10.1.{i // 256}.{i % 256}" for i in range(100000)), 4, lambda *a: None,
                      lambda n: n >= 50 and cancel.set(), cancel, rate=100000, timeout=5,
                      sock_factory=lambda v: (fake, False))
    assert sent < 1000


def test_sweep_real_loopback():
    """Real socket against 127.0.0.1 when this machine allows an ICMP socket (skipped otherwise)."""
    try:
        sock = icmp.open_socket(4)
    except OSError:
        return
    replies = []
    icmp.sweep(iter(["127.0.0.1"]), 4, lambda ip, rtt: replies.append((ip, rtt)), lambda n: None,
               threading.Event(), timeout=1.0, sock_factory=lambda v: sock)
    assert replies and replies[0][0] == "127.0.0.1" and replies[0][1] >= 0
