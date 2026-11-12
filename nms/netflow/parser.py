# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""NetFlow v5, NetFlow v9 and IPFIX (v10) packet parser. Pure functions + a per-exporter template cache.
Returns flow dicts: src, dst, sport, dport, proto, bytes, pkts, in_if, out_if, flags, ts (end time, epoch s)."""
from __future__ import annotations

import ipaddress
import struct
import time

# element id -> flow key (same numbers in NetFlow v9 and IPFIX)
_FIELDS = {8: "src", 12: "dst", 27: "src", 28: "dst", 7: "sport", 11: "dport", 4: "proto",
           1: "bytes", 2: "pkts", 10: "in_if", 14: "out_if", 6: "flags", 85: "bytes", 86: "pkts"}


class Templates:
    """Template cache keyed by (exporter ip, observation domain / source id, template id)."""

    def __init__(self):
        self._t = {}

    def set(self, exporter, domain, tid, fields):
        self._t[(exporter, domain, tid)] = fields

    def get(self, exporter, domain, tid):
        return self._t.get((exporter, domain, tid))


def _ip(raw):
    return str(ipaddress.ip_address(raw))


def _num(raw):
    return int.from_bytes(raw, "big")


def parse_v5(data):
    ver, count, uptime, secs, _ns, _seq, _et, _eid, _samp = struct.unpack("!HHIIIIBBH", data[:24])
    flows = []
    for i in range(min(count, (len(data) - 24) // 48)):
        r = data[24 + i * 48: 72 + i * 48]
        src, dst, _nh, inif, outif, pkts, octets, first, last, sport, dport, _p, flags, proto = \
            struct.unpack("!4s4s4sHHIIIIHHBBB", r[:39])
        flows.append({"src": _ip(src), "dst": _ip(dst), "sport": sport, "dport": dport, "proto": proto,
                      "bytes": octets, "pkts": pkts, "in_if": inif, "out_if": outif, "flags": flags,
                      "ts": secs - max(0, (uptime - last)) // 1000})
    return flows


def _parse_template_set(body, exporter, domain, templates, ipfix):
    pos = 0
    while pos + 4 <= len(body):
        tid, count = struct.unpack("!HH", body[pos:pos + 4])
        pos += 4
        fields = []
        for _ in range(count):
            if pos + 4 > len(body):
                return
            ie, ln = struct.unpack("!HH", body[pos:pos + 4])
            pos += 4
            if ipfix and ie & 0x8000:  # enterprise element: skip the 4-byte PEN
                pos += 4
                ie = -1
            fields.append((ie, ln))
        if fields:
            templates.set(exporter, domain, tid, fields)


def _parse_data_set(body, fields, ts):
    flows = []
    pos = 0
    min_len = sum(l for _, l in fields if l != 65535)
    while pos + min_len <= len(body) and fields:
        rec = {"ts": ts}
        for ie, ln in fields:
            if ln == 65535:  # IPFIX variable length
                ln = body[pos]
                pos += 1
                if ln == 255:
                    ln = struct.unpack("!H", body[pos:pos + 2])[0]
                    pos += 2
            raw = body[pos:pos + ln]
            pos += ln
            key = _FIELDS.get(ie)
            if key is None:
                continue
            if key in ("src", "dst"):
                rec[key] = _ip(raw) if len(raw) in (4, 16) else None
            else:
                rec[key] = rec.get(key, 0) + _num(raw) if key in ("bytes", "pkts") and key in rec else _num(raw)
        if rec.get("src") and rec.get("dst"):
            rec.setdefault("sport", 0); rec.setdefault("dport", 0); rec.setdefault("proto", 0)
            rec.setdefault("bytes", 0); rec.setdefault("pkts", 0); rec.setdefault("in_if", 0)
            rec.setdefault("out_if", 0); rec.setdefault("flags", 0)
            flows.append(rec)
        if pos >= len(body) - 3:  # remaining bytes are set padding
            break
    return flows


def parse_v9(data, exporter, templates):
    _v, _count, _up, secs, _seq, sid = struct.unpack("!HHIIII", data[:20])
    flows, pos = [], 20
    while pos + 4 <= len(data):
        sid_set, ln = struct.unpack("!HH", data[pos:pos + 4])
        if ln < 4:
            break
        body = data[pos + 4: pos + ln]
        pos += ln
        if sid_set == 0:
            _parse_template_set(body, exporter, sid, templates, False)
        elif sid_set >= 256:
            f = templates.get(exporter, sid, sid_set)
            if f:
                flows += _parse_data_set(body, f, secs)
    return flows


def parse_ipfix(data, exporter, templates):
    _v, _ln, secs, _seq, domain = struct.unpack("!HHIII", data[:16])
    flows, pos = [], 16
    end = min(len(data), _ln)
    while pos + 4 <= end:
        set_id, ln = struct.unpack("!HH", data[pos:pos + 4])
        if ln < 4:
            break
        body = data[pos + 4: pos + ln]
        pos += ln
        if set_id == 2:
            _parse_template_set(body, exporter, domain, templates, True)
        elif set_id >= 256:
            f = templates.get(exporter, domain, set_id)
            if f:
                flows += _parse_data_set(body, f, secs)
    return flows


def parse_packet(data, exporter, templates):
    """Returns (version, flows). Unknown / malformed packets give (0, [])."""
    if len(data) < 16:
        return 0, []
    ver = struct.unpack("!H", data[:2])[0]
    try:
        if ver == 5 and len(data) >= 24:
            return 5, parse_v5(data)
        if ver == 9:
            return 9, parse_v9(data, exporter, templates)
        if ver == 10:
            return 10, parse_ipfix(data, exporter, templates)
    except (struct.error, ValueError, IndexError):
        return 0, []
    return 0, []
