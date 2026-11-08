# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Syslog message parser: RFC 3164 (BSD) and RFC 5424. Never raises; unknown input becomes a plain message
(facility user=1, severity notice=5, the PRI default for unparsable datagrams)."""
from __future__ import annotations

import re
import time

FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp",
              "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5",
              "local6", "local7"]
SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
MAX_MSG = 4096

_PRI = re.compile(rb"^<(\d{1,3})>")
_V5424 = re.compile(r"^(\d+) (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+) ?(.*)$", re.S)
_V3164 = re.compile(r"^(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+) (\S+) (.*)$", re.S)
_TAG = re.compile(r"^([\w./-]{1,48})(?:\[\d+\])?:\s*(.*)$", re.S)
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _nil(v):
    return "" if v == "-" else v


def parse(data, src_ip, now=None):
    """Returns dict ts, src_ip, facility, severity, host, app, msg."""
    now = int(now or time.time())
    pri, body = 13, data
    m = _PRI.match(data)
    if m and int(m.group(1)) <= 191:
        pri, body = int(m.group(1)), data[m.end():]
    text = _CTRL.sub(" ", body.decode("utf-8", "replace").strip())[:MAX_MSG]
    host, app, msg = src_ip, "", text
    m5 = _V5424.match(text)
    if m5:
        host = _nil(m5.group(3)) or src_ip
        app = _nil(m5.group(4))
        msg = m5.group(8) or ""
    else:
        m3 = _V3164.match(text)
        if m3:
            host, rest = m3.group(1), m3.group(2)
            mt = _TAG.match(rest)
            app, msg = (mt.group(1), mt.group(2)) if mt else ("", rest)
        else:
            mt = _TAG.match(text)
            if mt:
                app, msg = mt.group(1), mt.group(2)
    return {"ts": now, "src_ip": src_ip, "facility": pri >> 3, "severity": pri & 7,
            "host": host[:255], "app": app[:64], "msg": msg}
