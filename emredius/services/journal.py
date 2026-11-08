# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""systemd journal reader for the live log page."""
import re

from ..core import run_cmd

_ERR = ("error", "failed", "crit", "fatal", "emerg")
_WARN = ("warn", "warning", "notice", "reject")
_OK = ("started", "active: active", "success", "accepted", "login ok", "ready")
_INFO = ("sshd", "sudo", "systemd", "session opened", "command", "pam", "kernel")


def fetch_lines(unit="all"):
    """Returns the last 200 journal lines (optionally for one sanitized unit name)."""
    cmd = ["journalctl", "-n", "200", "--no-pager"]
    unit = (unit or "all").strip().lower()
    if unit and unit != "all":
        unit_clean = re.sub(r"[^a-zA-Z0-9_\-.]", "", unit).lstrip("-.")[:64]
        if unit_clean:
            cmd = ["journalctl", "-u", unit_clean, "-n", "200", "--no-pager"]
    rc, out, _ = run_cmd(cmd)
    raw_lines = out.splitlines() if out else ["Journal günlüğü bulunamadı."]
    return [line for line in raw_lines if not line.startswith("-- Logs begin")]


def classify(line):
    """CSS class suffix of a journal line ('' for a plain line)."""
    lower = line.lower()
    for words, cls in ((_ERR, "err"), (_WARN, "warn"), (_OK, "ok"), (_INFO, "info")):
        if any(w in lower for w in words):
            return cls
    return ""


def classified_lines(unit="all"):
    return [(classify(line), line) for line in fetch_lines(unit)]
