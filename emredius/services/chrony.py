# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""chrony (NTP) status and actions."""
import re

from ..core import run_cmd

# -n: no reverse DNS for source / reference IPs. Without it chronyc blocks for 20-40 s when DNS is slow and the
# 15 s run_cmd timeout then returns nothing (empty source list on the NTP page).
_QUERY_TIMEOUT = 5
# -h 127.0.0.1: query over the UDP command port. Under the panel unit (NoNewPrivileges=yes) chronyc cannot
# transition to chronyc_t, so SELinux denies chronyd's reply on the unix socket and every query times out.
_CHRONYC = ["chronyc", "-h", "127.0.0.1", "-n"]
_MAKESTEP_UNIT = "emredius-chrony-makestep.service"

_TRACKING_KEYS = (("reference id", "ref_id"), ("stratum", "stratum"), ("system time", "system_time"),
                  ("last offset", "last_offset"), ("rms offset", "rms_offset"), ("frequency", "frequency"),
                  ("leap status", "leap_status"))


def parse_tracking(rc, out, sources=None):
    """sources: parse_sources() result. chronyc tracking keeps showing the last reference (rc 0, Leap Normal) even
    when every source is unreachable, so "synced" also requires a currently selected ('*') source."""
    info = {"is_synced": rc == 0, "ref_id": "-", "stratum": "-", "system_time": "-", "last_offset": "-",
            "rms_offset": "-", "frequency": "-", "leap_status": "Normal", "raw": out or ""}
    if rc == 0 and out:
        for line in out.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip().lower()
            for needle, key in _TRACKING_KEYS:
                if needle in k:
                    info[key] = v.strip()
                    break
    if info["leap_status"].lower().startswith("not sync"):
        info["is_synced"] = False
    if sources is not None and not any(s["state"].endswith("*") for s in sources):
        info["is_synced"] = False
    selected = [s for s in sources or [] if s["state"].endswith("*")]
    info["source"] = (selected[0].get("host") or selected[0]["name"]) if selected else "-"
    return info


def tracking_info():
    rc, out, _ = run_cmd(_CHRONYC + ["tracking"], timeout=_QUERY_TIMEOUT)
    return parse_tracking(rc, out, sources_list())


def parse_sources(out):
    sources, started = [], False
    for line in (out or "").splitlines():
        if "=====" in line:
            started = True
            continue
        parts = line.split()
        if started and len(parts) >= 6:
            sources.append({"state": parts[0], "name": parts[1], "stratum": parts[2], "poll": parts[3],
                            "reach": parts[4], "lastrx": parts[5],
                            "sample": " ".join(parts[6:]) if len(parts) > 6 else "-"})
    return sources


def merge_source_hosts(sources, named):
    """named: parse_sources() of `chronyc -N sources` (same row order). Adds the configured host name
    (pool.ntp.org, time.google.com ...) next to each IP without any DNS lookup."""
    if len(named) == len(sources):
        for s, n in zip(sources, named):
            s["host"] = n["name"] if n["name"] != s["name"] else ""
    return sources


def sources_list():
    rc, out, _ = run_cmd(_CHRONYC + ["sources", "-v"], timeout=_QUERY_TIMEOUT)
    if rc != 0:
        return []
    sources = parse_sources(out)
    rc_n, out_n, _ = run_cmd(_CHRONYC + ["-N", "sources"], timeout=_QUERY_TIMEOUT)
    return merge_source_hosts(sources, parse_sources(out_n) if rc_n == 0 else [])


def udp_123_listening():
    rc, out, _ = run_cmd(["ss", "-ulpn"], timeout=_QUERY_TIMEOUT)
    return rc == 0 and any(":123 " in line or line.rstrip().endswith(":123") for line in (out or "").splitlines())


def makestep():
    """(ok, message). makestep needs chronyd's unix socket (UDP gets "501 Not authorised"), which the panel cannot
    use (see _CHRONYC), so it runs in its own oneshot unit and the chronyc reply is read back from the journal."""
    rc, _, err = run_cmd(["systemctl", "start", _MAKESTEP_UNIT], timeout=25)
    if err.startswith("[staging]"):
        return False, err
    _, inv, _ = run_cmd(["systemctl", "show", "-p", "InvocationID", "--value", _MAKESTEP_UNIT], timeout=_QUERY_TIMEOUT)
    reply = ""
    if inv.strip():
        _, out, _ = run_cmd(["journalctl", "_SYSTEMD_INVOCATION_ID=" + inv.strip(), "-o", "cat", "--no-pager"],
                            timeout=_QUERY_TIMEOUT)
        replies = [l for l in out.splitlines() if re.match(r"^\d{3} ", l)]
        reply = replies[-1].strip() if replies else ""
    if rc == 0:
        return True, reply or "200 OK"
    return False, reply or err.strip() or "Hata oluştu."


def status():
    """Everything the NTP page cards and source table show, as JSON-able data (for the in-page refresh)."""
    sources = sources_list()
    return {"tracking": parse_tracking(*_tracking_raw(), sources), "sources": sources}


def _tracking_raw():
    rc, out, _ = run_cmd(_CHRONYC + ["tracking"], timeout=_QUERY_TIMEOUT)
    return rc, out


def restart():
    rc, _, err = run_cmd(["systemctl", "restart", "chronyd"])
    if rc == 0:
        return True, "chronyd restarted successfully."
    return False, err.strip() or "Servis başlatılamadı."
