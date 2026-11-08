# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""System command execution, service status and value formatting."""
import json
import logging
import subprocess
import threading
import time

log = logging.getLogger(__name__)


# Staging guard: with SYSTEM_DRY_RUN enabled, commands that change the host (services, firewall, clock, power)
# are refused, so a staging instance on the production server can never touch the live services.
_dry_run = {"on": False}
_READ_ONLY_SUBCOMMANDS = {
    "systemctl": {"is-active", "is-enabled", "is-failed", "status", "show", "cat", "list-units",
                  "list-unit-files", "list-timers"},
    "chronyc": {"tracking", "sources", "sourcestats", "activity", "clients", "serverstats", "ntpdata"},
    "timedatectl": {"status", "show", "list-timezones", "timesync-status", "show-timesync"},
}
_ALWAYS_BLOCKED = {"reboot", "shutdown", "poweroff", "halt", "init", "kill", "pkill", "killall"}


def set_dry_run(enabled):
    _dry_run["on"] = bool(enabled)


def is_dry_run():
    return _dry_run["on"]


def _blocked_in_dry_run(cmd_list):
    if not cmd_list:
        return False
    prog = str(cmd_list[0]).rsplit("/", 1)[-1]
    args = [str(a) for a in cmd_list[1:]]
    if prog in _ALWAYS_BLOCKED:
        return True
    if prog in _READ_ONLY_SUBCOMMANDS:
        if prog == "chronyc" and args[:1] == ["-h"]:  # -h <host> takes a value
            args = args[2:]
        sub = next((a for a in args if not a.startswith("-")), None)
        if prog == "timedatectl" and sub is None:
            return False
        return sub not in _READ_ONLY_SUBCOMMANDS[prog]
    if prog == "firewall-cmd":
        return not all(a.startswith(("--list", "--state", "--get", "--query", "--zone")) for a in args)
    if prog == "radclient":  # Disconnect / CoA packets would drop real users from the staging copy of radacct
        return any(a in ("disconnect", "coa") for a in args)
    return False


def run_cmd(cmd_list, timeout=15, input_text=None):
    """Runs a command WITHOUT a shell. Returns (returncode, stdout, stderr). Kills the process on timeout."""
    if _dry_run["on"] and _blocked_in_dry_run(cmd_list):
        log.warning("SYSTEM_DRY_RUN: refused %s", " ".join(map(str, cmd_list))[:200])
        return 1, "", "[staging] Bu komut SYSTEM_DRY_RUN modunda engellendi."
    try:
        p = subprocess.Popen(
            cmd_list,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        try:
            out, err = p.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
            return -1, (out or "").strip(), ((err or "") + "\n[timeout]").strip()
        return p.returncode, (out or "").strip(), (err or "").strip()
    except Exception as e:
        return -1, "", str(e)


_radiusd_status_cache = {"t": 0.0, "v": "inactive"}


def get_radiusd_status():
    """`systemctl is-active radiusd`, cached for 5 seconds."""
    now = time.time()
    if now - _radiusd_status_cache["t"] < 5:
        return _radiusd_status_cache["v"]
    rc, out, _ = run_cmd(["systemctl", "is-active", "radiusd"])
    val = out.strip() if rc == 0 else "inactive"
    _radiusd_status_cache.update({"t": now, "v": val})
    return val


def invalidate_radiusd_status():
    _radiusd_status_cache["t"] = 0.0


def restart_radiusd_async(delay=1):
    """Restart FreeRADIUS in the background after a config check (used after NAS changes; read_clients=yes)."""
    def _worker():
        time.sleep(delay)
        rc, _, err = run_cmd(["radiusd", "-C"], timeout=30)
        if rc != 0:
            log.error("radiusd config check failed, not restarting: %s", err)
            return
        run_cmd(["systemctl", "restart", "radiusd"], timeout=60)
        invalidate_radiusd_status()
    threading.Thread(target=_worker, daemon=True, name="RadiusdRestart").start()


def _heartbeat_epoch(value):
    """last_heartbeat column -> epoch seconds. The NMS daemons write UTC either as SQLite
    'YYYY-MM-DD HH:MM:SS' (poller) or ISO-8601 with offset (tacacs); naive values are UTC."""
    if not value:
        return None
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(str(value).replace(" ", "T"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return None


def daemon_alive(status_row, max_age_seconds=60):
    """True only if a daemon_status row says RUNNING and its heartbeat (metrics_json.heartbeat_epoch) is fresh."""
    try:
        if not status_row or status_row["status"] != "RUNNING":
            return False
        metrics = json.loads(status_row["metrics_json"] or "{}")
        epoch = metrics.get("heartbeat_epoch")
        if epoch is None:
            epoch = _heartbeat_epoch(status_row["last_heartbeat"])
        if epoch is None:
            return False
        return (time.time() - float(epoch)) < max_age_seconds
    except Exception:
        return False


def format_bytes(size):
    try:
        size = float(size or 0)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    except Exception:
        return "0 B"


def format_seconds(seconds):
    try:
        sec = int(seconds or 0)
        hours = sec // 3600
        minutes = (sec % 3600) // 60
        secs = sec % 60
        if hours > 0:
            return f"{hours} sa {minutes} dk"
        if minutes > 0:
            return f"{minutes} dk {secs} sn"
        return f"{secs} sn"
    except Exception:
        return "0 sn"
