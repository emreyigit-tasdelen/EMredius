# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Server-push (SSE) topology updates. One background monitor re-checks ping + NMS DB state every few seconds while
at least one page is subscribed and broadcasts only when something changed, so N open pages cost one ping round.
gunicorn runs 1 worker x 16 threads: every open stream pins a thread, hence MAX_STREAMS and MAX_LIFETIME
(clients auto-reconnect; over the limit they fall back to polling)."""
import json
import logging
import threading
import time

from . import snmp as svc

log = logging.getLogger(__name__)

MAX_STREAMS = 6
INTERVAL = 3.0       # monitor period (s)
KEEPALIVE = 15.0     # SSE comment period (s)
MAX_LIFETIME = 240.0  # per-connection cap (s); EventSource reconnects

_cond = threading.Condition()
_state = {"version": 0, "payload": None, "sig": None, "subs": 0, "thread": None}


def _sig(res):
    return json.dumps([(d["id"], d["live_status"], d["snmp_ok"], d.get("sys_name"), d.get("last_cpu"), d.get("last_ram"),
                        d.get("interface_count")) for d in res["devices"]])


def _monitor():
    while True:
        with _cond:
            if _state["subs"] <= 0:
                _state.update(thread=None, payload=None, sig=None)
                return
        try:
            res = svc.topology_live(force=True)
        except Exception as e:  # keep the monitor alive on transient DB/ping errors
            log.warning("snmp live monitor: %s", e)
            res = None
        if res is not None:
            sig = _sig(res)
            with _cond:
                if sig != _state["sig"]:
                    _state.update(sig=sig, payload=res, version=_state["version"] + 1)
                    _cond.notify_all()
        time.sleep(INTERVAL)


def _subscribe():
    with _cond:
        if _state["subs"] >= MAX_STREAMS:
            return False
        _state["subs"] += 1
        if _state["thread"] is None:
            t = threading.Thread(target=_monitor, name="snmp-live", daemon=True)
            _state["thread"] = t
            t.start()
    return True


def _unsubscribe():
    with _cond:
        _state["subs"] = max(0, _state["subs"] - 1)
        _cond.notify_all()


def _events():
    last, started = -1, time.monotonic()
    try:
        yield "retry: 3000\n\n"
        while time.monotonic() - started < MAX_LIFETIME:
            with _cond:
                _cond.wait_for(lambda: _state["version"] != last and _state["payload"] is not None, timeout=KEEPALIVE)
                changed = _state["version"] != last and _state["payload"] is not None
                payload, last = (_state["payload"], _state["version"]) if changed else (None, last)
            if payload is not None:
                yield "data: " + json.dumps(payload, ensure_ascii=False) + "\n\n"
            else:
                yield ": keepalive\n\n"
    finally:
        _unsubscribe()


def open_stream():
    """Returns a primed event generator, or None when the stream limit is reached."""
    if not _subscribe():
        return None
    gen = _events()
    next(gen)  # start it so its finally (unsubscribe) always runs on close
    return gen
