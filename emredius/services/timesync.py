# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""System clock trust (chrony): panel banner, alerting and the 5651 archive guard.

Levels: ok | warn (synced but |offset| > WARN_OFFSET_S) | crit (no selected NTP source / chronyc failed).
Law 5651 records are only as good as the clock that stamps them, so an unsynced clock must be visible."""
import logging
import re
import threading
import time

from . import chrony

log = logging.getLogger(__name__)

WARN_OFFSET_S = 1.0
CACHE_S = 60
ALERT_AFTER_S = 15 * 60  # alert only when the clock stays untrusted this long
WATCH_INTERVAL_S = 60

_OFFSET_RE = re.compile(r"([0-9.]+)\s+seconds\s+(slow|fast)")
_cache = {"at": 0.0, "value": None}
_watch = {"started": False, "bad_since": None, "alerted": False}


def parse_offset(system_time):
    """'0.000012 seconds fast of NTP time' -> 0.000012 (slow -> negative); None when unparsable."""
    m = _OFFSET_RE.search(system_time or "")
    if not m:
        return None
    v = float(m.group(1))
    return -v if m.group(2) == "slow" else v


def evaluate(tracking):
    """tracking: chrony.tracking_info() -> {"level", "offset_s", "ref_id", "message"}"""
    offset = parse_offset(tracking.get("system_time"))
    res = {"level": "ok", "offset_s": offset, "ref_id": tracking.get("ref_id", "-"),
           "message": "Sistem saati NTP ile senkron."}
    if not tracking.get("is_synced"):
        res.update(level="crit", message="Sistem saati NTP ile senkron değil: erişilebilir zaman kaynağı yok. "
                                         "5651 ve RADIUS kayıt zamanları güvenilir değil.")
    elif offset is not None and abs(offset) > WARN_OFFSET_S:
        res.update(level="warn", message=f"Sistem saati NTP'den {abs(offset):.1f} sn sapmış.")
    return res


def status(force=False):
    """evaluate() of the live chrony state, cached CACHE_S seconds (called on every page render)."""
    now = time.monotonic()
    if force or _cache["value"] is None or now - _cache["at"] > CACHE_S:
        try:
            _cache["value"] = evaluate(chrony.tracking_info())
        except Exception as e:  # never break page rendering
            log.debug("timesync status: %s", e)
            _cache["value"] = {"level": "crit", "offset_s": None, "ref_id": "-",
                               "message": "Saat senkron durumu okunamadı."}
        _cache["at"] = now
    return _cache["value"]


def watch_step(st, now, send):
    """One watcher tick (pure state machine, testable). send(msg) is called once when the clock has been
    untrusted for ALERT_AFTER_S, and once more when it recovers after such an alert."""
    if st["level"] == "ok":
        if _watch["alerted"]:
            send("✅ EMREDIUS: sistem saati yeniden NTP ile senkron.")
            log.warning("timesync: clock synchronised again")
        _watch.update(bad_since=None, alerted=False)
        return
    if _watch["bad_since"] is None:
        _watch["bad_since"] = now
        log.warning("timesync: %s", st["message"])
    elif not _watch["alerted"] and now - _watch["bad_since"] >= ALERT_AFTER_S:
        _watch["alerted"] = True
        send("⚠️ EMREDIUS: " + st["message"])


def start_watcher():
    """Background thread (live panel only; staging runs in SYSTEM_DRY_RUN and must not alert)."""
    if _watch["started"]:
        return
    _watch["started"] = True
    from ..core.notify import send_alert

    def _worker():
        while True:
            time.sleep(WATCH_INTERVAL_S)
            try:
                watch_step(status(force=True), time.monotonic(), send_alert)
            except Exception as e:
                log.debug("timesync watcher: %s", e)
    threading.Thread(target=_worker, daemon=True, name="TimesyncWatcher").start()
