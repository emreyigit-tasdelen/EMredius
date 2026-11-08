# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import timesync


def test_parse_offset():
    assert timesync.parse_offset("0.000012 seconds fast of NTP time") == 0.000012
    assert timesync.parse_offset("2.5 seconds slow of NTP time") == -2.5
    assert timesync.parse_offset("-") is None


def test_evaluate_levels():
    ok = {"is_synced": True, "system_time": "0.000008 seconds slow of NTP time", "ref_id": "x"}
    assert timesync.evaluate(ok)["level"] == "ok"
    assert timesync.evaluate(dict(ok, system_time="3.2 seconds fast of NTP time"))["level"] == "warn"
    assert timesync.evaluate(dict(ok, is_synced=False))["level"] == "crit"


def test_watch_step_alerts_once_and_on_recovery(monkeypatch):
    monkeypatch.setattr(timesync, "_watch", {"started": True, "bad_since": None, "alerted": False})
    sent = []
    bad, good = {"level": "crit", "message": "senkron değil"}, {"level": "ok", "message": ""}
    timesync.watch_step(bad, 0, sent.append)
    timesync.watch_step(bad, timesync.ALERT_AFTER_S - 1, sent.append)
    assert sent == []  # short glitches stay quiet
    timesync.watch_step(bad, timesync.ALERT_AFTER_S, sent.append)
    timesync.watch_step(bad, timesync.ALERT_AFTER_S + 600, sent.append)
    assert len(sent) == 1 and "senkron değil" in sent[0]
    timesync.watch_step(good, timesync.ALERT_AFTER_S + 700, sent.append)
    assert len(sent) == 2 and "yeniden" in sent[1]
    timesync.watch_step(good, timesync.ALERT_AFTER_S + 800, sent.append)
    assert len(sent) == 2


def test_banner_shown_when_clock_unsynced(client, monkeypatch):
    login_as(client, "superadmin")
    monkeypatch.setattr(timesync, "status", lambda force=False: {"level": "crit", "message": "SAAT-SENKRON-DEGIL"})
    assert b"timesyncBanner" in client.get("/ntp").data
    monkeypatch.setattr(timesync, "status", lambda force=False: {"level": "ok", "message": ""})
    assert b"timesyncBanner" not in client.get("/ntp").data
