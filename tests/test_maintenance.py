# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import contextlib
import importlib.util
import io
import os
from datetime import datetime

import pytest

from emredius.services import audit5651

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _row(user, ip="10.0.0.5"):
    return {"username": user, "framedipaddress": ip, "callingstationid": "AA-BB", "nasipaddress": "10.0.0.1",
            "acctstarttime": datetime(2026, 10, 9, 8, 0), "acctstoptime": None, "acctsessiontime": 60,
            "acctinputoctets": 1, "acctoutputoctets": 2, "acctsessionid": "s1"}


def test_daily_archive_chain_verifies(tmp_path):
    d = str(tmp_path)
    assert audit5651.write_daily_archive(d, "2026-10-08", [_row("a")])
    assert audit5651.write_daily_archive(d, "2026-10-09", [_row("=cmd()")])
    assert audit5651.write_daily_archive(d, "2026-10-09", []) is None  # idempotent
    with pytest.raises(ValueError):
        audit5651.write_daily_archive(d, "2026-10-01", [])  # out of order
    entries, err = audit5651.parse_chain(os.path.join(d, "chain.log"))
    assert err is None and [e["link_ok"] for e in entries] == [True, True]
    assert "'=cmd()" in open(os.path.join(d, "5651_2026-10-09.csv"), encoding="utf-8").read()
    listing = audit5651.list_archive(d)
    assert listing["has_chain"] and [x["date"] for x in listing["days"]] == ["2026-10-09", "2026-10-08"]


def test_pending_days_catch_up(tmp_path):
    d = str(tmp_path)
    assert audit5651.pending_days(d, "2026-10-11") == ["2026-10-11"]  # nothing archived yet
    audit5651.write_daily_archive(d, "2026-10-08", [])
    assert audit5651.pending_days(d, "2026-10-11") == ["2026-10-09", "2026-10-10", "2026-10-11"]
    assert audit5651.pending_days(d, "2026-10-08") == []
    assert len(audit5651.pending_days(d, "2027-10-08", max_days=5)) == 5


def _maintenance(tmp_path, monkeypatch, synced=True):
    spec = importlib.util.spec_from_file_location("maintenance", os.path.join(ROOT, "scripts", "maintenance.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    monkeypatch.setattr(m, "build_config", lambda: {"ARCHIVE_5651_DIR": str(tmp_path), "LOG_LEVEL": "INFO",
                                                    "SYSTEM_DRY_RUN": True, "DB_HOST": "127.0.0.1", "DB_PORT": 1,
                                                    "DB_USER": "x", "DB_PASSWORD": "", "DB_NAME": "x",
                                                    "DB_POOL_SIZE": 1, "NMS_DB_PATH": str(tmp_path / "n.db")})
    monkeypatch.setattr(m.audit5651, "day_rows", lambda day: iter([_row("u1")]))
    monkeypatch.setattr(m.chrony, "tracking_info", lambda: {"is_synced": synced, "system_time": "0.0 seconds fast"})
    return m


def test_maintenance_cli_archive(tmp_path, monkeypatch):
    m = _maintenance(tmp_path, monkeypatch)
    for expected in ("ARCHIVE_CREATED", "ARCHIVE_EXISTS"):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            assert m.main(["archive5651", "--date", "2026-10-09"]) == 0
        assert expected in out.getvalue()
    out = io.StringIO()
    with contextlib.redirect_stdout(out):  # default run: yesterday + every missed day since 2026-10-09
        assert m.main(["archive5651"]) == 0
    assert "5651_2026-10-10.csv" in out.getvalue()


def test_maintenance_archive_deferred_when_unsynced(tmp_path, monkeypatch):
    m = _maintenance(tmp_path, monkeypatch, synced=False)
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        assert m.main(["archive5651", "--date", "2026-10-09"]) == m.EXIT_DEFERRED == 75
    assert "ARCHIVE_DEFERRED" in err.getvalue() and not [f for f in os.listdir(tmp_path) if f.startswith("5651_")]
    with contextlib.redirect_stdout(io.StringIO()):
        assert m.main(["archive5651", "--date", "2026-10-09", "--ignore-clock"]) == 0


def test_archive_deferral_is_a_unit_success_but_errors_are_not(tmp_path, monkeypatch):
    """emredius-5651.service must treat only the deferral code as success; a real error still fails the unit."""
    unit = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "deploy", "systemd", "emredius-5651.service"), encoding="utf-8").read()
    m = _maintenance(tmp_path, monkeypatch)
    assert f"SuccessExitStatus={m.EXIT_DEFERRED}" in unit
    monkeypatch.setattr(m.audit5651, "write_daily_archive", lambda *a: (_ for _ in ()).throw(OSError("disk")))
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        assert m.main(["archive5651", "--date", "2026-10-09"]) == 1
    assert "ERROR:disk" in err.getvalue()


def _clock(synced=True):
    tracking = {"is_synced": synced, "ref_id": "C0A80101", "stratum": "3", "source": "time.google.com",
                "leap_status": "Normal", "system_time": "0.000012 seconds fast"}
    st = {"level": "ok" if synced else "crit", "offset_s": 1.2e-05, "message": "m"}
    return audit5651.clock_record(tracking, st, ignore_clock=not synced, now=datetime(2026, 10, 10, 0, 5))


def test_clock_record_chain_and_old_days(tmp_path):
    """Old days (no clock record) stay valid as YOK; new days get a clock record bound to the day's hashes."""
    d = str(tmp_path)
    audit5651.write_daily_archive(d, "2026-10-07", [_row("old")])  # archived before clock records existed
    audit5651.write_daily_archive(d, "2026-10-08", [_row("a")], _clock())
    audit5651.write_daily_archive(d, "2026-10-09", [_row("b")], _clock(synced=False))
    chain = open(os.path.join(d, "chain.log"), encoding="utf-8").read().split()
    assert len(chain) == 9  # chain.log format unchanged: 3 fields per day
    rec = __import__("json").load(open(os.path.join(d, "5651_2026-10-08.clock.json"), encoding="utf-8"))
    assert rec["synced"] is True and rec["source"] == "time.google.com" and rec["stratum"] == "3"
    assert rec["measured_at_utc"].endswith("Z") and rec["csv_sha256"] == chain[4] and rec["chain_sha256"] == chain[5]
    res = audit5651.verify_archive(d)
    st = {r["date"]: r["clock_status"] for r in res["rows"]}
    assert st == {"2026-10-07": "YOK", "2026-10-08": "OK", "2026-10-09": "WARN"}
    assert all(r["ok"] for r in res["rows"]) and res["clock_total"] == 2 and not res["clock_broken"]
    assert audit5651.list_archive(d)["days"][0]["has_clock"]


def test_clock_record_tamper_detected(tmp_path):
    d = str(tmp_path)
    audit5651.write_daily_archive(d, "2026-10-08", [_row("a")], _clock())
    audit5651.write_daily_archive(d, "2026-10-09", [_row("b")], _clock())
    p = os.path.join(d, "5651_2026-10-08.clock.json")
    open(p, "w", encoding="utf-8").write(open(p, encoding="utf-8").read().replace('"synced": true', '"synced": false'))
    os.remove(os.path.join(d, "5651_2026-10-09.clock.json"))
    res = audit5651.verify_archive(d)
    assert {r["date"]: r["clock_status"] for r in res["rows"]} == {"2026-10-08": "FAIL", "2026-10-09": "FAIL"}
    assert not any(r["ok"] for r in res["rows"])


def test_maintenance_cli_writes_clock_record(tmp_path, monkeypatch):
    m = _maintenance(tmp_path, monkeypatch)
    with contextlib.redirect_stdout(io.StringIO()):
        assert m.main(["archive5651", "--date", "2026-10-09"]) == 0
    assert os.path.isfile(tmp_path / "5651_2026-10-09.clock.json") and os.path.isfile(tmp_path / "clock_chain.log")
    assert [r["clock_status"] for r in audit5651.verify_archive(str(tmp_path))["rows"]] == ["OK"]
