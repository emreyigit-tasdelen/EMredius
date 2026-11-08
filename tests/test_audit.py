# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import hashlib
import os

from conftest import login_as
from emredius.services import audit5651 as svc


def _make_archive(d, tamper=False):
    prev = "0" * 64
    lines = []
    for day in ("2026-10-01", "2026-10-02"):
        name = f"5651_{day}.csv"
        data = f"username\nu-{day}\n".encode()
        (d / name).write_bytes(data)
        sha = hashlib.sha256(data).hexdigest()
        (d / (name + ".sha256")).write_text(sha)
        prev = hashlib.sha256((prev + sha).encode()).hexdigest()
        lines.append(f"{day} {sha} {prev}")
    (d / "chain.log").write_text("\n".join(lines) + "\n")
    if tamper:
        (d / "5651_2026-10-01.csv").write_bytes(b"changed\n")


def test_filters_and_where():
    f, errors = svc.parse_filters({"ip": "10.0.0.1", "mac": "AA-BB", "username": "a_b%", "start": "2026-10-02",
                                   "end": "2026-10-01"})
    assert errors  # start after end
    f, errors = svc.parse_filters({"mac": "AA-BB", "username": "a_b%"})
    sql, params = svc.build_where(f)
    assert "%aabb%" in params and "%a\\_b\\%%" in params and "%s" in sql
    assert svc.csv_cell("=cmd") == "'=cmd" and svc.csv_cell(5) == 5


def test_verify_archive(tmp_path):
    _make_archive(tmp_path)
    res = svc.verify_archive(str(tmp_path))
    assert all(r["ok"] for r in res["rows"]) and not res["chain_broken"]
    _make_archive(tmp_path, tamper=True)
    res = svc.verify_archive(str(tmp_path))
    assert [r["date"] for r in res["rows"] if not r["ok"]] == ["2026-10-01"]


def test_audit_pages(client, app, tmp_path, monkeypatch):
    _make_archive(tmp_path)
    app.config["ARCHIVE_5651_DIR"] = str(tmp_path)
    monkeypatch.setattr(svc, "search", lambda f, page: ([{"username": "<x>", "acctstoptime": None}], 250, 3, page))
    login_as(client, "superadmin")
    body = client.get("/audit?username=x&page=2").get_data(as_text=True)
    assert "&lt;x&gt;" in body and "Sayfa <strong>2</strong> / 3" in body and "username=x&amp;page=3" in body
    assert "5651_2026-10-02.csv" in body
    body = client.get("/audit/archive/verify").get_data(as_text=True)
    assert "2 OK" in body
    r = client.get("/audit/archive/5651_2026-10-01.csv")
    assert r.status_code == 200 and b"u-2026-10-01" in r.data
    assert client.get("/audit/archive/..%2Fetc").status_code in (302, 404)


def test_verify_page_shows_clock_records(client, app, tmp_path):
    svc.write_daily_archive(str(tmp_path), "2026-10-08", [{"username": "a"}])
    clock = svc.clock_record({"is_synced": True, "source": "pool<x>", "stratum": "2"}, {"level": "ok", "offset_s": 0.5})
    svc.write_daily_archive(str(tmp_path), "2026-10-09", [{"username": "b"}], clock)
    app.config["ARCHIVE_5651_DIR"] = str(tmp_path)
    login_as(client, "superadmin")
    body = client.get("/audit/archive/verify").get_data(as_text=True)
    assert "2 OK" in body and "clock_chain.log" in body and "pool&lt;x&gt;" in body and "0.500 sn" in body
    r = client.get("/audit/archive/5651_2026-10-09.clock.json")
    assert r.status_code == 200 and b'"synced": true' in r.data
    assert client.get("/audit/archive/clock_chain.log").status_code == 200
    assert ".clock.json" in client.get("/audit").get_data(as_text=True)
