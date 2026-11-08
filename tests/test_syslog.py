# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import asyncio
import socket
import time

from conftest import login_as
from nms.syslogd import store
from nms.syslogd.parser import parse
from emredius.services import syslog as svc


def test_syslog_parser():
    m = parse(b"<34>Oct 11 22:14:15 sw1 sshd[123]: Failed password for root", "10.0.0.5", now=1000)
    assert (m["facility"], m["severity"], m["host"], m["app"]) == (4, 2, "sw1", "sshd")
    assert m["msg"] == "Failed password for root" and m["src_ip"] == "10.0.0.5"
    m = parse(b"<165>1 2026-10-21T10:00:00Z core1 bgpd 55 ID1 - peer down", "10.0.0.6")
    assert (m["facility"], m["severity"], m["host"], m["app"], m["msg"]) == (20, 5, "core1", "bgpd", "peer down")
    m = parse(b"plain text\x00\x01 no pri", "10.0.0.7")
    assert (m["facility"], m["severity"], m["host"]) == (1, 5, "10.0.0.7") and "\x00" not in m["msg"]
    assert parse(b"<999>x", "1.1.1.1")["severity"] == 5 and len(parse(b"a" * 10000, "1.1.1.1")["msg"]) <= 4096


def test_store_retention_purge(tmp_path):
    conn = store.connect(str(tmp_path / "s.db"))
    now = int(time.time())
    store.insert(conn, [parse(b"<14>old", "1.1.1.1", now - 40 * 86400), parse(b"<14>new", "1.1.1.1", now)])
    assert store.retention_days(conn) == 30
    assert store.purge(conn) == 1
    assert conn.execute("SELECT msg FROM syslog_msgs").fetchone()[0] == "new"
    conn.execute("INSERT INTO syslog_cfg VALUES('retention_days','zz')")
    assert store.retention_days(conn) == 30


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _send_through_collector(db, payload):
    from nms.syslogd.collector import run
    port = _free_port()

    async def go():
        stop = asyncio.Event()
        task = asyncio.create_task(run(db, [port], "127.0.0.1", stop))
        await asyncio.sleep(0.3)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.sendto(payload, ("127.0.0.1", port))
        u.close()
        await asyncio.sleep(0.2)
        stop.set()
        await task

    asyncio.run(go())


def test_collector_udp_e2e(tmp_path):
    db = str(tmp_path / "c.db")
    _send_through_collector(db, b"<11>Oct 11 22:14:15 r1 kernel: boom")
    r = store.connect(db).execute("SELECT src_ip, facility, severity, app, msg FROM syslog_msgs").fetchone()
    assert r == ("127.0.0.1", 1, 3, "kernel", "boom")


def test_collector_allowlist(tmp_path):
    db = str(tmp_path / "a.db")
    conn = store.connect(db)
    conn.execute("INSERT INTO syslog_cfg VALUES('allowed_sources','10.9.9.0/24')")
    conn.commit()
    _send_through_collector(db, b"<11>blocked")
    assert conn.execute("SELECT COUNT(*) FROM syslog_msgs").fetchone()[0] == 0


def test_page_search_paging_csv_settings(tmp_path):
    from conftest import make_app
    import emredius.core.db as db
    app = make_app(tmp_path)
    c = app.test_client()
    assert c.get("/syslog").status_code in (302, 401, 403)
    login_as(c, "superadmin")
    r = c.get("/syslog")
    assert r.status_code == 200 and "514" in r.get_data(as_text=True)
    conn = store.connect(db.NMS_DB_PATH)
    now = int(time.time())
    rows = [parse(b"<%d>sw: message %d" % (i % 8, i), "10.0.0.%d" % (1 + i % 3), now - i) for i in range(120)]
    rows.append(parse(b"<11>sw: =cmd|calc 50%_off", "10.0.0.9", now))
    store.insert(conn, rows)
    j = c.get("/syslog/data").get_json()["data"]
    assert j["total"] == 121 and len(j["rows"]) == 50 and j["pages"] == 3
    assert len(c.get("/syslog/data?page=3").get_json()["data"]["rows"]) == 21
    assert c.get("/syslog/data?src_ip=10.0.0.1").get_json()["data"]["total"] == 40
    assert c.get("/syslog/data?severity=3").get_json()["data"]["total"] == sum(1 for r in rows if r["severity"] <= 3)
    assert c.get("/syslog/data?facility=0&q=message 7").get_json()["data"]["total"] == 11  # 7, 70-79
    assert c.get("/syslog/data?facility=1").get_json()["data"]["total"] == 1  # the =cmd row
    assert c.get("/syslog/data?q=50%25_off").get_json()["data"]["total"] == 1   # LIKE wildcards are literal
    assert c.get("/syslog/data?q=%25").get_json()["data"]["total"] == 1
    assert c.get("/syslog/data?severity=99&facility=x&since=bad&page=-4").get_json()["success"]
    csvb = c.get("/syslog/export.csv?src_ip=10.0.0.9").get_data(as_text=True)
    assert csvb.startswith("time,source_ip") and "'=cmd" in csvb
    r = c.post("/syslog/settings", data={"_csrf_token": "tok", "retention_days": "90", "allowed_sources": "10.0.0.0/24"}, follow_redirects=True)
    assert r.status_code == 200 and svc.get_settings() == {"retention_days": 90, "allowed_sources": "10.0.0.0/24"}
    c.post("/syslog/settings", data={"_csrf_token": "tok", "retention_days": "0", "allowed_sources": ""})
    c.post("/syslog/settings", data={"_csrf_token": "tok", "retention_days": "5", "allowed_sources": "not-an-ip"})
    assert svc.get_settings()["retention_days"] == 90


def test_syslog_menu_entry_is_unique():
    """The sidebar must list Syslog once (a duplicate block slipped in when two changes merged)."""
    from pathlib import Path
    base = Path(__file__).resolve().parent.parent / "emredius" / "templates" / "base.html"
    assert base.read_text(encoding="utf-8").count('href="/syslog"') == 1
