# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Async UDP syslog collector. `python -m nms.syslogd` (systemd: emredius-syslog.service).
Env: SYSLOG_PORTS (default 514), SYSLOG_BIND (0.0.0.0), NMS_DB_PATH. Sender allow-list: syslog_cfg key allowed_sources
(CIDR list set from the panel; empty = everyone). Retention: syslog_cfg key retention_days."""
from __future__ import annotations

import asyncio
import logging
import os
import signal

from . import acl as allow, store
from .parser import parse

log = logging.getLogger("syslogd")
MAX_QUEUE = 20000


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue, acl=None):
        self.queue, self.acl = queue, acl

    def datagram_received(self, data, addr):
        if (self.acl is not None and not self.acl.allows(addr[0])) or len(self.queue) >= MAX_QUEUE:
            return
        self.queue.append(parse(data, addr[0]))


def _acl_loader(conn):
    def load():
        try:
            return allow.parse(store.get_cfg(conn, "allowed_sources"))
        except Exception:  # noqa: BLE001
            return []
    return load


async def run(db_path, ports, bind="0.0.0.0", stop=None):
    conn = store.connect(db_path)
    queue = []
    acl = allow.Acl(_acl_loader(conn))
    loop = asyncio.get_running_loop()
    transports = []
    for p in ports:
        t, _ = await loop.create_datagram_endpoint(lambda: SyslogProtocol(queue, acl), local_addr=(bind, p))
        transports.append(t)
        log.info("listening on udp/%s", p)
    stop = stop or asyncio.Event()
    ticks = 0
    try:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), 2)
            except asyncio.TimeoutError:
                pass
            try:
                batch, queue[:] = queue[:], []
                if batch:
                    store.insert(conn, batch)
                ticks += 1
                if ticks % 1800 == 1:  # hourly
                    store.purge(conn)
            except Exception:
                log.exception("flush failed")
    finally:
        for t in transports:
            t.close()
        try:
            if queue:
                store.insert(conn, queue)
        finally:
            conn.close()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ports = [int(x) for x in os.environ.get("SYSLOG_PORTS", "514").split(",") if x.strip()]
    db = os.environ.get("NMS_DB_PATH", "data/enterprise_nms.db")
    stop = asyncio.Event()

    async def _main():
        loop = asyncio.get_running_loop()
        for s in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(s, stop.set)
        await run(db, ports, os.environ.get("SYSLOG_BIND", "0.0.0.0"), stop)

    asyncio.run(_main())
