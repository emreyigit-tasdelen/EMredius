# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Async UDP flow collector. `python -m nms.netflow` (systemd: emredius-netflow.service).
Env: NETFLOW_PORTS (default 2055,4739), NETFLOW_BIND (0.0.0.0), NMS_DB_PATH, NETFLOW_RETENTION_DAYS."""
from __future__ import annotations

import asyncio
import logging
import os
import signal

from . import allow, store
from .parser import Templates, parse_packet

log = logging.getLogger("netflow")


class FlowProtocol(asyncio.DatagramProtocol):
    def __init__(self, agg, templates, acl=None):
        self.agg, self.templates, self.acl = agg, templates, acl

    def datagram_received(self, data, addr):
        if self.acl is not None and not self.acl.allows(addr[0]):
            return
        ver, flows = parse_packet(data, addr[0], self.templates)
        if ver:
            self.agg.add(addr[0], ver, flows)


async def run(db_path, ports, bind="0.0.0.0", retention=store.RETENTION_DAYS, stop=None):
    conn = store.connect(db_path)
    agg, templates = store.Aggregator(), Templates()
    acl = allow.Acl(lambda: allow.load(conn))
    loop = asyncio.get_running_loop()
    transports = []
    for p in ports:
        t, _ = await loop.create_datagram_endpoint(lambda: FlowProtocol(agg, templates, acl), local_addr=(bind, p))
        transports.append(t)
        log.info("listening on udp/%s", p)
    stop = stop or asyncio.Event()
    ticks = 0
    try:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), 5)
            except asyncio.TimeoutError:
                pass
            try:
                agg.flush(conn)
                ticks += 1
                if ticks % 720 == 1:  # hourly
                    store.purge(conn, retention)
            except Exception:
                log.exception("flush failed")
    finally:
        for t in transports:
            t.close()
        try:
            agg.flush(conn)
        finally:
            conn.close()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ports = [int(x) for x in os.environ.get("NETFLOW_PORTS", "2055,4739").split(",") if x.strip()]
    db = os.environ.get("NMS_DB_PATH", "data/enterprise_nms.db")
    stop = asyncio.Event()

    async def _main():
        loop = asyncio.get_running_loop()
        for s in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(s, stop.set)
        await run(db, ports, os.environ.get("NETFLOW_BIND", "0.0.0.0"),
                  int(os.environ.get("NETFLOW_RETENTION_DAYS", store.RETENTION_DAYS)), stop)

    asyncio.run(_main())
