# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Unified enterprise daemons runner for TACACS+ TCP 49 and SNMP NMS Poller."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from typing import Optional


from nms.common.db import DEFAULT_DB_PATH, init_db
from nms.snmp.poller import SnmpPollerDaemon
from nms.tacacs.server import TacacsServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("enterprise.runner")


class DaemonSupervisor:
    """Manages lifecycle of both TACACS+ and SNMP Poller daemons."""

    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        tacacs_port: int = 49,
        tacacs_host: str = "0.0.0.0",
        snmp_poll_interval: float = 15.0,
    ) -> None:
        self.db_path = db_path
        self.tacacs_port = tacacs_port
        self.tacacs_host = tacacs_host
        self.snmp_poll_interval = snmp_poll_interval

        self.tacacs_server: Optional[TacacsServer] = None
        self.snmp_poller: Optional[SnmpPollerDaemon] = None
        self.shutdown_event = asyncio.Event()

    async def start(self) -> None:
        """Initializes database and runs daemons concurrently."""
        logger.info("Initializing SQLite database with WAL mode at: %s", self.db_path)
        init_db(self.db_path)

        # 1. Instantiate TACACS+ server
        self.tacacs_server = TacacsServer(
            host=self.tacacs_host,
            port=self.tacacs_port,
            db_path=self.db_path,
        )

        # 2. Instantiate SNMP poller daemon
        self.snmp_poller = SnmpPollerDaemon(
            db_path=self.db_path,
            poll_interval=self.snmp_poll_interval,
        )

        logger.info(
            "Starting TACACS+ Server (%s:%d) and SNMP Poller Daemon (interval: %.1fs)...",
            self.tacacs_host,
            self.tacacs_port,
            self.snmp_poll_interval,
        )

        # Launch concurrent background tasks
        tacacs_task = asyncio.create_task(self.tacacs_server.start())
        snmp_task = asyncio.create_task(self.snmp_poller.run_forever())

        try:
            await self.shutdown_event.wait()
        finally:
            logger.info("Shutdown signaled. Gracefully stopping daemons...")
            if self.tacacs_server:
                await self.tacacs_server.stop()
            if self.snmp_poller:
                self.snmp_poller.stop()

            # Wait for tasks to exit
            for task in (tacacs_task, snmp_task):
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
            logger.info("All enterprise daemons stopped cleanly.")

    def stop(self) -> None:
        """Signals shutdown event."""
        self.shutdown_event.set()


def main() -> None:
    db_path = os.environ.get("NMS_DB_PATH", DEFAULT_DB_PATH)
    tacacs_port = int(os.environ.get("TACACS_PORT", "49"))
    tacacs_host = os.environ.get("TACACS_HOST", "0.0.0.0")
    poll_interval = float(os.environ.get("SNMP_POLL_INTERVAL", "15.0"))

    supervisor = DaemonSupervisor(
        db_path=db_path,
        tacacs_port=tacacs_port,
        tacacs_host=tacacs_host,
        snmp_poll_interval=poll_interval,
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _sig_handler():
        logger.info("Signal received. Triggering supervisor shutdown...")
        supervisor.stop()

    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _sig_handler)
            except NotImplementedError:
                pass

    try:
        loop.run_until_complete(supervisor.start())
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received.")
        supervisor.stop()
        loop.run_until_complete(asyncio.sleep(0.5))
    finally:
        loop.close()


if __name__ == "__main__":
    main()
