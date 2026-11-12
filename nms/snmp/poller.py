# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Background Poller Daemon: High-concurrency telemetry and health polling loop,
vendor-specific health indicator extraction, daemon heartbeat recording, and clean shutdown.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
import json
import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from nms.common.db import DEFAULT_DB_PATH, get_db_connection
from nms.snmp.alarms import AlarmEngine
from nms.snmp.mibs import get_vendor_adapter
from nms.snmp.telemetry import InterfaceSample, TelemetryEngine
from nms.snmp.webhooks import WebhookManager

logger = logging.getLogger("snmp.poller")

# Standard OIDs
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"

# IF-MIB 32-bit & 64-bit HC OID Prefixes
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
OID_IF_IN_UCAST = "1.3.6.1.2.1.2.2.1.11"
OID_IF_OUT_UCAST = "1.3.6.1.2.1.2.2.1.17"
OID_IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
OID_IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
OID_IF_IN_DISCARDS = "1.3.6.1.2.1.2.2.1.13"
OID_IF_OUT_DISCARDS = "1.3.6.1.2.1.2.2.1.19"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"

OID_IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
OID_IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
OID_IF_HC_IN_UCAST = "1.3.6.1.2.1.31.1.1.1.7"
OID_IF_HC_OUT_UCAST = "1.3.6.1.2.1.31.1.1.1.11"


@dataclass
class PollerDaemonMetrics:
    """Operational metrics tracked by the SNMP poller daemon."""
    uptime_seconds: int = 0
    cycles_completed: int = 0
    last_poll_duration_sec: float = 0.0
    devices_total: int = 0
    devices_online: int = 0
    devices_offline: int = 0
    interfaces_monitored: int = 0
    error_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SnmpPollerDaemon:
    """Continuous background polling daemon for universal multi-vendor SNMP infrastructure."""

    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        poll_interval: float = 15.0,
        concurrency: int = 30,
        client: Any = None,
        webhook_manager: Optional[WebhookManager] = None,
    ) -> None:
        self.db_path = db_path
        self.poll_interval = poll_interval
        self.concurrency = concurrency
        self.running: bool = False
        self.start_time: float = 0.0

        # Subsystems
        self.telemetry = TelemetryEngine()
        self.alarms = AlarmEngine()
        self.webhooks = webhook_manager or WebhookManager()
        self.client = client

        # Operational state
        self.consecutive_failures: Dict[int, int] = {}
        self.metrics = PollerDaemonMetrics()

    async def run_forever(self) -> None:
        """Main async daemon execution loop."""
        self.running = True
        self.start_time = time.time()
        logger.info(
            "SNMP Poller Daemon started (PID: %d, interval: %.1fs)",
            os.getpid(),
            self.poll_interval,
        )

        if self.client is None:
            from nms.snmp.engine import SnmpClient
            self.client = SnmpClient()

        # Load existing active alarms into cache
        conn = get_db_connection(self.db_path)
        try:
            self.alarms.load_active_alarms_from_db(conn)
        finally:
            conn.close()

        try:
            while self.running:
                cycle_start = time.time()

                # 1. Update daemon heartbeat
                self._update_heartbeat(status="RUNNING")

                # 2. Execute single poll cycle
                await self.poll_cycle()

                # 3. Calculate cycle timing and metrics
                cycle_duration = time.time() - cycle_start
                self.metrics.last_poll_duration_sec = round(cycle_duration, 3)
                self.metrics.cycles_completed += 1
                self.metrics.uptime_seconds = int(time.time() - self.start_time)

                # 4. Sleep for remainder of poll interval
                sleep_sec = max(0.1, self.poll_interval - cycle_duration)
                try:
                    await asyncio.sleep(sleep_sec)
                except asyncio.CancelledError:
                    break

        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.info("SNMP Poller Daemon received cancellation signal.")
        finally:
            self.running = False
            self._update_heartbeat(status="STOPPED")
            logger.info("SNMP Poller Daemon cleanly stopped.")

    def stop(self) -> None:
        """Triggers graceful shutdown of the poller loop."""
        self.running = False

    def _update_heartbeat(self, status: str = "RUNNING") -> None:
        """Writes daemon heartbeat to SQLite daemon_status table."""
        try:
            conn = get_db_connection(self.db_path)
            with conn:
                conn.execute(
                    """
                    INSERT INTO daemon_status (daemon_name, last_heartbeat, pid, status, metrics_json)
                    VALUES ('snmp_daemon', CURRENT_TIMESTAMP, ?, ?, ?)
                    ON CONFLICT(daemon_name) DO UPDATE SET
                        last_heartbeat = CURRENT_TIMESTAMP,
                        pid = excluded.pid,
                        status = excluded.status,
                        metrics_json = excluded.metrics_json
                    """,
                    (os.getpid(), status, json.dumps(self.metrics.to_dict())),
                )
            conn.close()
        except Exception as exc:
            logger.error("Failed to update daemon_status heartbeat: %s", exc)

    async def poll_cycle(self) -> None:
        """Polls all active devices concurrently using a bounded semaphore worker pool."""
        conn = get_db_connection(self.db_path)
        devices: List[sqlite3.Row] = []
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM snmp_devices WHERE status != 'DISABLED'")
            devices = cursor.fetchall()
        finally:
            conn.close()

        self.metrics.devices_total = len(devices)
        if not devices:
            return

        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self._poll_device_guarded(device, semaphore) for device in devices]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        online_count = sum(1 for r in results if r is True)
        offline_count = sum(1 for r in results if r is False)
        self.metrics.devices_online = online_count
        self.metrics.devices_offline = offline_count

    async def _poll_device_guarded(self, device_row: sqlite3.Row, semaphore: asyncio.Semaphore) -> bool:
        async with semaphore:
            try:
                return await self.poll_device(device_row)
            except Exception as err:
                logger.warning("Error polling device %s: %s", device_row["ip"], err)
                self.metrics.error_count += 1
                return False

    async def poll_device(self, device_row: sqlite3.Row) -> bool:
        """Polls connectivity, IF-MIB telemetry, and vendor health metrics for a single device."""
        device_id = device_row["id"]
        ip = device_row["ip"]
        port = device_row["port"] or 161
        version = device_row["version"] or "v2c"
        vendor = device_row["vendor"] or "Generic"

        common_snmp: Dict[str, Any] = {
            "ip": ip,
            "port": port,
            "version": version,
            "timeout": 2.0,
            "retries": 1,
        }
        if version == "v2c":
            common_snmp["community"] = device_row["community"] or "public"
        else:
            common_snmp.update({
                "v3_user": device_row["v3_user"] or "",
                "v3_auth_proto": device_row["v3_auth_proto"] or "",
                "v3_auth_key": device_row["v3_auth_key"] or "",
                "v3_priv_proto": device_row["v3_priv_proto"] or "",
                "v3_priv_key": device_row["v3_priv_key"] or "",
            })

        conn = get_db_connection(self.db_path)
        try:
            # 1. Reachability & Uptime Check
            sys_uptime: Optional[int] = None
            try:
                res = await self.client.get(oids=[SYS_UPTIME], **common_snmp)
                if res and SYS_UPTIME in res and res[SYS_UPTIME] is not None:
                    sys_uptime = int(res[SYS_UPTIME])
            except Exception:
                sys_uptime = None

            is_reachable = (sys_uptime is not None)

            # Evaluate Reachability Alarms
            def on_alarm_event(evt: Dict[str, Any]) -> None:
                asyncio.create_task(
                    self.webhooks.dispatch_alarm(
                        device_id=evt["device_id"],
                        device_name=device_row["sys_name"] or ip,
                        device_ip=ip,
                        alarm_type=evt["alarm_type"],
                        severity=evt["severity"],
                        message=evt["message"],
                        if_name=None,
                        if_index=evt["if_index"],
                        is_resolved=evt["is_resolved"],
                    )
                )

            self.alarms.evaluate_reachability(
                conn=conn,
                device_id=device_id,
                device_name=device_row["sys_name"] or ip,
                is_reachable=is_reachable,
                timeout_threshold=3,
                on_alarm_change=on_alarm_event,
            )

            if not is_reachable:
                self.consecutive_failures[device_id] = self.consecutive_failures.get(device_id, 0) + 1
                if self.consecutive_failures[device_id] >= 3:
                    conn.execute(
                        "UPDATE snmp_devices SET status = 'OFFLINE' WHERE id = ?",
                        (device_id,),
                    )
                conn.commit()
                return False

            self.consecutive_failures[device_id] = 0
            conn.execute(
                "UPDATE snmp_devices SET status = 'ONLINE', last_seen = CURRENT_TIMESTAMP WHERE id = ?",
                (device_id,),
            )
            conn.commit()

            # 2. Fetch Interface List for Device
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM snmp_interfaces WHERE device_id = ?", (device_id,))
            interfaces = cursor.fetchall()
            self.metrics.interfaces_monitored += len(interfaces)

            # 3. IF-MIB Telemetry Polling
            now = time.time()
            for iface in interfaces:
                idx = iface["if_index"]
                if_name = iface["if_name"] or iface["if_descr"] or f"if{idx}"
                admin_status = iface["if_admin_status"] or 1
                if_speed = iface["if_speed"] or 0

                oids_to_fetch = [
                    f"{OID_IF_HC_IN_OCTETS}.{idx}",
                    f"{OID_IF_HC_OUT_OCTETS}.{idx}",
                    f"{OID_IF_IN_OCTETS}.{idx}",
                    f"{OID_IF_OUT_OCTETS}.{idx}",
                    f"{OID_IF_HC_IN_UCAST}.{idx}",
                    f"{OID_IF_HC_OUT_UCAST}.{idx}",
                    f"{OID_IF_IN_UCAST}.{idx}",
                    f"{OID_IF_OUT_UCAST}.{idx}",
                    f"{OID_IF_IN_ERRORS}.{idx}",
                    f"{OID_IF_OUT_ERRORS}.{idx}",
                    f"{OID_IF_IN_DISCARDS}.{idx}",
                    f"{OID_IF_OUT_DISCARDS}.{idx}",
                    f"{OID_IF_OPER_STATUS}.{idx}",
                    f"{OID_IF_ADMIN_STATUS}.{idx}",
                ]

                try:
                    vbinds = await self.client.get(oids=oids_to_fetch, **common_snmp)
                    if not vbinds:
                        continue

                    # Check 64-bit HC octets
                    hc_in_key = f"{OID_IF_HC_IN_OCTETS}.{idx}"
                    is_64bit = hc_in_key in vbinds and vbinds[hc_in_key] is not None and not str(vbinds[hc_in_key]).startswith("NO_SUCH")

                    if is_64bit:
                        in_octets = int(vbinds.get(f"{OID_IF_HC_IN_OCTETS}.{idx}", 0) or 0)
                        out_octets = int(vbinds.get(f"{OID_IF_HC_OUT_OCTETS}.{idx}", 0) or 0)
                        in_pkts = int(vbinds.get(f"{OID_IF_HC_IN_UCAST}.{idx}", 0) or 0)
                        out_pkts = int(vbinds.get(f"{OID_IF_HC_OUT_UCAST}.{idx}", 0) or 0)
                    else:
                        in_octets = int(vbinds.get(f"{OID_IF_IN_OCTETS}.{idx}", 0) or 0)
                        out_octets = int(vbinds.get(f"{OID_IF_OUT_OCTETS}.{idx}", 0) or 0)
                        in_pkts = int(vbinds.get(f"{OID_IF_IN_UCAST}.{idx}", 0) or 0)
                        out_pkts = int(vbinds.get(f"{OID_IF_OUT_UCAST}.{idx}", 0) or 0)

                    in_errors = int(vbinds.get(f"{OID_IF_IN_ERRORS}.{idx}", 0) or 0)
                    out_errors = int(vbinds.get(f"{OID_IF_OUT_ERRORS}.{idx}", 0) or 0)
                    in_discards = int(vbinds.get(f"{OID_IF_IN_DISCARDS}.{idx}", 0) or 0)
                    out_discards = int(vbinds.get(f"{OID_IF_OUT_DISCARDS}.{idx}", 0) or 0)
                    oper_status = int(vbinds.get(f"{OID_IF_OPER_STATUS}.{idx}", iface["if_oper_status"] or 1) or 1)
                    curr_admin = int(vbinds.get(f"{OID_IF_ADMIN_STATUS}.{idx}", admin_status) or 1)

                    sample = InterfaceSample(
                        timestamp=now,
                        sys_uptime=sys_uptime or 0,
                        in_octets=in_octets,
                        out_octets=out_octets,
                        in_pkts=in_pkts,
                        out_pkts=out_pkts,
                        in_errors=in_errors,
                        out_errors=out_errors,
                        in_discards=in_discards,
                        out_discards=out_discards,
                        is_64bit=is_64bit,
                        if_speed=if_speed,
                    )

                    rates = self.telemetry.process_interface_sample(device_id, idx, sample)
                    if rates:
                        self.telemetry.persist_telemetry(conn, rates)

                    # Evaluate Link Down Alarms
                    self.alarms.evaluate_link_status(
                        conn=conn,
                        device_id=device_id,
                        if_index=idx,
                        if_name=if_name,
                        oper_status=oper_status,
                        admin_status=curr_admin,
                        on_alarm_change=on_alarm_event,
                    )

                    conn.execute(
                        "UPDATE snmp_interfaces SET if_oper_status = ?, if_admin_status = ? WHERE device_id = ? AND if_index = ?",
                        (oper_status, curr_admin, device_id, idx),
                    )
                    conn.commit()

                except Exception as if_err:
                    logger.debug("Failed telemetry poll on dev %d if %d: %s", device_id, idx, if_err)

            # 4. Vendor Health Metrics Polling
            await self._poll_vendor_health(conn, device_id, vendor, common_snmp, sys_uptime or 0, on_alarm_event)

            return True
        finally:
            conn.close()

    async def _poll_vendor_health(
        self,
        conn: sqlite3.Connection,
        device_id: int,
        vendor: str,
        common_snmp: Dict[str, Any],
        sys_uptime: int,
        on_alarm_event: Any,
    ) -> None:
        """Collects vendor-specific CPU, RAM, and Temperature indicators using VendorAdapter."""
        adapter = get_vendor_adapter(vendor)
        health_oids = adapter.get_health_oids()

        cpu_pct: float = 0.0
        mem_pct: float = 0.0
        temp_c: Optional[float] = None

        try:
            res = await self.client.get(oids=health_oids, **common_snmp)
            if res and not res.is_error:
                metrics = adapter.parse_health_metrics(dict(res.items()))
                cpu_pct = metrics.cpu_percent
                mem_pct = metrics.memory_percent
                temp_c = metrics.temperature_c
        except Exception as health_err:
            logger.debug("Failed vendor health poll on device %d: %s", device_id, health_err)

        uptime_seconds = int(sys_uptime / 100.0) if sys_uptime else 0

        # Persist health metrics
        self.telemetry.persist_health(
            conn=conn,
            device_id=device_id,
            cpu_percent=cpu_pct,
            memory_percent=mem_pct,
            temperature_c=temp_c,
            uptime_seconds=uptime_seconds,
        )

        # Evaluate CPU threshold alarms
        self.alarms.evaluate_metric_threshold(
            conn=conn,
            device_id=device_id,
            metric_name="CPU",
            current_val=cpu_pct,
            warn_thresh=80.0,
            crit_thresh=90.0,
            deadband_pct=10.0,
            on_alarm_change=on_alarm_event,
        )

        # Evaluate Memory threshold alarms
        if mem_pct > 0.0:
            self.alarms.evaluate_metric_threshold(
                conn=conn,
                device_id=device_id,
                metric_name="RAM",
                current_val=mem_pct,
                warn_thresh=85.0,
                crit_thresh=95.0,
                deadband_pct=10.0,
                on_alarm_change=on_alarm_event,
            )

        # Evaluate Temperature threshold alarms
        if temp_c is not None:
            self.alarms.evaluate_metric_threshold(
                conn=conn,
                device_id=device_id,
                metric_name="TEMP",
                current_val=temp_c,
                warn_thresh=65.0,
                crit_thresh=75.0,
                deadband_pct=5.0,
                on_alarm_change=on_alarm_event,
            )

        conn.commit()
