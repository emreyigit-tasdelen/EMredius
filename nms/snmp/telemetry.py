# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Telemetry Math Engine: Delta rate computation, 32/64-bit counter wrap handling,
reboot spike prevention, and time-series persistence into SQLite WAL.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("snmp.telemetry")

# Counter rollover constants
WRAP_32 = 4_294_967_296               # 2^32
WRAP_64 = 18_446_744_073_709_551_616  # 2^64


@dataclass
class InterfaceSample:
    """Raw counter sample retrieved from SNMP agent at a given timestamp."""
    timestamp: float           # Wall-clock time (seconds, float)
    sys_uptime: int            # sysUpTime in hundredths of a second (10ms ticks)
    in_octets: int
    out_octets: int
    in_pkts: int = 0
    out_pkts: int = 0
    in_errors: int = 0
    out_errors: int = 0
    in_discards: int = 0
    out_discards: int = 0
    is_64bit: bool = False
    if_speed: int = 0          # Link speed in bps (0 if unknown)


@dataclass
class InterfaceRates:
    """Calculated rates and engineering metrics for an interface."""
    timestamp: float
    device_id: int
    if_index: int
    in_bps: float
    out_bps: float
    in_pps: float
    out_pps: float
    in_errors: float           # errors per second
    out_errors: float          # errors per second
    in_discards: float         # discards per second
    out_discards: float        # discards per second
    in_utilization_pct: float  # 0.0 - 100.0%
    out_utilization_pct: float # 0.0 - 100.0%
    wrapped: bool = False
    rebooted: bool = False


def calculate_counter_delta(
    curr: int,
    prev: int,
    is_64bit: bool = False,
    sys_uptime_curr: Optional[int] = None,
    sys_uptime_prev: Optional[int] = None,
) -> Tuple[int, bool, bool]:
    """Computes non-negative counter delta handling 32/64-bit wrap and reboot reset.

    Returns:
        (delta, wrapped, rebooted)
    """
    # 1. Reboot Detection: sysUpTime decreased
    if (
        sys_uptime_curr is not None
        and sys_uptime_prev is not None
        and sys_uptime_curr < sys_uptime_prev
    ):
        logger.info(
            "Device reboot detected: sysUpTime %d < %d. Suppressing false delta spike.",
            sys_uptime_curr,
            sys_uptime_prev,
        )
        return 0, False, True

    # 2. Monotonic increment (normal case)
    if curr >= prev:
        return curr - prev, False, False

    # 3. Counter Wrap: curr < prev without reboot
    wrap_limit = WRAP_64 if is_64bit else WRAP_32
    delta = (wrap_limit - prev) + curr
    return delta, True, False


class TelemetryEngine:
    """In-memory stateful telemetry calculator and SQLite time-series persistence."""

    def __init__(self) -> None:
        # Cache previous sample: self._samples[device_id][if_index] = InterfaceSample
        self._samples: Dict[int, Dict[int, InterfaceSample]] = {}
        # Cache previous uptime: self._uptimes[device_id] = sys_uptime
        self._uptimes: Dict[int, int] = {}

    def reset_device(self, device_id: int) -> None:
        """Clears state cache for a specific device (e.g. on manual reset)."""
        self._samples.pop(device_id, None)
        self._uptimes.pop(device_id, None)

    def process_interface_sample(
        self, device_id: int, if_index: int, curr_sample: InterfaceSample
    ) -> Optional[InterfaceRates]:
        """Processes a new interface sample and computes high-precision delta rates."""
        dev_samples = self._samples.setdefault(device_id, {})
        prev_sample = dev_samples.get(if_index)
        prev_uptime = self._uptimes.get(device_id)

        # Update cache for next iteration
        dev_samples[if_index] = curr_sample
        self._uptimes[device_id] = curr_sample.sys_uptime

        if prev_sample is None:
            # Baseline reading established; rate cannot be computed until second sample
            return None

        delta_t = curr_sample.timestamp - prev_sample.timestamp
        if delta_t <= 0.0:
            logger.warning("Zero or negative delta_t (%f) on dev %d if %d", delta_t, device_id, if_index)
            return None

        # Check reboot
        uptime_prev = prev_sample.sys_uptime or prev_uptime
        rebooted = (
            curr_sample.sys_uptime is not None
            and uptime_prev is not None
            and curr_sample.sys_uptime < uptime_prev
        )

        # Calculate Octet Deltas
        in_octets_delta, in_wrapped, _ = calculate_counter_delta(
            curr_sample.in_octets,
            prev_sample.in_octets,
            curr_sample.is_64bit,
            curr_sample.sys_uptime,
            uptime_prev,
        )
        out_octets_delta, out_wrapped, _ = calculate_counter_delta(
            curr_sample.out_octets,
            prev_sample.out_octets,
            curr_sample.is_64bit,
            curr_sample.sys_uptime,
            uptime_prev,
        )

        # Calculate Packet Deltas
        in_pkts_delta, _, _ = calculate_counter_delta(
            curr_sample.in_pkts,
            prev_sample.in_pkts,
            curr_sample.is_64bit,
            curr_sample.sys_uptime,
            uptime_prev,
        )
        out_pkts_delta, _, _ = calculate_counter_delta(
            curr_sample.out_pkts,
            prev_sample.out_pkts,
            curr_sample.is_64bit,
            curr_sample.sys_uptime,
            uptime_prev,
        )

        # Calculate Error and Discard Deltas (32-bit standard)
        in_err_delta, _, _ = calculate_counter_delta(
            curr_sample.in_errors,
            prev_sample.in_errors,
            False,
            curr_sample.sys_uptime,
            uptime_prev,
        )
        out_err_delta, _, _ = calculate_counter_delta(
            curr_sample.out_errors,
            prev_sample.out_errors,
            False,
            curr_sample.sys_uptime,
            uptime_prev,
        )
        in_disc_delta, _, _ = calculate_counter_delta(
            curr_sample.in_discards,
            prev_sample.in_discards,
            False,
            curr_sample.sys_uptime,
            uptime_prev,
        )
        out_disc_delta, _, _ = calculate_counter_delta(
            curr_sample.out_discards,
            prev_sample.out_discards,
            False,
            curr_sample.sys_uptime,
            uptime_prev,
        )

        # Rate calculations (bps, pps, errors/sec, discards/sec)
        in_bps = (in_octets_delta * 8.0) / delta_t
        out_bps = (out_octets_delta * 8.0) / delta_t
        in_pps = in_pkts_delta / delta_t
        out_pps = out_pkts_delta / delta_t
        in_errors = in_err_delta / delta_t
        out_errors = out_err_delta / delta_t
        in_discards = in_disc_delta / delta_t
        out_discards = out_disc_delta / delta_t

        # Plausibility filtering: clamp anomalous spikes exceeding 2x line rate
        speed = curr_sample.if_speed or prev_sample.if_speed
        if speed > 0:
            max_bps = speed * 2.0
            if in_bps > max_bps:
                logger.warning("Clamping anomalous in_bps (%f > %f) on dev %d if %d", in_bps, max_bps, device_id, if_index)
                in_bps = 0.0
            if out_bps > max_bps:
                logger.warning("Clamping anomalous out_bps (%f > %f) on dev %d if %d", out_bps, max_bps, device_id, if_index)
                out_bps = 0.0

        # Utilization calculation
        in_util = (in_bps / speed * 100.0) if speed > 0 else 0.0
        out_util = (out_bps / speed * 100.0) if speed > 0 else 0.0

        return InterfaceRates(
            timestamp=curr_sample.timestamp,
            device_id=device_id,
            if_index=if_index,
            in_bps=round(in_bps, 2),
            out_bps=round(out_bps, 2),
            in_pps=round(in_pps, 2),
            out_pps=round(out_pps, 2),
            in_errors=round(in_errors, 2),
            out_errors=round(out_errors, 2),
            in_discards=round(in_discards, 2),
            out_discards=round(out_discards, 2),
            in_utilization_pct=min(round(in_util, 2), 100.0),
            out_utilization_pct=min(round(out_util, 2), 100.0),
            wrapped=(in_wrapped or out_wrapped),
            rebooted=rebooted,
        )

    @staticmethod
    def persist_telemetry(conn: sqlite3.Connection, rates: InterfaceRates) -> None:
        """Persists interface rates into snmp_telemetry table in SQLite WAL mode."""
        conn.execute(
            """
            INSERT INTO snmp_telemetry (
                device_id, if_index, in_bps, out_bps, in_pps, out_pps, in_errors, out_errors
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rates.device_id,
                rates.if_index,
                rates.in_bps,
                rates.out_bps,
                rates.in_pps,
                rates.out_pps,
                rates.in_errors,
                rates.out_errors,
            ),
        )

    @staticmethod
    def persist_health(
        conn: sqlite3.Connection,
        device_id: int,
        cpu_percent: float,
        memory_percent: float,
        temperature_c: Optional[float],
        uptime_seconds: int,
    ) -> None:
        """Persists device health into snmp_health table."""
        conn.execute(
            """
            INSERT INTO snmp_health (
                device_id, cpu_percent, memory_percent, temperature_c, uptime_seconds
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (device_id, cpu_percent, memory_percent, temperature_c, uptime_seconds),
        )
