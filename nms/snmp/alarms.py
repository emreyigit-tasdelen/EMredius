# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Stateful Alarm Engine: Evaluates operational thresholds, link-down transitions,
device timeouts, 10% hysteresis deadbands, interface flap damping, and WAL persistence.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import logging
import sqlite3
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger("snmp.alarms")


@dataclass
class FlapRecord:
    """Sliding-window flapping tracker for a single network interface."""
    transitions: Deque[Tuple[float, int]] = field(default_factory=deque)
    is_damped: bool = False
    damped_at: float = 0.0
    last_oper_status: Optional[int] = None


class AlarmEngine:
    """Evaluates stateful alarms with hysteresis and flap damping."""

    def __init__(
        self,
        flap_window_sec: float = 300.0,
        flap_max_transitions: int = 4,
        flap_damp_duration_sec: float = 300.0,
    ) -> None:
        self.flap_window_sec = flap_window_sec
        self.flap_max_transitions = flap_max_transitions
        self.flap_damp_duration_sec = flap_damp_duration_sec

        # Flap state: self._flap_state[(device_id, if_index)] = FlapRecord
        self._flap_state: Dict[Tuple[int, int], FlapRecord] = {}

        # Device consecutive timeout tracker: self._unreachable_counts[device_id] = count
        self._unreachable_counts: Dict[int, int] = {}

        # In-memory tracking of currently active alarms:
        # self._active_alarms[(device_id, if_index, alarm_type)] = (severity, message)
        self._active_alarms: Dict[Tuple[int, Optional[int], str], Tuple[str, str]] = {}

    def load_active_alarms_from_db(self, conn: sqlite3.Connection) -> None:
        """Initializes in-memory active alarm cache from SQLite database on startup."""
        cursor = conn.cursor()
        cursor.execute("SELECT device_id, if_index, alarm_type, severity, message FROM alarms WHERE resolved = 0")
        for row in cursor.fetchall():
            key = (row["device_id"], row["if_index"], row["alarm_type"])
            self._active_alarms[key] = (row["severity"], row["message"])

    def evaluate_link_status(
        self,
        conn: sqlite3.Connection,
        device_id: int,
        if_index: int,
        if_name: str,
        oper_status: int,      # 1=up, 2=down, 7=lowerLayerDown
        admin_status: int,     # 1=up, 2=down
        on_alarm_change: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        """Evaluates interface operational transitions with flap damping and admin down suppression."""
        now = time.time()
        key = (device_id, if_index)
        flap_rec = self._flap_state.setdefault(key, FlapRecord())

        # If adminStatus is DOWN (2), administratively shut down; suppress alarms
        if admin_status == 2:
            self._resolve_alarm(
                conn, device_id, if_index, "LINK_DOWN", f"Interface {if_name} is administratively down.", on_alarm_change
            )
            flap_rec.last_oper_status = oper_status
            return

        prev_status = flap_rec.last_oper_status
        flap_rec.last_oper_status = oper_status

        if prev_status is not None and prev_status != oper_status:
            # Operational state transition occurred! Record transition
            flap_rec.transitions.append((now, oper_status))

            # Prune transitions older than sliding window
            cutoff = now - self.flap_window_sec
            while flap_rec.transitions and flap_rec.transitions[0][0] < cutoff:
                flap_rec.transitions.popleft()

            # Check if flapping threshold reached
            if len(flap_rec.transitions) >= self.flap_max_transitions and not flap_rec.is_damped:
                flap_rec.is_damped = True
                flap_rec.damped_at = now
                msg = f"Interface {if_name} (index {if_index}) flapping detected ({len(flap_rec.transitions)} transitions in {int(self.flap_window_sec)}s). Notifications damped."
                self._trigger_alarm(conn, device_id, if_index, "PORT_FLAPPING", "WARNING", msg, on_alarm_change)

        # Check if flap damping should clear (stabilized for damp_duration)
        if flap_rec.is_damped:
            if now - flap_rec.damped_at >= self.flap_damp_duration_sec:
                flap_rec.is_damped = False
                flap_rec.transitions.clear()
                self._resolve_alarm(
                    conn,
                    device_id,
                    if_index,
                    "PORT_FLAPPING",
                    f"Interface {if_name} stabilized. Flap damping released.",
                    on_alarm_change,
                )

        # If currently damped, suppress link notifications
        if flap_rec.is_damped:
            return

        # Normal link down / link up evaluation
        if oper_status in (2, 7):  # Down or lowerLayerDown
            msg = f"Interface {if_name} (index {if_index}) is DOWN."
            self._trigger_alarm(conn, device_id, if_index, "LINK_DOWN", "CRITICAL", msg, on_alarm_change)
        elif oper_status == 1:  # Up
            self._resolve_alarm(
                conn, device_id, if_index, "LINK_DOWN", f"Interface {if_name} is UP.", on_alarm_change
            )

    def evaluate_metric_threshold(
        self,
        conn: sqlite3.Connection,
        device_id: int,
        metric_name: str,      # 'CPU' or 'RAM' or 'TEMP'
        current_val: float,
        warn_thresh: float,
        crit_thresh: float,
        deadband_pct: float = 10.0,
        on_alarm_change: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        """Evaluates health metric against thresholds with 10% hysteresis deadband.

        Deadband logic:
        - Critical triggers at crit_thresh; demotes to warning when < (crit_thresh - deadband).
        - Warning triggers at warn_thresh; clears when < (warn_thresh - deadband).
        """
        alarm_type = f"HIGH_{metric_name}"
        alarm_key = (device_id, None, alarm_type)
        current_active = self._active_alarms.get(alarm_key)

        # Deadband values
        warn_clear = warn_thresh - deadband_pct
        crit_demote = crit_thresh - (deadband_pct * (crit_thresh / 100.0))

        if current_val >= crit_thresh:
            msg = f"{metric_name} utilization critical: {current_val:.1f}% (threshold {crit_thresh:.1f}%)"
            self._trigger_alarm(conn, device_id, None, alarm_type, "CRITICAL", msg, on_alarm_change)
        elif current_active and current_active[0] == "CRITICAL":
            # Currently in CRITICAL state
            if current_val < warn_clear:
                self._resolve_alarm(
                    conn,
                    device_id,
                    None,
                    alarm_type,
                    f"{metric_name} utilization normal: {current_val:.1f}% (below {warn_clear:.1f}%)",
                    on_alarm_change,
                )
            elif current_val < crit_demote:
                msg = f"{metric_name} utilization warning: {current_val:.1f}% (demoted from critical)"
                self._trigger_alarm(conn, device_id, None, alarm_type, "WARNING", msg, on_alarm_change)
            # Else: current_val >= crit_demote -> maintain CRITICAL
        elif current_active and current_active[0] == "WARNING":
            # Currently in WARNING state
            if current_val < warn_clear:
                self._resolve_alarm(
                    conn,
                    device_id,
                    None,
                    alarm_type,
                    f"{metric_name} utilization normal: {current_val:.1f}% (below {warn_clear:.1f}%)",
                    on_alarm_change,
                )
            # Else: current_val >= warn_clear -> maintain WARNING
        else:
            # Currently NORMAL (no active alarm)
            if current_val >= warn_thresh:
                msg = f"{metric_name} utilization warning: {current_val:.1f}% (threshold {warn_thresh:.1f}%)"
                self._trigger_alarm(conn, device_id, None, alarm_type, "WARNING", msg, on_alarm_change)

    def evaluate_reachability(
        self,
        conn: sqlite3.Connection,
        device_id: int,
        device_name: str,
        is_reachable: bool,
        timeout_threshold: int = 3,
        on_alarm_change: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        """Evaluates consecutive SNMP timeouts and triggers DEVICE_UNREACHABLE alarm."""
        if not is_reachable:
            self._unreachable_counts[device_id] = self._unreachable_counts.get(device_id, 0) + 1
            count = self._unreachable_counts[device_id]
            if count >= timeout_threshold:
                msg = f"Device {device_name} is UNREACHABLE across {count} consecutive polling cycles."
                self._trigger_alarm(conn, device_id, None, "DEVICE_UNREACHABLE", "CRITICAL", msg, on_alarm_change)
        else:
            self._unreachable_counts[device_id] = 0
            self._resolve_alarm(
                conn,
                device_id,
                None,
                "DEVICE_UNREACHABLE",
                f"Device {device_name} is reachable and responding.",
                on_alarm_change,
            )

    def _trigger_alarm(
        self,
        conn: sqlite3.Connection,
        device_id: int,
        if_index: Optional[int],
        alarm_type: str,
        severity: str,
        message: str,
        on_alarm_change: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        key = (device_id, if_index, alarm_type)
        existing = self._active_alarms.get(key)

        if existing and existing[0] == severity:
            # Already active at same severity; do not duplicate database row
            return

        cursor = conn.cursor()
        if existing:
            # Severity escalated or changed; update active record
            cursor.execute(
                """
                UPDATE alarms SET severity = ?, message = ?, timestamp = CURRENT_TIMESTAMP
                WHERE device_id = ? AND (if_index = ? OR (if_index IS NULL AND ? IS NULL))
                  AND alarm_type = ? AND resolved = 0
                """,
                (severity, message, device_id, if_index, if_index, alarm_type),
            )
        else:
            # Insert new active alarm
            cursor.execute(
                """
                INSERT INTO alarms (device_id, if_index, alarm_type, severity, message, resolved)
                VALUES (?, ?, ?, ?, ?, 0)
                """,
                (device_id, if_index, alarm_type, severity, message),
            )

        self._active_alarms[key] = (severity, message)
        if on_alarm_change:
            on_alarm_change({
                "device_id": device_id,
                "if_index": if_index,
                "alarm_type": alarm_type,
                "severity": severity,
                "message": message,
                "is_resolved": False,
            })

    def _resolve_alarm(
        self,
        conn: sqlite3.Connection,
        device_id: int,
        if_index: Optional[int],
        alarm_type: str,
        resolve_message: str,
        on_alarm_change: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        key = (device_id, if_index, alarm_type)
        if key not in self._active_alarms:
            return

        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE alarms SET resolved = 1, resolved_at = CURRENT_TIMESTAMP
            WHERE device_id = ? AND (if_index = ? OR (if_index IS NULL AND ? IS NULL))
              AND alarm_type = ? AND resolved = 0
            """,
            (device_id, if_index, if_index, alarm_type),
        )

        old_severity, _ = self._active_alarms.pop(key)
        if on_alarm_change:
            on_alarm_change({
                "device_id": device_id,
                "if_index": if_index,
                "alarm_type": alarm_type,
                "severity": "INFO",
                "message": resolve_message,
                "is_resolved": True,
            })
