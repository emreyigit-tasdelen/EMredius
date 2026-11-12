# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Webhook Dispatchers: Asynchronous non-blocking delivery of alert notifications
to Telegram Bot API and Slack Incoming Webhooks without external dependencies.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("snmp.webhooks")


async def async_http_post(
    url: str,
    json_data: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
) -> Tuple[int, str]:
    """Asynchronous HTTP POST using standard library urllib within asyncio.to_thread."""

    def _do_post() -> Tuple[int, str]:
        req_headers = {
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "Enterprise-NMS-Webhook/1.0",
        }
        if headers:
            req_headers.update(headers)
        data_bytes = json.dumps(json_data).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=req_headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status = response.status
                body = response.read().decode("utf-8", errors="replace")
                return status, body
        except urllib.error.HTTPError as err:
            body = err.read().decode("utf-8", errors="replace")
            return err.code, body
        except Exception as err:
            logger.error("HTTP POST to %s failed: %s", url, err)
            return 0, str(err)

    return await asyncio.to_thread(_do_post)


class TelegramDispatcher:
    """Async Telegram Bot API Alert Dispatcher."""

    def __init__(self, bot_token: str, chat_id: str) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"

    def format_message(
        self,
        severity: str,
        alarm_type: str,
        device_name: str,
        device_ip: str,
        if_name: Optional[str],
        message: str,
        is_resolved: bool,
    ) -> str:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if is_resolved:
            emoji = "✅"
            header = f"{emoji} *[RESOLVED] ALARM CLEARED*"
        elif severity == "CRITICAL":
            emoji = "🚨"
            header = f"{emoji} *[CRITICAL] ALARM TRIGGERED*"
        else:
            emoji = "⚠️"
            header = f"{emoji} *[WARNING] ALARM TRIGGERED*"

        lines = [
            header,
            "",
            f"*Device*: {device_name} (`{device_ip}`)",
            f"*Alarm*: `{alarm_type}`",
        ]
        if if_name:
            lines.append(f"*Interface*: `{if_name}`")
        lines.extend([
            f"*Details*: {message}",
            f"*Timestamp*: {now_str}",
            "",
            "_Enterprise TACACS+ & SNMP NMS_",
        ])
        return "\n".join(lines)

    async def send_alarm(
        self,
        severity: str,
        alarm_type: str,
        device_name: str,
        device_ip: str,
        if_name: Optional[str],
        message: str,
        is_resolved: bool = False,
    ) -> bool:
        text = self.format_message(severity, alarm_type, device_name, device_ip, if_name, message, is_resolved)
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        status, body = await async_http_post(self.api_url, payload)
        if status == 200:
            logger.info("Telegram alert sent successfully for %s on %s", alarm_type, device_name)
            return True

        if status == 429:  # Rate limit
            try:
                data = json.loads(body)
                retry_after = data.get("parameters", {}).get("retry_after", 3)
                logger.warning("Telegram 429 rate limit hit. Retrying after %d seconds.", retry_after)
                await asyncio.sleep(retry_after)
                status, _ = await async_http_post(self.api_url, payload)
                return status == 200
            except Exception:
                pass

        logger.error("Failed to send Telegram alert: HTTP %d - %s", status, body)
        return False


class SlackDispatcher:
    """Async Slack Incoming Webhook Alert Dispatcher."""

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def format_payload(
        self,
        severity: str,
        alarm_type: str,
        device_name: str,
        device_ip: str,
        if_name: Optional[str],
        message: str,
        is_resolved: bool,
    ) -> Dict[str, Any]:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if is_resolved:
            color = "#388E3C"  # Green
            emoji = "✅"
            header_text = f"{emoji} RESOLVED: {alarm_type}"
        elif severity == "CRITICAL":
            color = "#D32F2F"  # Red
            emoji = "🚨"
            header_text = f"{emoji} CRITICAL: {alarm_type}"
        else:
            color = "#FFA000"  # Amber
            emoji = "⚠️"
            header_text = f"{emoji} WARNING: {alarm_type}"

        fields = [
            {"type": "mrkdwn", "text": f"*Device:*\n{device_name} ({device_ip})"},
            {"type": "mrkdwn", "text": f"*Alarm Type:*\n{alarm_type}"},
            {"type": "mrkdwn", "text": f"*Severity:*\n{severity if not is_resolved else 'RESOLVED'}"},
            {"type": "mrkdwn", "text": f"*Timestamp:*\n{now_str}"},
        ]
        if if_name:
            fields.insert(2, {"type": "mrkdwn", "text": f"*Interface:*\n{if_name}"})

        return {
            "text": f"[{severity if not is_resolved else 'RESOLVED'}] {alarm_type} on {device_name}",
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {"type": "plain_text", "text": header_text},
                        },
                        {"type": "section", "fields": fields},
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*Message:*\n{message}"},
                        },
                    ],
                }
            ],
        }

    async def send_alarm(
        self,
        severity: str,
        alarm_type: str,
        device_name: str,
        device_ip: str,
        if_name: Optional[str],
        message: str,
        is_resolved: bool = False,
    ) -> bool:
        payload = self.format_payload(severity, alarm_type, device_name, device_ip, if_name, message, is_resolved)
        status, body = await async_http_post(self.webhook_url, payload)
        if status == 200:
            logger.info("Slack alert sent successfully for %s on %s", alarm_type, device_name)
            return True
        logger.error("Failed to send Slack alert: HTTP %d - %s", status, body)
        return False


class WebhookManager:
    """Unified manager dispatching notifications to all configured webhook channels."""

    def __init__(
        self,
        telegram_token: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
        slack_webhook_url: Optional[str] = None,
    ) -> None:
        self.telegram = (
            TelegramDispatcher(telegram_token, telegram_chat_id)
            if telegram_token and telegram_chat_id
            else None
        )
        self.slack = SlackDispatcher(slack_webhook_url) if slack_webhook_url else None
        self._last_dispatched: Dict[Tuple[int, Optional[int], str, str], float] = {}

    async def dispatch_alarm(
        self,
        device_id: int,
        device_name: str,
        device_ip: str,
        alarm_type: str,
        severity: str,
        message: str,
        if_name: Optional[str] = None,
        if_index: Optional[int] = None,
        is_resolved: bool = False,
    ) -> Dict[str, bool]:
        """Dispatches an alarm event across configured Telegram and Slack targets concurrently."""
        tasks = []
        labels = []

        if self.telegram:
            tasks.append(
                self.telegram.send_alarm(
                    severity, alarm_type, device_name, device_ip, if_name, message, is_resolved
                )
            )
            labels.append("telegram")

        if self.slack:
            tasks.append(
                self.slack.send_alarm(
                    severity, alarm_type, device_name, device_ip, if_name, message, is_resolved
                )
            )
            labels.append("slack")

        if not tasks:
            return {}

        results = await asyncio.gather(*tasks, return_exceptions=True)
        outcome = {}
        for label, res in zip(labels, results):
            outcome[label] = bool(res is True)
        return outcome
