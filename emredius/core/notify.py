# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Alert notifications (Telegram + Slack/Discord webhook), dispatched off the request thread."""
import json
import logging
import threading
import urllib.parse
import urllib.request

from .settings import get_setting

log = logging.getLogger(__name__)

_listeners = []  # fn(message); ek bildirim kanalları (genel webhook) kaydeder


def add_listener(fn):
    if fn not in _listeners:
        _listeners.append(fn)


def _send_alert_sync(message):
    bot_token = get_setting("telegram_bot_token")
    chat_id = get_setting("telegram_chat_id")
    if bot_token and chat_id:
        try:
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            data = urllib.parse.urlencode({"chat_id": chat_id, "text": message, "parse_mode": "HTML"}).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"User-Agent": "FreeRADIUS-Notifier"})
            urllib.request.urlopen(req, timeout=5).close()
        except Exception as e:
            log.warning("Telegram error: %s", e)

    webhook_url = get_setting("slack_webhook_url") or get_setting("discord_webhook_url")
    if webhook_url and webhook_url.startswith("https://"):
        try:
            payload = json.dumps({"text": message, "content": message}).encode("utf-8")
            req = urllib.request.Request(webhook_url, data=payload, headers={
                "Content-Type": "application/json", "User-Agent": "FreeRADIUS-Notifier"})
            urllib.request.urlopen(req, timeout=5).close()
        except Exception as e:
            log.warning("Webhook error: %s", e)


def send_alert(message):
    """Non-blocking notification dispatch (never delays the request that triggered it)."""
    for fn in list(_listeners):
        try:
            fn(message)
        except Exception as e:  # noqa: BLE001
            log.warning("alert listener error: %s", e)
    try:
        threading.Thread(target=_send_alert_sync, args=(message,), daemon=True, name="AlertSender").start()
    except Exception as e:
        log.error("send_alert error: %s", e)
