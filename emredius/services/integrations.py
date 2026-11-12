# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Entegrasyonlar ve bildirim kanalları: Telegram/Slack (Sistem Ayarları), SMTP (Servis Sağlığı) durumu + genel webhook.
Genel webhook varsayılan KAPALI (int_webhook_enabled=0); uyarılar JSON olarak POST edilir, gizli anahtar varsa HMAC-SHA256 imzalanır."""
import hashlib
import hmac
import json
import logging
import re
import threading
import urllib.request

from ..core import get_setting, notify, set_setting
from . import svchealth

log = logging.getLogger(__name__)
URL_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?(/[\x21-\x7e]{0,500})?$")
DEFAULTS = {"int_webhook_enabled": "0", "int_webhook_url": ""}


def channels():
    """Kanal özeti (gizli değer göstermez)."""
    smtp = svchealth.get_settings()
    return [
        {"name": "Telegram", "configured": bool(get_setting("telegram_bot_token") and get_setting("telegram_chat_id")),
         "enabled": None, "link": "/settings"},
        {"name": "Slack / Discord webhook", "configured": bool(get_setting("slack_webhook_url") or get_setting("discord_webhook_url")),
         "enabled": None, "link": "/settings"},
        {"name": "E-posta (SMTP)", "configured": bool(smtp["svchealth_smtp_host"] and smtp["svchealth_mail_to"]),
         "enabled": smtp["svchealth_email_enabled"] == "1", "link": "/svchealth"},
        {"name": "Genel webhook", "configured": bool(get_setting("int_webhook_url")),
         "enabled": get_setting("int_webhook_enabled", "0") == "1", "link": "/integrations"},
    ]


def get_settings():
    d = {k: get_setting(k, v) for k, v in DEFAULTS.items()}
    d["secret_set"] = bool(get_setting("int_webhook_secret"))
    return d


def save_settings(form):
    url, enabled = (form.get("int_webhook_url") or "").strip(), bool(form.get("int_webhook_enabled"))
    if url and not URL_RE.match(url):
        return "Webhook URL http(s):// ile başlamalı ve boşluk içermemeli."
    if enabled and not url:
        return "Etkinleştirmek için webhook URL gerekli."
    set_setting("int_webhook_url", url)
    set_setting("int_webhook_enabled", "1" if enabled else "0")
    secret = (form.get("int_webhook_secret") or "").strip()
    if form.get("int_webhook_secret_clear"):
        set_setting("int_webhook_secret", "")
    elif secret:
        set_setting("int_webhook_secret", secret[:200])
    return None


def post_webhook(message, source="alert", force=False):
    """-> (ok, mesaj). Kapalıysa (force=False) gönderilmez."""
    if not force and get_setting("int_webhook_enabled", "0") != "1":
        return False, "Webhook kapalı."
    url = get_setting("int_webhook_url")
    if not url:
        return False, "Webhook URL tanımlı değil."
    body = json.dumps({"source": "emredius", "type": source, "message": message}, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "EMREDIUS-Notifier"}
    secret = get_setting("int_webhook_secret")
    if secret:
        headers["X-Emredius-Signature"] = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    try:
        urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers), timeout=5).close()
    except Exception as e:  # noqa: BLE001
        return False, "Gönderilemedi: %s" % str(e)[:100]
    return True, "Gönderildi."


def _on_alert(message):
    if get_setting("int_webhook_enabled", "0") == "1":
        threading.Thread(target=post_webhook, args=(message,), daemon=True, name="WebhookSender").start()


def register():
    notify.add_listener(_on_alert)
