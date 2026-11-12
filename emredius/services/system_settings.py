# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Panel settings (notifications, voucher branding, API token) and host settings (DNS, sshd, firewalld, timezone)."""
import re

from ..core import get_api_token, get_setting, is_dry_run, is_valid_ip, run_cmd, set_setting
from .radius_users import ServiceError

TIMEZONES = [("Europe/Istanbul", "Europe/Istanbul (UTC+3)"), ("UTC", "UTC (GMT)"), ("Europe/London", "Europe/London")]
TELEGRAM_TOKEN_RE = re.compile(r"^\d{5,15}:[A-Za-z0-9_-]{20,64}$")
CHAT_ID_RE = re.compile(r"^-?\d{1,20}$|^@[A-Za-z0-9_]{5,64}$")
WEBHOOK_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:\d{1,5})?/[\x21-\x7e]{0,500}$")
API_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.~-]{16,128}$")
TEXT_MAX = 64


def page_values():
    return {
        "bot_token": get_setting("telegram_bot_token", ""),
        "chat_id": get_setting("telegram_chat_id", ""),
        "slack_wh": get_setting("slack_webhook_url", ""),
        "brand": get_setting("company_brand_name", "Kurumsal Ağ Güvenliği"),
        "ssid": get_setting("company_ssid_name", "Sirket-WiFi-Secure"),
        "api_token": get_api_token(),
    }


def validate_notifications(form):
    """-> (errors, values) for the Telegram / Slack form; empty values disable a channel."""
    d = {k: (form.get(k) or "").strip() for k in ("telegram_bot_token", "telegram_chat_id", "slack_webhook_url")}
    errors = []
    if d["telegram_bot_token"] and not TELEGRAM_TOKEN_RE.match(d["telegram_bot_token"]):
        errors.append("Telegram Bot Token biçimi geçersiz (örn: 123456789:ABC...).")
    if d["telegram_chat_id"] and not CHAT_ID_RE.match(d["telegram_chat_id"]):
        errors.append("Telegram Chat ID sayısal olmalı (veya @kanal_adi).")
    if d["slack_webhook_url"] and not WEBHOOK_RE.match(d["slack_webhook_url"]):
        errors.append("Webhook URL https:// ile başlamalı ve boşluk içermemeli.")
    return errors, d


def validate_branding(form):
    d = {k: (form.get(k) or "").strip() for k in ("company_brand_name", "company_ssid_name", "api_token")}
    errors = []
    if not d["company_brand_name"] or len(d["company_brand_name"]) > TEXT_MAX:
        errors.append(f"Kurum başlığı 1-{TEXT_MAX} karakter olmalı.")
    if not d["company_ssid_name"] or len(d["company_ssid_name"].encode("utf-8")) > 32:
        errors.append("SSID adı 1-32 bayt olmalı.")
    if d["api_token"] and not API_TOKEN_RE.match(d["api_token"]):
        errors.append("API anahtarı 16-128 karakter olmalı (harf, rakam, - _ . ~).")
    return errors, d


def save(values):
    for k, v in values.items():
        if k == "api_token" and not v:
            continue  # empty field keeps the current token
        set_setting(k, v)


# ---------- host settings ----------

def read_dns(resolv_conf):
    servers = []
    try:
        with open(resolv_conf, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    return (servers + ["", ""])[:2]


def write_dns(resolv_conf, dns1, dns2):
    dns1, dns2 = (dns1 or "").strip(), (dns2 or "").strip()
    if not dns1:
        raise ServiceError("Birincil DNS sunucu IP adresi zorunludur.")
    for v in filter(None, (dns1, dns2)):
        if not is_valid_ip(v):
            raise ServiceError(f"Geçersiz DNS sunucu IP adresi: {v}")
    if is_dry_run():
        raise ServiceError("[staging] /etc/resolv.conf SYSTEM_DRY_RUN modunda değiştirilmez.")
    text = f"# Managed by EMredius\nnameserver {dns1}\n" + (f"nameserver {dns2}\n" if dns2 else "")
    try:
        with open(resolv_conf, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        raise ServiceError(f"DNS dosyası yazılamadı: {e}")
    return dns1, dns2


def reload_ssh():
    """(ok, message): reload first (keeps sessions), restart as fallback."""
    rc, _, err = run_cmd(["systemctl", "reload", "sshd"])
    if rc == 0:
        return True, "SSH Daemon (sshd) konfigürasyonu kesintisiz yeniden yüklendi."
    rc2, _, err2 = run_cmd(["systemctl", "restart", "sshd"])
    if rc2 == 0:
        return True, "SSH Daemon (sshd) başarıyla yeniden başlatıldı."
    return False, f"SSH servisi yenilenemedi: {err2 or err}"


def reload_firewall():
    rc, _, err = run_cmd(["firewall-cmd", "--reload"])
    if rc == 0:
        return True, "FirewallD güvenlik duvarı kuralları başarıyla yeniden yüklendi."
    return False, f"FirewallD yenilenemedi: {err}"


def set_timezone(tz):
    if tz not in dict(TIMEZONES):
        return False, "Geçersiz zaman dilimi."
    rc, _, err = run_cmd(["timedatectl", "set-timezone", tz])
    if rc == 0:
        return True, f"Sistem zaman dilimi başarıyla '{tz}' olarak ayarlandı."
    return False, f"Zaman dilimi değiştirilemedi: {err}"


def current_timezone():
    rc, out, _ = run_cmd(["timedatectl", "show", "-p", "Timezone", "--value"])
    return out.strip() if rc == 0 and out.strip() else "Europe/Istanbul"
