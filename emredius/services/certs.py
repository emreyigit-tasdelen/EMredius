# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Sertifikalar: EAP (RADIUS), web paneli ve CA sertifikalarının geçerlilik takibi. Yalnızca okur; özel anahtara dokunmaz.
Süre sonu uyarısı eşiği `cert_warn_days`; dışarı bildirim `cert_alert_enabled` (varsayılan KAPALI)."""
import time
from datetime import datetime, timezone

from cryptography import x509

from ..core import get_setting, send_alert, set_setting
from . import svchealth

CERTS = [
    {"key": "eap", "name": "EAP sunucu sertifikası (RADIUS)", "path": "/etc/raddb/certs/server.pem"},
    {"key": "web", "name": "Web paneli sertifikası (HTTPS)", "path": "/etc/ssl/radius/server.crt"},
    {"key": "ca", "name": "Kök CA sertifikası", "path": "/etc/raddb/certs/ca.pem"},
]
DEFAULT_WARN = 30


def warn_days():
    try:
        return min(365, max(1, int(get_setting("cert_warn_days", str(DEFAULT_WARN)))))
    except ValueError:
        return DEFAULT_WARN


def inspect(path, now=None, warn=DEFAULT_WARN):
    """-> dict(status ok|warn|expired|missing|error, subject, issuer, not_after, days_left, serial, sans)."""
    now = now or datetime.now(timezone.utc)
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return {"status": "missing", "error": "dosya yok"}
    except OSError as e:
        return {"status": "error", "error": str(e)[:100]}
    try:
        cert = x509.load_pem_x509_certificate(data)  # çok bloklu PEM'de ilk sertifika
    except Exception:  # noqa: BLE001
        return {"status": "error", "error": "geçerli PEM sertifika değil"}
    end = cert.not_valid_after_utc
    days = (end - now).days
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    status = "expired" if end <= now else ("warn" if days <= warn else "ok")
    return {"status": status, "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.strftime("%d.%m.%Y"), "not_after": end.strftime("%d.%m.%Y"),
            "days_left": days, "serial": format(cert.serial_number, "x"), "sans": sans}


def snapshot(now=None):
    w = warn_days()
    return [dict(c, **inspect(c["path"], now, w)) for c in CERTS]


def get_settings():
    return {"cert_warn_days": str(warn_days()), "cert_alert_enabled": get_setting("cert_alert_enabled", "0")}


def save_settings(form):
    try:
        d = int(form.get("cert_warn_days") or "")
    except ValueError:
        return "Uyarı eşiği 1-365 gün olmalı."
    if not 1 <= d <= 365:
        return "Uyarı eşiği 1-365 gün olmalı."
    set_setting("cert_warn_days", str(d))
    set_setting("cert_alert_enabled", "1" if form.get("cert_alert_enabled") else "0")
    return None


def notify_expiring(rows=None):
    """Süresi yaklaşan/dolan sertifikalar için uyarı gönderir (anahtar kapalıysa hiçbir şey göndermez). -> mesaj sayısı"""
    if get_setting("cert_alert_enabled", "0") != "1":
        return 0
    n = 0
    for r in rows or snapshot():
        if r["status"] in ("warn", "expired"):
            send_alert("⚠️ [SERTİFİKA] %s: %s" % (r["name"], "SÜRESİ DOLDU" if r["status"] == "expired" else "%d gün kaldı" % r["days_left"]))
            n += 1
    return n


_last_notify = [0.0]


def _daily(rows, now):
    """Servis sağlığı yoklaması içinden günde en çok bir kez süre sonu uyarısı."""
    if now - _last_notify[0] >= 86400:
        _last_notify[0] = now
        notify_expiring()


def register():
    svchealth.add_listener(_daily)
