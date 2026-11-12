# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Servis Sağlığı: systemd servisleri ve TCP uçları yoklanır; servis düşünce e-posta/Telegram alarmı.
Dışarı bildirim gönderen anahtarlar varsayılan KAPALI (svchealth_alert_enabled, svchealth_email_enabled)."""
import logging
import smtplib
import socket
import threading
import time
from datetime import datetime
from email.message import EmailMessage

from ..core import get_setting, is_dry_run, run_cmd, send_alert, set_setting

log = logging.getLogger(__name__)

CHECKS = [
    {"key": "panel", "name": "Web Yönetim Paneli", "kind": "self"},
    {"key": "radiusd", "name": "FreeRADIUS (RADIUS 1812/1813)", "kind": "unit", "unit": "radiusd.service"},
    {"key": "nms", "name": "TACACS+ & SNMP NMS", "kind": "unit", "unit": "emredius-nms.service"},
    {"key": "tacacs", "name": "TACACS+ portu (TCP 49)", "kind": "tcp", "port": 49},
    {"key": "netflow", "name": "NetFlow toplayıcı", "kind": "unit", "unit": "emredius-netflow.service", "optional": True},
    {"key": "mariadb", "name": "MariaDB", "kind": "unit", "unit": "mariadb.service"},
    {"key": "chronyd", "name": "Chrony NTP", "kind": "unit", "unit": "chronyd.service"},
]
SETTING_DEFAULTS = {
    "svchealth_alert_enabled": "0", "svchealth_email_enabled": "0", "svchealth_smtp_host": "",
    "svchealth_smtp_port": "587", "svchealth_smtp_user": "", "svchealth_smtp_password": "",
    "svchealth_smtp_tls": "1", "svchealth_mail_from": "", "svchealth_mail_to": "",
}
SECRET_KEYS = {"svchealth_smtp_password"}
INTERVAL_S = 60
FAILS_BEFORE_ALERT = 2  # ardışık başarısız yoklama (tek seferlik takılmada alarm vermez)

_state = {}
_listeners = []  # fn(rows, now); erişilebilirlik kaydı vb.


def add_listener(fn):
    if fn not in _listeners:
        _listeners.append(fn)
_lock = threading.Lock()


def _unit_status(unit):
    rc, out, _ = run_cmd(["systemctl", "show", "-p", "LoadState,ActiveState", unit], timeout=8)
    props = dict(l.split("=", 1) for l in (out or "").splitlines() if "=" in l)
    if rc != 0 or not props:
        return "unknown", "systemctl okunamadı"
    if props.get("LoadState") == "not-found":
        return "absent", "servis kurulu değil"
    active = props.get("ActiveState", "")
    return ("up" if active == "active" else "down"), active


def _tcp_status(port):
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=2):
            return "up", "bağlantı kabul ediyor"
    except OSError as e:
        return "down", str(e)[:80]


def probe(check):
    if check["kind"] == "self":
        return "up", "yanıt veriyor"
    if check["kind"] == "tcp":
        return _tcp_status(check["port"])
    if is_dry_run():
        return "unknown", "staging (dry-run): systemctl yoklanmaz"
    status, detail = _unit_status(check["unit"])
    if status == "absent" and not check.get("optional"):
        return "down", detail
    return status, detail


def _mark(key, status, detail, now):
    with _lock:
        rec = _state.setdefault(key, {"status": "unknown", "since": now, "fails": 0, "alerted": False})
        prev = rec["status"]
        if status != prev:
            rec["since"] = now
        rec["status"], rec["detail"], rec["checked"] = status, detail, now
        rec["fails"] = rec["fails"] + 1 if status == "down" else 0
        event = None
        if status == "down" and rec["fails"] >= FAILS_BEFORE_ALERT and not rec["alerted"]:
            rec["alerted"], event = True, "down"
        elif status == "up" and rec["alerted"]:
            rec["alerted"], event = False, "up"
        return event


def check_all(now=None, notify=True):
    now = now or time.time()
    events = []
    for c in CHECKS:
        status, detail = probe(c)
        ev = _mark(c["key"], status, detail, now)
        if ev:
            events.append((c, ev, detail))
    if notify:
        for c, ev, detail in events:
            notify_event(c["name"], ev, detail)
    rows = snapshot()
    for fn in list(_listeners):
        try:
            fn(rows, now)
        except Exception as e:  # noqa: BLE001
            log.warning("svchealth listener hatası: %s", e)
    return events


def snapshot():
    with _lock:
        recs = {k: dict(v) for k, v in _state.items()}
    rows = []
    for c in CHECKS:
        r = recs.get(c["key"], {})
        rows.append({"key": c["key"], "name": c["name"], "status": r.get("status", "unknown"),
                     "detail": r.get("detail", "henüz yoklanmadı"),
                     "since": datetime.fromtimestamp(r["since"]).strftime("%d.%m.%Y %H:%M:%S") if r.get("since") else "-"})
    return rows


def summary(rows):
    down = [r for r in rows if r["status"] == "down"]
    return {"total": len(rows), "up": sum(1 for r in rows if r["status"] == "up"), "down": len(down),
            "ok": not down}


# ---------- bildirim ----------
def get_settings():
    return {k: get_setting(k, d) for k, d in SETTING_DEFAULTS.items()}


def save_settings(form):
    for k in SETTING_DEFAULTS:
        if k in ("svchealth_alert_enabled", "svchealth_email_enabled", "svchealth_smtp_tls"):
            set_setting(k, "1" if form.get(k) else "0")
        elif k in SECRET_KEYS:
            if (form.get(k) or "").strip():  # boş bırakılırsa mevcut parola korunur
                set_setting(k, form.get(k).strip()[:200])
        else:
            set_setting(k, (form.get(k) or "").strip()[:200])


def send_email(subject, body, cfg=None):
    cfg = cfg or get_settings()
    to = [a.strip() for a in cfg["svchealth_mail_to"].replace(";", ",").split(",") if a.strip()]
    if not (cfg["svchealth_smtp_host"] and to and cfg["svchealth_mail_from"]):
        return False, "SMTP sunucusu, gönderen ve alıcı adresi gerekli."
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, cfg["svchealth_mail_from"], ", ".join(to)
    msg.set_content(body)
    try:
        port = int(cfg["svchealth_smtp_port"] or 587)
        with smtplib.SMTP(cfg["svchealth_smtp_host"], port, timeout=10) as s:
            if cfg["svchealth_smtp_tls"] == "1":
                s.starttls()
            if cfg["svchealth_smtp_user"]:
                s.login(cfg["svchealth_smtp_user"], cfg["svchealth_smtp_password"])
            s.send_message(msg)
    except Exception as e:  # noqa: BLE001
        log.warning("svchealth e-posta hatası: %s", e)
        return False, "E-posta gönderilemedi: %s" % str(e)[:120]
    return True, "E-posta gönderildi."


def notify_event(name, event, detail=""):
    """Düşme/kurtarma alarmı. Her iki anahtar da kapalıysa hiçbir şey dışarı gönderilmez."""
    cfg = get_settings()
    when = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    text = ("🔴 [SERVİS DÜŞTÜ] %s — %s (%s)" if event == "down" else "🟢 [SERVİS DÜZELDİ] %s — %s (%s)") % (name, detail, when)
    if cfg["svchealth_alert_enabled"] == "1":
        send_alert(text)
    if cfg["svchealth_email_enabled"] == "1":
        threading.Thread(target=send_email, args=("EMREDIUS: " + text[:80], text, cfg), daemon=True).start()


def start_scheduler(interval_s=INTERVAL_S):
    def loop():
        while True:
            try:
                check_all()
            except Exception:  # noqa: BLE001
                log.exception("svchealth yoklama hatası")
            time.sleep(interval_s)
    threading.Thread(target=loop, daemon=True, name="svchealth-scheduler").start()