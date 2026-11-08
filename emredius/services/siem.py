# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""SIEM yönlendirme: yönetici işlem günlüğü olaylarını syslog (RFC 5424) veya CEF olarak UDP/TCP ile dışarı yollar.
Varsayılan KAPALI (siem_enabled=0). Gönderim istek iş parçacığını bekletmez; hata panelde görülür, işlemi bozmaz."""
import logging
import re
import socket
import threading
import time
from datetime import datetime, timezone

from ..core import audit, get_setting, set_setting

log = logging.getLogger(__name__)

DEFAULTS = {"siem_enabled": "0", "siem_host": "", "siem_port": "514", "siem_proto": "udp", "siem_format": "syslog"}
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$|^[0-9a-fA-F:]{2,45}$")
_last = {"ok": None, "msg": "", "at": 0}
_cache = {"at": 0, "cfg": None}


def get_settings():
    return {k: get_setting(k, d) for k, d in DEFAULTS.items()}


def _cfg():
    if time.time() - _cache["at"] > 10 or _cache["cfg"] is None:
        _cache["cfg"], _cache["at"] = get_settings(), time.time()
    return _cache["cfg"]


def save_settings(form):
    host = (form.get("siem_host") or "").strip()
    proto, fmt = form.get("siem_proto"), form.get("siem_format")
    try:
        port = int(form.get("siem_port") or "")
    except ValueError:
        return "Port 1-65535 olmalı."
    enabled = bool(form.get("siem_enabled"))
    if not 1 <= port <= 65535:
        return "Port 1-65535 olmalı."
    if proto not in ("udp", "tcp") or fmt not in ("syslog", "cef"):
        return "Geçersiz protokol veya biçim."
    if enabled and not host:
        return "Etkinleştirmek için SIEM sunucu adresi gerekli."
    if host and not HOST_RE.match(host):
        return "SIEM sunucu adresi geçersiz."
    for k, v in (("siem_enabled", "1" if enabled else "0"), ("siem_host", host), ("siem_port", str(port)),
                 ("siem_proto", proto), ("siem_format", fmt)):
        set_setting(k, v)
    _cache["cfg"] = None
    return None


def _esc(v, header=False):
    v = str(v).replace("\\", "\\\\").replace("\r", " ").replace("\n", " ")
    return v.replace("|", "\\|") if header else v.replace("=", "\\=")


def _sd(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def format_event(fmt, user, action, target="", details="", ip="", host="emredius", when=None):
    when = when or datetime.now(timezone.utc)
    if fmt == "cef":
        return "CEF:0|EMREDIUS|Panel|1.0|%s|%s|3|suser=%s dst=%s msg=%s src=%s rt=%d" % (
            _esc(action, True), _esc(action, True), _esc(user or "Sistem"), _esc(target),
            _esc(details)[:500], _esc(ip), int(when.timestamp() * 1000))
    sd = '[emredius@32473 user="%s" target="%s" ip="%s"]' % (_sd(user or "Sistem"), _sd(target), _sd(ip))
    return "<14>1 %s %s emredius - %s %s %s" % (when.strftime("%Y-%m-%dT%H:%M:%SZ"), host,
                                                 re.sub(r"\s+", "_", str(action))[:32] or "-", sd,
                                                 str(details).replace("\n", " ")[:500])


def send(message, cfg=None):
    """-> (ok, mesaj). Sunucu tanımlı değilse gönderilmez."""
    cfg = cfg or get_settings()
    if not cfg["siem_host"]:
        return False, "SIEM sunucu adresi tanımlı değil."
    data = message.encode("utf-8", "replace")
    try:
        port = int(cfg["siem_port"])
        if cfg["siem_proto"] == "tcp":
            with socket.create_connection((cfg["siem_host"], port), timeout=4) as s:
                s.sendall(data + b"\n")
        else:
            fam = socket.AF_INET6 if ":" in cfg["siem_host"] else socket.AF_INET
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.settimeout(4)
                s.sendto(data, (cfg["siem_host"], port))
    except Exception as e:  # noqa: BLE001
        return False, "Gönderilemedi: %s" % str(e)[:100]
    return True, "Gönderildi."


def _deliver(message, cfg):
    ok, msg = send(message, cfg)
    _last.update(ok=ok, msg=msg, at=time.time())
    if not ok:
        log.warning("SIEM: %s", msg)


def on_audit(user, action, target="", details="", ip=""):
    """Denetim kaydı dinleyicisi; kapalıyken hiçbir şey yapmaz."""
    try:
        cfg = _cfg()
        if cfg["siem_enabled"] != "1" or not cfg["siem_host"]:
            return
        msg = format_event(cfg["siem_format"], user, action, target, details, ip)
        threading.Thread(target=_deliver, args=(msg, cfg), daemon=True, name="SiemSender").start()
    except Exception as e:  # noqa: BLE001
        log.warning("SIEM dinleyici hatası: %s", e)


def last_status():
    return dict(_last)


def register():
    audit.add_listener(on_audit)
