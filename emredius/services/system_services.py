# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Managed systemd services: status, journal tail, restart (with a radiusd -C pre-check), probes, server reboot."""
import os
import socket
import threading
import time
from datetime import datetime

from ..core import invalidate_radiusd_status, run_cmd

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SERVICES = {
    "radiusd": {
        "name": "FreeRADIUS AAA Servisi", "unit": "radiusd.service", "icon": "fa-tower-broadcast",
        "color": "#2563eb", "bg_color": "#eff6ff", "port": "UDP 1812 / 1813",
        "desc": "RADIUS Authentication & Accounting motoru (Port 1812 / 1813). Ağ cihazları ve Wi-Fi kimlik "
                "doğrulamalarını yönetir.",
        "paths": ["/etc/raddb", "/var/log/radius", "/usr/sbin/radiusd", "/usr/lib64/freeradius"],
    },
    "enterprise-daemons": {
        "name": "TACACS+ & SNMP NMS Motoru", "unit": "emredius-nms.service", "icon": "fa-shield-halved",
        "color": "#7c3aed", "bg_color": "#f5f3ff", "port": "TCP 49 / SNMP Poller",
        "desc": "RFC 8907 uyumlu TACACS+ AAA motoru (Port 49) ve evrensel çok markalı SNMP telemetri/poller arka plan "
                "servisi.",
        "paths": [os.path.join(_PROJECT_DIR, "nms"), "/var/log/enterprise_tacacs_nms"],
    },
    # key kept for the page JS; the unit is this panel's own (PANEL_UNIT)
    "radius-admin": {
        "name": "Web Yönetim Paneli", "unit": None, "icon": "fa-gauge-high",
        "color": "#059669", "bg_color": "#ecfdf5", "port": "TCP 5000 / HTTP",
        "desc": "FreeRADIUS Enterprise yönetim konsolu, dinamik RBAC, REST API ve oturum yönetim web sunucusu.",
        "paths": [os.path.join(_PROJECT_DIR, "emredius")],
    },
    "mariadb": {
        "name": "MariaDB Veritabanı Servisi", "unit": "mariadb.service", "icon": "fa-database",
        "color": "#d97706", "bg_color": "#fffbeb", "port": "TCP 3306 / SQL",
        "desc": "Kullanıcı hesapları, RADIUS muhasebe kayıtları (radacct), TACACS+ denetim izleri ve NMS telemetri "
                "veritabanı.",
        "paths": ["/var/lib/mysql", "/var/log/mariadb"],
    },
    "chronyd": {
        "name": "Chrony NTP Zaman Servisi", "unit": "chronyd.service", "icon": "fa-clock",
        "color": "#0284c7", "bg_color": "#e0f2fe", "port": "UDP 123 / NTP",
        "desc": "AlmaLinux sistem zamanını mikrosaniye hassasiyetinde NTP havuzları ile senkronize eder.",
        "paths": ["/var/lib/chrony", "/etc/chrony.conf", "/usr/sbin/chronyd"],
    },
}
PANEL_KEY = "radius-admin"
_panel_unit = {"unit": "emredius-panel.service"}
STORAGE_CACHE_TTL = 300  # walking /var/lib/mysql is expensive; disk usage changes slowly
_storage_cache = {}


def configure(panel_unit):
    _panel_unit["unit"] = panel_unit or "emredius-panel.service"


def unit_of(key):
    return _panel_unit["unit"] if key == PANEL_KEY else SERVICES[key]["unit"]


def _fmt_size(total):
    if total >= 1024 ** 3:
        return f"{total / 1024 ** 3:.2f} GB"
    if total >= 1024 ** 2:
        return f"{total / 1024 ** 2:.1f} MB"
    if total >= 1024:
        return f"{total / 1024:.1f} KB"
    return f"{total} B" if total > 0 else "-"


def storage_usage(key):
    now = time.time()
    cached = _storage_cache.get(key)
    if cached and now - cached[0] < STORAGE_CACHE_TTL:
        return cached[1]
    total = 0
    for p in SERVICES[key]["paths"]:
        if os.path.isfile(p):
            try:
                total += os.path.getsize(p)
            except OSError:
                pass
        elif os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for f in files:
                    try:
                        total += os.lstat(os.path.join(root, f)).st_size  # never follow symlinks out of the tree
                    except OSError:
                        pass
    formatted = _fmt_size(total)
    _storage_cache[key] = (now, formatted)
    return formatted


def detail(key):
    info = SERVICES.get(key)
    if not info:
        return None
    unit = unit_of(key)
    _, out, _ = run_cmd(["systemctl", "show", "-p", "ActiveState,SubState,MainPID,MemoryCurrent,ActiveEnterTimestamp", unit])
    props = {}
    for line in (out or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    try:
        mem = int(props.get("MemoryCurrent", "0"))
        memory = f"{mem / 1024 / 1024:.1f} MB" if mem > 0 else "-"
    except ValueError:
        memory = "-"
    return {
        "key": key, "name": info["name"], "unit": unit, "icon": info["icon"], "color": info["color"],
        "bg_color": info["bg_color"], "desc": info["desc"], "port": info["port"],
        "is_active": props.get("ActiveState") == "active", "substate": props.get("SubState", "unknown"),
        "pid": props.get("MainPID", "-"), "memory": memory, "storage": storage_usage(key),
        "uptime": props.get("ActiveEnterTimestamp", "-"),
    }


def all_details():
    return {k: detail(k) for k in SERVICES}


def _tail_text_file(path, max_lines=35, max_bytes=65536):
    """Last max_lines non-empty lines of a (possibly huge) file, reading only its tail."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            start = max(0, f.tell() - max_bytes)
            f.seek(start)
            data = f.read(max_bytes)
    except OSError:
        return []
    lines = data.decode("utf-8", errors="replace").splitlines()
    if start > 0 and lines:
        lines = lines[1:]  # first line is probably cut in half
    return [ln.strip() for ln in lines[-max_lines:] if ln.strip()]


def logs(key):
    if key not in SERVICES:
        return []
    lines = _tail_text_file("/var/log/radius/radius.log") if key == "radiusd" else []
    _, out, _ = run_cmd(["journalctl", "-u", unit_of(key), "-n", "40", "--no-pager"])
    for ln in (out or "").splitlines():
        ln = ln.strip()
        if ln and not ln.startswith(("-- Logs begin", "-- No entries")):
            lines.append(ln)
    return lines


def _delayed_systemctl(args, delay):
    """`systemctl <args>` in the background after `delay` s (when the action kills the process answering the request)."""
    def _worker():
        time.sleep(delay)
        run_cmd(["systemctl"] + list(args), timeout=60)
    threading.Thread(target=_worker, daemon=True, name="DelayedSystemctl").start()


def check_radiusd_config():
    """(ok, message): never restart FreeRADIUS into a broken configuration."""
    rc, out, err = run_cmd(["radiusd", "-C"], timeout=30)
    if rc == 0:
        return True, ""
    detail_lines = (err or out or "").strip().splitlines()
    return False, ("FreeRADIUS yapılandırma kontrolü (radiusd -C) başarısız, servis yeniden başlatılmadı: "
                   + (detail_lines[-1] if detail_lines else f"Hata kodu: {rc}"))


def restart(key):
    """(ok, message)"""
    if key not in SERVICES:
        return False, "Geçersiz servis adı."
    unit = unit_of(key)
    if key == PANEL_KEY:
        # --no-block: the restart job is queued in systemd and survives this process being stopped
        _delayed_systemctl(["--no-block", "restart", unit], 1)
        return True, "Web yönetim paneli yeniden başlatılıyor. Sayfa 4 saniye içinde otomatik yenilenecektir."
    if key == "radiusd":
        ok, msg = check_radiusd_config()
        if not ok:
            return False, msg
    rc, out, err = run_cmd(["systemctl", "restart", unit], timeout=90)
    if key == "radiusd":
        invalidate_radiusd_status()
    if rc == 0:
        return True, f"{SERVICES[key]['name']} ({unit}) başarıyla yeniden başlatıldı."
    return False, f"Servis yeniden başlatılamadı: {err or out or 'Hata kodu: ' + str(rc)}"


def restart_radiusd():
    """/restart-radius: (ok, message)"""
    ok, msg = check_radiusd_config()
    if not ok:
        return False, msg
    rc, _, err = run_cmd(["systemctl", "restart", "radiusd"], timeout=60)
    invalidate_radiusd_status()
    if rc == 0:
        return True, "FreeRADIUS servisi başarıyla yeniden başlatıldı."
    return False, f"Servis yeniden başlatılamadı: {err[-300:]}"


def probe(key, mysql_defaults_file):
    """Liveness probe for one service: (success, message, output_or_None)."""
    ts = datetime.now().strftime("%H:%M:%S")
    if key == "radiusd":
        rc, out, err = run_cmd(["radtest", "live_ping_user", "LiveTestPass2026", "127.0.0.1", "0", "testing123"], timeout=4)
        return True, f"[{ts}] Canlı RADIUS Access-Request paketi localhost:1812'ye iletildi.", out or err
    if key == "enterprise-daemons":
        try:
            with socket.create_connection(("127.0.0.1", 49), timeout=2.0):
                ok, msg = True, "Port 49 (TACACS+) açık ve aktif dinliyor."
        except OSError:
            ok, msg = False, "Port 49 kapalı."
        return ok, f"[{ts}] TACACS+ TCP 49 Probe: {msg}", None
    if key == "chronyd":
        rc, out, err = run_cmd(["chronyc", "-h", "127.0.0.1", "-n", "activity"], timeout=5)  # UDP: see chrony.py
        txt = (out or "").strip() if rc == 0 else ((err or out or "").strip() or f"Hata kodu: {rc}")
        return rc == 0, f"[{ts}] Chrony NTP: {txt or 'OK'}", None
    if key == "mariadb":
        # credentials come from the client defaults file, never from the command line
        rc, out, err = run_cmd(["mysqladmin", f"--defaults-extra-file={mysql_defaults_file}", "ping"], timeout=5)
        txt = ((out or "").strip() or "mysqld is alive") if rc == 0 else \
            "HATA: " + ((err or out or "").strip() or f"Hata kodu: {rc}")
        return rc == 0, f"[{ts}] MariaDB Ping: {txt}", None
    return True, f"[{ts}] Web Yönetim Paneli: HTTP/1.1 200 OK", None


def reboot_server():
    _delayed_systemctl(["reboot"], 2)
