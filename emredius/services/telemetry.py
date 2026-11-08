# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Host telemetry (/proc based): CPU, RAM, swap, disk, network I/O, GPU/OS info, plus the 12-hour history
collector thread and its query."""
import logging
import os
import platform
import shutil
import threading
import time
from datetime import datetime

from ..core import format_bytes, get_db, run_cmd

log = logging.getLogger(__name__)

_cpu = {"idle": 0.0, "total": 0.0, "time": 0.0, "usage": 0.0}
_net = {"rx_bytes": 0, "tx_bytes": 0, "time": 0.0, "rx_rate_str": "0.0 KB/s", "tx_rate_str": "0.0 KB/s"}
_lock = threading.Lock()
HISTORY_RANGES = {
    "15m": (15 * 60, "%H:%M:%S"), "30m": (30 * 60, "%H:%M:%S"), "1h": (3600, "%H:%M"),
    "3h": (3 * 3600, "%H:%M"), "6h": (6 * 3600, "%H:%M"), "12h": (12 * 3600, "%H:%M"),
}
HISTORY_INTERVAL = 30


def _read_cpu():
    with open("/proc/stat", "r") as f:
        parts = [float(x) for x in f.readline().split()[1:8]]
    return parts[3] + parts[4], sum(parts)


def cpu_percent():
    """CPU usage from /proc/stat deltas (cached between calls)."""
    try:
        with _lock:
            idle, total = _read_cpu()
            now = time.time()
            if _cpu["total"] == 0:
                time.sleep(0.08)
                idle2, total2 = _read_cpu()
                usage = 100.0 * (1.0 - (idle2 - idle) / (total2 - total)) if total2 > total else 0.0
                _cpu.update(idle=idle2, total=total2, time=time.time(), usage=max(0.0, min(100.0, round(usage, 1))))
            elif now - _cpu["time"] >= 0.4 and total > _cpu["total"]:
                usage = 100.0 * (1.0 - (idle - _cpu["idle"]) / (total - _cpu["total"]))
                _cpu.update(idle=idle, total=total, time=now, usage=max(0.0, min(100.0, round(usage, 1))))
            return _cpu["usage"]
    except (OSError, ValueError, IndexError, ZeroDivisionError):
        return 0.0


def meminfo():
    mem = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    mem[parts[0].strip()] = int(parts[1].strip().split()[0])
    except (OSError, ValueError, IndexError):
        pass
    return mem


def os_info():
    name = "Linux"
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    name = line.split("=", 1)[1].strip().strip('"')
                    break
    except OSError:
        pass
    return f"{name} • Kernel {platform.release()} ({platform.machine()})"


_GPU_IDS = (("VMware SVGA II Adapter", ("15AD:0405", "vmwgfx")), ("NVIDIA Graphics Adapter", ("10DE:", "nouveau", "nvidia")),
            ("Intel HD/UHD Graphics Adapter", ("8086:", "i915")), ("AMD Radeon Graphics Adapter", ("1002:", "amdgpu", "radeon")),
            ("VirtIO-GPU Sanal Grafik Kartı", ("1AF4:", "virtio")), ("QEMU / Bochs Standart VGA", ("1234:1111", "bochs")))


def gpu_info():
    name, driver, res = "Standart Linux Ekran / Framebuffer", "Standart DRM/FB", "1280x800 (32 bpp)"
    try:
        if os.path.exists("/sys/class/graphics/fb0/virtual_size"):
            with open("/sys/class/graphics/fb0/virtual_size") as f:
                res = f.read().strip().replace(",", "x") + " (32 bpp)"
        elif os.path.exists("/sys/class/graphics/fb0/modes"):
            with open("/sys/class/graphics/fb0/modes") as f:
                m = f.readline().strip()
                if m:
                    res = m.split(":")[-1]
    except OSError:
        pass
    try:
        cards = [c for c in os.listdir("/sys/class/drm") if c.startswith("card") and "-" not in c]
        if cards:
            dev = os.path.join("/sys/class/drm", cards[0], "device")
            if os.path.exists(os.path.join(dev, "driver")):
                driver = os.path.basename(os.readlink(os.path.join(dev, "driver")))
            with open(os.path.join(dev, "uevent")) as f:
                uevent = f.read()
            for label, needles in _GPU_IDS:
                if any(n in uevent for n in needles):
                    name = label
                    break
    except OSError:
        pass
    rc, out, _ = run_cmd(["lspci"], timeout=2)
    if rc == 0:
        for line in out.splitlines():
            if any(k in line.lower() for k in ("vga compatible", "3d controller", "display controller")):
                parts = line.split(":", 2)
                if len(parts) >= 3:
                    name = parts[2].strip()
                    break
    return {"name": name, "driver": driver, "resolution": res, "status": "Aktif / Çalışıyor",
            "acceleration": "Donanımsal 2D / 3D Hızlandırma Aktif" if driver != "Standart DRM/FB" else "Temel Ekran Çıktısı"}


def _rate(kbps):
    return f"{kbps / 1024:.2f} MB/s" if kbps >= 1024 else f"{kbps:.1f} KB/s"


def network_io():
    rx_total = tx_total = 0
    ifaces = []
    try:
        with open("/proc/net/dev", "r") as f:
            for line in f:
                if ":" in line:
                    iface, stats = line.split(":", 1)
                    iface = iface.strip()
                    if iface == "lo":
                        continue
                    cols = stats.split()
                    rx_total += int(cols[0])
                    tx_total += int(cols[8])
                    ifaces.append(iface)
    except (OSError, ValueError, IndexError):
        pass
    now = time.time()
    with _lock:
        if _net["time"] > 0 and now - _net["time"] >= 0.4:
            dt = now - _net["time"]
            _net["rx_rate_str"] = _rate(max(0, rx_total - _net["rx_bytes"]) / dt / 1024.0)
            _net["tx_rate_str"] = _rate(max(0, tx_total - _net["tx_bytes"]) / dt / 1024.0)
        _net.update(rx_bytes=rx_total, tx_bytes=tx_total, time=now)
        return {"rx_mb": round(rx_total / 1048576, 1), "tx_mb": round(tx_total / 1048576, 1),
                "iface": ", ".join(ifaces[:2]) or "Tüm Arayüzler", "rx_rate": _net["rx_rate_str"],
                "tx_rate": _net["tx_rate_str"]}


def _mem_summary(mem):
    total = round(mem.get("MemTotal", 0) / 1024, 1)
    avail = round(mem.get("MemAvailable", 0) / 1024, 1)
    used = round(total - avail, 1)
    swap_total = round(mem.get("SwapTotal", 0) / 1024, 1)
    swap_free = round(mem.get("SwapFree", 0) / 1024, 1)
    swap_used = round(swap_total - swap_free, 1)
    return {
        "ram": {"total_mb": total, "used_mb": used, "free_mb": round(mem.get("MemFree", 0) / 1024, 1), "avail_mb": avail,
                "buff_cache_mb": round((mem.get("Buffers", 0) + mem.get("Cached", 0)) / 1024, 1),
                "used_pct": round(used / total * 100, 1) if total > 0 else 0.0},
        "swap": {"total_mb": swap_total, "used_mb": swap_used, "free_mb": swap_free,
                 "used_pct": round(swap_used / swap_total * 100, 1) if swap_total > 0 else 0.0},
    }


def _radius_summary():
    data = {"total_users": 0, "active_sessions": 0, "total_nas": 0, "total_bytes": 0, "traffic_formatted": "0 B"}
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(DISTINCT username) AS n FROM radcheck WHERE attribute = 'Cleartext-Password'")
                data["total_users"] = cur.fetchone()["n"] or 0
                cur.execute("SELECT COUNT(*) AS n FROM radacct WHERE acctstoptime IS NULL")
                data["active_sessions"] = cur.fetchone()["n"] or 0
                cur.execute("SELECT COUNT(*) AS n FROM nas")
                data["total_nas"] = cur.fetchone()["n"] or 0
                cur.execute("SELECT SUM(acctinputoctets) AS up, SUM(acctoutputoctets) AS down FROM radacct")
                tr = cur.fetchone()
                total = int(tr["up"] or 0) + int(tr["down"] or 0)
                data["total_bytes"], data["traffic_formatted"] = total, format_bytes(total)
        finally:
            conn.close()
    except Exception as e:
        log.debug("telemetry radius summary: %s", e)
    return data


def snapshot():
    cpu_model = "Standart Çok Çekirdekli İşlemci"
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "model name" in line:
                    cpu_model = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    try:
        load_avg = [round(x, 2) for x in os.getloadavg()]
    except OSError:
        load_avg = [0.0, 0.0, 0.0]
    try:
        tasks = len([p for p in os.listdir("/proc") if p.isdigit()])
    except OSError:
        tasks = 0
    uptime = "Bilinmiyor"
    try:
        with open("/proc/uptime", "r") as f:
            secs = float(f.readline().split()[0])
        uptime = f"{int(secs // 3600)} sa {int((secs % 3600) // 60)} dk"
    except (OSError, ValueError, IndexError):
        pass
    disk = shutil.disk_usage("/")
    data = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "os_info": os_info(),
        "cpu": {"percent": cpu_percent(), "cores": os.cpu_count() or 1, "model": cpu_model, "load_avg": load_avg,
                "tasks": tasks},
        "disk": {"total_gb": round(disk.total / 1024 ** 3, 2), "used_gb": round(disk.used / 1024 ** 3, 2),
                 "free_gb": round(disk.free / 1024 ** 3, 2),
                 "used_pct": round(disk.used / disk.total * 100, 1) if disk.total > 0 else 0.0, "mount": "/"},
        "gpu": gpu_info(),
        "net": network_io(),
        "radius": _radius_summary(),
        "uptime": uptime,
    }
    data.update(_mem_summary(meminfo()))
    return data


# ---------- 12-hour history ----------

def record_history_point():
    m = _mem_summary(meminfo())
    try:
        disk_used = round(shutil.disk_usage("/").used / 1024 ** 3, 2)
    except OSError:
        disk_used = 0.0
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO system_telemetry_history (recorded_at, cpu_percent, ram_used_mb, ram_avail_mb, ram_pct, "
                        "swap_used_mb, disk_used_gb) VALUES (NOW(), %s, %s, %s, %s, %s, %s)",
                        (cpu_percent(), m["ram"]["used_mb"], m["ram"]["avail_mb"], m["ram"]["used_pct"],
                         m["swap"]["used_mb"], disk_used))
            cur.execute("DELETE FROM system_telemetry_history WHERE recorded_at < NOW() - INTERVAL 12 HOUR")
    finally:
        conn.close()


_history_thread = {"started": False}


def start_history_collector():
    """Background thread writing one telemetry point every 30 s (started once from create_app)."""
    if _history_thread["started"]:
        return
    _history_thread["started"] = True

    def _worker():
        while True:
            time.sleep(HISTORY_INTERVAL)
            try:
                record_history_point()
            except Exception as e:
                log.debug("telemetry history: %s", e)
    threading.Thread(target=_worker, daemon=True, name="TelemetryHistory").start()


def history(range_key):
    """(range_key, points)"""
    if range_key not in HISTORY_RANGES:
        range_key = "15m"
    seconds, fmt = HISTORY_RANGES[range_key]
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT recorded_at, cpu_percent, ram_used_mb, ram_avail_mb, ram_pct, swap_used_mb, disk_used_gb "
                        "FROM system_telemetry_history WHERE recorded_at >= NOW() - INTERVAL %s SECOND "
                        "ORDER BY recorded_at ASC", (seconds,))
            rows = cur.fetchall()
    finally:
        conn.close()
    points = []
    for r in rows:
        t = r["recorded_at"]
        points.append({
            "time": t.strftime(fmt) if isinstance(t, datetime) else str(t),
            "cpu": round(float(r["cpu_percent"]), 1), "ram_used": round(float(r["ram_used_mb"]), 1),
            "ram_avail": round(float(r["ram_avail_mb"]), 1), "ram_pct": round(float(r["ram_pct"]), 1),
            "swap": round(float(r["swap_used_mb"]), 1), "disk_used": round(float(r["disk_used_gb"]), 2),
        })
    return range_key, points
