# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""TCP connect port scanner (/portscan). Pure Python (no nmap / root): one connect() per port with a short
timeout, run in a thread pool. A scan runs as a background job (a full 1-65535 scan outlives one HTTP
request); the page polls its progress. Jobs live in process memory (gunicorn runs a single worker).
The total number of simultaneous scans (all administrators together) is a panel setting only the superadmin
can change; an administrator may run several scans at once within that limit (USER_COOLDOWN_SECONDS apart). The last MAX_KEPT_JOBS finished scans stay viewable."""
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from ..core import get_setting, safe_int, set_setting
from ..core.audit import log_admin_action

log = logging.getLogger(__name__)

MAX_PORT = 65535
SMALL_SCAN_WORKERS = 64        # up to 1024 ports
LARGE_SCAN_WORKERS = 256       # bigger ranges (full scan of a silent host: 65535 / 256 x timeout)
TIMEOUT_CHOICES = (0.3, 0.5, 1.0, 2.0)
DEFAULT_TIMEOUT = 0.5
USER_COOLDOWN_SECONDS = 10     # per admin, between two scan starts
MAX_KEPT_JOBS = 20             # finished scans kept in memory (running ones are never dropped)
HISTORY_PER_USER = 20          # finished scans kept on disk per administrator
MAX_CONCURRENT_KEY = "portscan_max_concurrent"
DEFAULT_MAX_CONCURRENT = 2
MAX_CONCURRENT_LIMIT = 16      # a large scan runs LARGE_SCAN_WORKERS connect threads

PRESETS = {
    "common": [21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 161, 389, 443, 445, 465, 514, 587, 636,
               993, 995, 1433, 1521, 1812, 1813, 2049, 3306, 3389, 5060, 5432, 5900, 6379, 8080, 8443,
               8291, 9200, 27017],
    "network": [22, 23, 49, 80, 161, 162, 443, 514, 830, 1812, 1813, 3799, 8080, 8291, 8443, 8728, 8729],
    "well_known": list(range(1, 1025)),
    "all": list(range(1, MAX_PORT + 1)),
}
PRESET_LABELS = {
    "common": "Yaygın servisler",
    "network": "Ağ cihazları (SSH/Telnet/TACACS+/SNMP/RADIUS/Web)",
    "well_known": "1-1024 (iyi bilinen portlar)",
    "all": "Tüm portlar (1-65535)",
}

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
                          r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")
_PORT_SPEC_RE = re.compile(r"^[0-9,\- ]{1,512}$")

_jobs = {}
_lock = threading.Lock()
_hist_lock = threading.Lock()
_last_start = {}


class ScanError(ValueError):
    pass


def resolve_target(raw, allow_public=False):
    """IP literal or hostname -> ip string. Only private/loopback/link-local targets unless allow_public."""
    raw = (raw or "").strip()
    if not raw:
        raise ScanError("Hedef boş olamaz!")
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        if not _HOSTNAME_RE.match(raw):
            raise ScanError("Geçersiz hedef. IP adresi veya alan adı girin (CIDR aralığı desteklenmez).")
        try:
            infos = socket.getaddrinfo(raw, None, type=socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError):
            raise ScanError(f"'{raw}' çözümlenemedi.")
        ip = ipaddress.ip_address(infos[0][4][0])
    if ip.is_multicast or ip.is_unspecified or ip.is_reserved or str(ip) == "255.255.255.255":
        raise ScanError("Bu adres taranamaz (multicast / ayrılmış / broadcast).")
    internal = ip.is_private or ip.is_loopback or ip.is_link_local
    if not internal and not allow_public:
        raise ScanError("Genel (public) IP adreslerini yalnızca Süper Yönetici tarayabilir.")
    return str(ip)


def parse_ports(spec, preset=""):
    """'443', '22,80,8000-8100' or '0-65535' (or a preset key) -> sorted unique ports in 1..65535.
    Port 0 is accepted in the input but skipped: TCP cannot connect to port 0."""
    spec = (spec or "").strip()
    if not spec:
        if preset not in PRESETS:
            raise ScanError("Port, port aralığı veya hazır şablon seçin.")
        return list(PRESETS[preset])
    if not _PORT_SPEC_RE.match(spec):
        raise ScanError("Port listesi yalnızca rakam, virgül ve tire içerebilir (örn: 443 veya 22,80,8000-8100).")
    ports = set()
    for part in (p.strip() for p in spec.split(",")):
        if not part:
            continue
        lo, sep, hi = part.partition("-")
        lo, hi = lo.strip(), hi.strip()
        if not lo.isdigit() or (sep and not hi.isdigit()) or len(lo) > 5 or len(hi) > 5:
            raise ScanError(f"Geçersiz port ifadesi: '{part}'")
        lo = int(lo)
        hi = int(hi) if sep else lo
        if not (0 <= lo <= hi <= MAX_PORT):
            raise ScanError(f"Port değerleri 0-65535 arasında ve küçükten büyüğe olmalı: '{part}'")
        ports.update(range(max(lo, 1), hi + 1))
    if not ports:
        raise ScanError("Taranacak port yok (port 0 taranamaz).")
    return sorted(ports)


def parse_timeout(value):
    try:
        t = float(value)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT
    return t if t in TIMEOUT_CHOICES else DEFAULT_TIMEOUT


def _service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def _probe(ip, port, timeout):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            rc = s.connect_ex((ip, port))
    except OSError:
        return "filtered"
    if rc == 0:
        return "open"
    # ECONNREFUSED -> the host answered with RST; anything else (timeout, unreachable) -> filtered
    return "closed" if rc in (111, 10061, 61) else "filtered"


def _record(job):
    """JSON-safe record of a finished job (caller holds _lock)."""
    return {"id": job["id"], "user": job["user"], "target": job["target"], "label": job["label"],
            "range": job["range"], "status": job["status"], "total": job["total"], "done": job["done"],
            "open": list(job["open"]), "closed": job["closed"], "filtered": job["filtered"],
            "timeout": job["timeout"], "elapsed": job["duration"], "started": job["started"],
            "started_wall": job["started_wall"]}


def _read_history(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data["scans"] if isinstance(data, dict) and isinstance(data.get("scans"), list) else []
    except FileNotFoundError:
        return []
    except Exception:
        log.exception("port scan history unreadable: %s", path)
        return []


def _write_history(path, scans):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"scans": scans}, f, ensure_ascii=False)
    os.replace(tmp, path)


def _save_history(path, record):
    """Adds a finished scan and keeps the newest HISTORY_PER_USER per administrator. Best effort."""
    if not path:
        return
    try:
        with _hist_lock:
            scans = [record] + [r for r in _read_history(path) if r.get("id") != record["id"]]
            seen, kept = {}, []
            for r in scans:  # newest first
                seen[r.get("user")] = seen.get(r.get("user"), 0) + 1
                if seen[r.get("user")] <= HISTORY_PER_USER:
                    kept.append(r)
            _write_history(path, kept)
    except Exception:
        log.exception("port scan history not saved: %s", path)


def delete_history(path, scan_id):
    """Removes one finished scan (file and memory). Returns its record, or None if missing / still running."""
    if not path or not scan_id:
        return None
    with _lock:
        job = _jobs.get(scan_id)
        if job and job["status"] == "running":
            return None
        removed_mem = _record(job) if job else None
        _jobs.pop(scan_id, None)
    try:
        with _hist_lock:
            scans = _read_history(path)
            removed = next((r for r in scans if r.get("id") == scan_id), None)
            if removed is not None:
                _write_history(path, [r for r in scans if r.get("id") != scan_id])
            return removed or removed_mem
    except Exception:
        log.exception("port scan history not updated: %s", path)
        return removed_mem


def _prune():
    finished = sorted((j for j in _jobs.values() if j["status"] != "running"), key=lambda j: j["finished_at"])
    for job in finished[:max(0, len(finished) - MAX_KEPT_JOBS)]:
        del _jobs[job["id"]]


def _run(job, ports, timeout):
    ip = job["target"]
    workers = SMALL_SCAN_WORKERS if len(ports) <= 1024 else LARGE_SCAN_WORKERS

    def probe(port):
        if job["cancel"].is_set():
            return
        state = _probe(ip, port, timeout)
        with _lock:
            job["done"] += 1
            if state == "open":
                job["open"].append({"port": port, "service": _service_name(port)})
            else:
                job[state] += 1

    try:
        with ThreadPoolExecutor(max_workers=min(workers, len(ports)), thread_name_prefix="portscan") as ex:
            list(ex.map(probe, ports))
        status = "cancelled" if job["cancel"].is_set() else "done"
    except Exception:
        log.exception("port scan %s failed", job["id"])
        status = "error"
    with _lock:
        job["open"].sort(key=lambda p: p["port"])
        job["status"] = status
        job["finished_at"] = time.monotonic()
        job["duration"] = round(job["finished_at"] - job["started_at"], 1)
        record = _record(job)
    _save_history(job["history_path"], record)
    open_list = ",".join(str(p["port"]) for p in job["open"])
    log_admin_action(job["user"], "PORT_SCAN", f"{job['label']} ({ip})"[:128],
                     f"{job['done']}/{job['total']} port tarandı ({status}), açık: {open_list or '-'}"[:1000],
                     job["client_ip"])


def get_max_concurrent():
    return safe_int(get_setting(MAX_CONCURRENT_KEY, ""), DEFAULT_MAX_CONCURRENT,
                    min_value=1, max_value=MAX_CONCURRENT_LIMIT)


def set_max_concurrent(raw):
    """Stores the limit; returns an error message or None. The caller enforces superadmin."""
    value = safe_int(raw, None, min_value=1, max_value=MAX_CONCURRENT_LIMIT)
    if value is None:
        return f"Eşzamanlı tarama sayısı 1 ile {MAX_CONCURRENT_LIMIT} arasında olmalı."
    set_setting(MAX_CONCURRENT_KEY, str(value))
    if get_max_concurrent() != value:
        return "Ayar kaydedilemedi (veritabanına ulaşılamıyor)."
    return None


def _summary(job):
    return {"id": job["id"], "user": job["user"], "target": job["target"], "label": job["label"],
            "range": job["range"], "status": job["status"], "done": job["done"], "total": job["total"],
            "open_count": len(job["open"]), "started": job["started"]}


def running_jobs():
    """Summaries of all running scans (the superadmin's overview)."""
    with _lock:
        return [_summary(j) for j in _jobs.values() if j["status"] == "running"]


def recent_jobs(user, is_superadmin=False, history_path=""):
    """Scans visible to user (own, or all for the superadmin), newest first: those in memory plus the saved
    ones (which survive a restart)."""
    with _lock:
        jobs = [dict(_summary(j), started_wall=j["started_wall"]) for j in _jobs.values()
                if is_superadmin or j["user"] == user]
    seen = {j["id"] for j in jobs}
    with _hist_lock:
        saved = _read_history(history_path) if history_path else []
    for r in saved:
        if r.get("id") in seen or not (is_superadmin or r.get("user") == user):
            continue
        jobs.append({"id": r["id"], "user": r.get("user", ""), "target": r.get("target", ""),
                     "label": r.get("label", ""), "range": r.get("range", ""), "status": r.get("status", ""),
                     "done": r.get("done", 0), "total": r.get("total", 0), "open_count": len(r.get("open", [])),
                     "started": r.get("started", ""), "started_wall": r.get("started_wall", 0)})
    return sorted(jobs, key=lambda j: j["started_wall"], reverse=True)


def running_job_id(user):
    """Id of the viewer's newest running scan (to link back to it from the form), else None."""
    with _lock:
        own = [j for j in _jobs.values() if j["status"] == "running" and j["user"] == user]
        return max(own, key=lambda j: j["started_at"])["id"] if own else None


def start_scan(ip, ports, timeout=DEFAULT_TIMEOUT, user="", label="", client_ip="", max_concurrent=None,
               history_path=""):
    """Starts a background scan and returns its job id. Raises ScanError when the simultaneous-scan limit is
    reached or the user is in the cooldown."""
    limit = max_concurrent or get_max_concurrent()
    now = time.monotonic()
    with _lock:
        _prune()
        running = [j for j in _jobs.values() if j["status"] == "running"]
        if len(running) >= limit:
            raise ScanError(f"Aynı anda en fazla {limit} tarama çalışabilir ve şu an {len(running)} tarama sürüyor; "
                            "biri bitince veya durdurulunca tekrar deneyin.")
        last = _last_start.get(user)
        if last is not None and now - last < USER_COOLDOWN_SECONDS:
            raise ScanError(f"Yeni tarama için {int(USER_COOLDOWN_SECONDS - (now - last)) + 1} saniye bekleyin.")
        _last_start[user] = now
        job = {
            "id": secrets.token_hex(8), "user": user, "label": label or ip, "target": ip, "client_ip": client_ip,
            "total": len(ports), "done": 0, "open": [], "closed": 0, "filtered": 0, "timeout": timeout,
            "range": f"{ports[0]}-{ports[-1]}" if len(ports) > 1 else str(ports[0]),
            "status": "running", "started_at": now, "finished_at": 0.0, "duration": 0.0,
            "started": datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
            "cancel": threading.Event(), "history_path": history_path, "started_wall": time.time(),
        }
        _jobs[job["id"]] = job
    threading.Thread(target=_run, args=(job, ports, timeout), daemon=True, name=f"portscan-{job['id']}").start()
    return job["id"]


def get_job(job_id, user, is_superadmin=False, history_path=""):
    """JSON-safe snapshot of a job visible to user (owner or superadmin), else None. Finished scans no longer
    in memory (after a restart) come from the history file."""
    with _lock:
        job = _jobs.get(job_id or "")
        if job:
            if job["user"] != user and not is_superadmin:
                return None
            elapsed = (job["finished_at"] or time.monotonic()) - job["started_at"]
            return {
                "id": job["id"], "user": job["user"], "started": job["started"],
                "target": job["target"], "label": job["label"], "range": job["range"],
                "status": job["status"], "total": job["total"], "done": job["done"], "open": list(job["open"]),
                "closed": job["closed"], "filtered": job["filtered"], "elapsed": round(elapsed, 1),
                "timeout": job["timeout"],
            }
    if not (history_path and job_id):
        return None
    with _hist_lock:
        rec = next((r for r in _read_history(history_path) if r.get("id") == job_id), None)
    if not rec or (rec.get("user") != user and not is_superadmin):
        return None
    return {k: rec.get(k) for k in ("id", "user", "started", "target", "label", "range", "status", "total",
                                    "done", "open", "closed", "filtered", "elapsed", "timeout")}


def cancel_job(job_id, user, is_superadmin=False):
    with _lock:
        job = _jobs.get(job_id or "")
        if not job or (job["user"] != user and not is_superadmin):
            return False
        job["cancel"].set()
        return True


def wait(job_id, timeout=30.0):
    """Blocks until the job leaves 'running' (tests / CLI use)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with _lock:
            job = _jobs.get(job_id)
            if not job or job["status"] != "running":
                return
        time.sleep(0.05)
