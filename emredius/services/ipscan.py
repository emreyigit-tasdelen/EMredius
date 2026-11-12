# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""IP scan (host discovery): ICMP ping sweep over any IPv4/IPv6 network the administrator enters, plus ARP/NDP
(MAC / vendor) and reverse DNS for the hosts that answer. Pings go out over one ICMP socket (services/icmp.py);
when the process may not open one, it falls back to one `ping` process per address. Read-only.
A scan runs as a background job (large networks outlive one HTTP request). Every administrator may run up to N
scans at the same time (N is a panel setting only the superadmin can change). Administrators see only their own
scans, the superadmin also sees every running scan. The last 20 finished scans per administrator are kept in a
JSON file, so they survive a restart."""
import ipaddress
import json
import logging
import os
import secrets
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import icmp
from . import portscan
from ..core import get_setting, log_admin_action, run_cmd, safe_int, set_setting
from ..core.validators import lookup_mac_vendor

log = logging.getLogger(__name__)

WORKERS = 128              # parallel ping processes (fallback only)
PING_TIMEOUT_S = 1
SEND_RATE = 2000           # ICMP packets per second per scan (socket sweep)
DNS_WORKERS = 32
JOB_TTL_SECONDS = 3600     # finished jobs stay viewable this long
MAX_KEPT_JOBS = 20
MAX_CONCURRENT_KEY = "ipscan_max_concurrent"
DEFAULT_MAX_CONCURRENT = 2  # per administrator
MAX_CONCURRENT_LIMIT = 16   # each scan sends up to SEND_RATE packets/s (or runs WORKERS ping processes)
HISTORY_PER_USER = 20
PORT_WORKERS = 192
MAX_PORT_PROBES = 1_000_000   # alive hosts x ports per scan
HISTORY_MAX_HOSTS = 5000    # alive hosts stored per finished scan (the rest is cut, flagged `truncated`)

_lock = threading.Lock()
_hist_lock = threading.Lock()
_jobs = {}


class ScanError(Exception):
    pass


def parse_target(raw):
    """Returns (ipaddress network, None) or (None, error message). A bare IP means that single host.
    Any address family, range or size is accepted; the administrator picks the network for every scan."""
    text = (raw or "").strip()
    if not text:
        return None, "Hedef ağ boş olamaz!"
    if len(text) > 64 or text.startswith("-"):
        return None, "Geçersiz hedef ağ!"
    try:
        return ipaddress.ip_network(text, strict=False), None
    except ValueError:
        return None, "Geçersiz IP / alt ağ. Örnek: 192.168.1.0/24"


def host_count(net):
    if net.version == 4 and net.prefixlen < 31:
        return net.num_addresses - 2
    if net.version == 6 and net.prefixlen < 127:
        return net.num_addresses - 1
    return net.num_addresses


def iter_hosts(net):
    """Lazy host iterator (a /8 or an IPv6 /64 is never materialised)."""
    if (net.version == 4 and net.prefixlen < 31) or (net.version == 6 and net.prefixlen < 127):
        return (str(h) for h in net.hosts())
    return (str(h) for h in net)


def _ping(ip):
    started = time.monotonic()
    rc, out, _ = run_cmd(["ping", "-c", "1", "-W", str(PING_TIMEOUT_S), "-n", ip], timeout=PING_TIMEOUT_S + 2)
    if rc != 0:
        return None
    for token in (out or "").split():
        if token.startswith("time="):
            try:
                return round(float(token[5:]), 2)
            except ValueError:
                break
    return round((time.monotonic() - started) * 1000, 2)


def _neighbors():
    """{ip: mac} from the kernel ARP / NDP table (entries with a link-layer address only)."""
    rc, out, _ = run_cmd(["ip", "neigh", "show"], timeout=5)
    table = {}
    if rc != 0:
        return table
    for line in (out or "").splitlines():
        parts = line.split()
        if "lladdr" in parts and parts[-1] not in ("FAILED", "INCOMPLETE"):
            i = parts.index("lladdr")
            if i + 1 < len(parts):
                table[parts[0]] = parts[i + 1].lower()
    return table


def _netbios_name(ip):
    """NetBIOS node-status query (UDP 137): the machine name of Windows hosts that have no reverse DNS record."""
    if ":" in ip:
        return ""
    query = b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.8)
            s.sendto(query, (ip, 137))
            data = s.recv(1024)
        if len(data) > 57 and data[56] > 0:
            return data[57:72].decode("ascii", "ignore").strip()
    except Exception:
        pass
    return ""


def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return _netbios_name(ip)


def _host_entry(ip, rtt, mac="", hostname=""):
    return {"ip": ip, "rtt_ms": rtt, "mac": mac, "vendor": lookup_mac_vendor(mac) if mac else "",
            "hostname": hostname}


def _record(job):
    """JSON-safe record of a finished job (caller holds _lock)."""
    alive = job["alive"][:HISTORY_MAX_HOSTS]
    return {"id": job["id"], "user": job["user"], "network": job["network"], "status": job["status"],
            "total": job["total"], "done": job["done"], "method": job.get("method", ""),
            "started_at": job["started_wall"], "elapsed": round(job["finished_at"] - job["started_at"], 1),
            "alive_count": len(job["alive"]), "truncated": len(job["alive"]) > len(alive), "alive": alive,
            "port_total": job.get("port_total", 0), "port_done": job.get("port_done", 0),
            "ports_scanned": len(job.get("ports") or [])}


def _read_history(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data["scans"] if isinstance(data, dict) and isinstance(data.get("scans"), list) else []
    except FileNotFoundError:
        return []
    except Exception:
        log.exception("ip scan history unreadable: %s", path)
        return []


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
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            tmp = f"{path}.{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"scans": kept}, f, ensure_ascii=False)
            os.replace(tmp, path)
    except Exception:
        log.exception("ip scan history not saved: %s", path)


def list_history(user, path):
    """The user's last finished scans, newest first (without host lists)."""
    with _hist_lock:
        scans = _read_history(path) if path else []
    return [{k: v for k, v in r.items() if k != "alive"} for r in scans if r.get("user") == user][:HISTORY_PER_USER]


def delete_history(path, scan_id):
    """Removes one finished scan from the history file. Returns True if it existed."""
    if not path or not scan_id:
        return None
    try:
        with _hist_lock:
            scans = _read_history(path)
            kept = [r for r in scans if r.get("id") != scan_id]
            if len(kept) == len(scans):
                return None
            removed = next(r for r in scans if r.get("id") == scan_id)
            tmp = f"{path}.{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"scans": kept}, f, ensure_ascii=False)
            os.replace(tmp, path)
            return removed
    except Exception:
        log.exception("ip scan history not updated: %s", path)
        return None


def _prune(now):
    for jid, job in list(_jobs.items()):
        if job["status"] != "running" and now - job["finished_at"] > JOB_TTL_SECONDS:
            del _jobs[jid]
    finished = sorted((j for j in _jobs.values() if j["status"] != "running"), key=lambda j: j["finished_at"])
    for job in finished[:max(0, len(_jobs) - MAX_KEPT_JOBS)]:
        del _jobs[job["id"]]


def _sweep_socket(job, net, opened):
    def on_reply(ip, rtt):
        with _lock:
            job["alive"].append(_host_entry(ip, rtt))

    def on_sent(n):
        with _lock:
            job["done"] = n

    icmp.sweep(iter_hosts(net), net.version, on_reply, on_sent, job["cancel"], rate=SEND_RATE,
               timeout=PING_TIMEOUT_S, sock_factory=lambda _version: opened)


def _sweep_processes(job, net):
    hosts = iter_hosts(net)
    cancel = job["cancel"]

    def worker():
        while not cancel.is_set():
            with _lock:
                ip = next(hosts, None)
            if ip is None:
                return
            rtt = _ping(ip)
            with _lock:
                job["done"] += 1
                if rtt is not None:
                    job["alive"].append(_host_entry(ip, rtt))

    threads = [threading.Thread(target=worker, daemon=True, name=f"ipscan-{job['id']}-{i}")
               for i in range(min(WORKERS, max(1, job["total"])))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def _run(job, net):
    cancel = job["cancel"]
    status = "done"
    try:
        try:
            opened = icmp.open_socket(net.version)
        except OSError as e:
            log.warning("ip scan %s: no ICMP socket (%s), falling back to ping processes", job["id"], e)
            job["method"] = "ping"
            _sweep_processes(job, net)
        else:
            job["method"] = "icmp-socket"
            _sweep_socket(job, net, opened)
        if cancel.is_set():
            status = "cancelled"
        # MAC / vendor from the neighbour table; a host that blocks ICMP still answers ARP / NDP on a
        # directly connected network, so those are added too (only for addresses that were actually probed)
        neigh = _neighbors()
        with _lock:
            seen = {h["ip"] for h in job["alive"]}
            for h in job["alive"]:
                mac = neigh.get(h["ip"], "")
                h["mac"], h["vendor"] = mac, lookup_mac_vendor(mac) if mac else ""
            if status == "done":
                job["alive"].extend(_host_entry(ip, None, neigh[ip]) for ip in neigh
                                    if ip not in seen and _in_net(ip, net))
            targets = list(job["alive"])
        if job["resolve_names"] and targets and not cancel.is_set():
            with ThreadPoolExecutor(max_workers=DNS_WORKERS, thread_name_prefix="ipscan-dns") as pool:
                names = list(pool.map(_reverse_dns, [h["ip"] for h in targets]))
            with _lock:
                for h, name in zip(targets, names):
                    h["hostname"] = name
        if job.get("ports") and not cancel.is_set():
            _port_phase(job)
            if cancel.is_set():
                status = "cancelled"
    except Exception:
        log.exception("ip scan %s failed", job["id"])
        status = "error"
    with _lock:
        job["alive"].sort(key=lambda h: ipaddress.ip_address(h["ip"]))
        job["status"] = status
        job["finished_at"] = time.monotonic()
        record = _record(job)
    _save_history(job["history_path"], record)
    _notify(job, record)
    log_admin_action(job["user"], "IP_SCAN", job["network"][:128],
                     f"{len(job['alive'])} aktif host, {job['done']}/{job['total']} adres tarandı ({status}, "
                     f"{job.get('method', '-')})", job["client_ip"])


def _notify(job, record):
    """Biten taramadan yeni cihaz bildirimi (ilk tarama yalnızca bir özet bildirimi üretir)."""
    if record["status"] != "done" or not record["alive"]:
        return
    try:
        from . import notifications
        new, had = notifications.remember_hosts([h["ip"] for h in record["alive"]], job.get("tenant_id"))
        if not new:
            return
        link = f"/ip-scan?job={job['id']}"
        if not had:
            notifications.publish("ipscan", f"{job['network']} taraması tamamlandı",
                                  f"{len(new)} cihaz bulundu (ilk tarama; sonraki taramalarda yalnızca yeni cihazlar bildirilir).",
                                  link, ntype="scan_done", severity="info", tenant_id=job.get("tenant_id"))
        else:
            sample = ", ".join(new[:5]) + (" ..." if len(new) > 5 else "")
            notifications.publish("ipscan", f"Ağda {len(new)} yeni cihaz bulundu", f"{job['network']}: {sample}", link,
                                  ntype="new_device", severity="warning", tenant_id=job.get("tenant_id"))
    except Exception:  # noqa: BLE001
        log.debug("ip scan notification failed", exc_info=True)


def _port_phase(job):
    """TCP connect scan of the chosen ports on every host that answered; results land in each host's `ports`."""
    ports, timeout = job["ports"], job["port_timeout"]
    with _lock:
        hosts = [h["ip"] for h in job["alive"]]
        for h in job["alive"]:
            h["ports"] = []
        job["phase"] = "ports"
        job["port_total"] = len(hosts) * len(ports)
        by_ip = {h["ip"]: h for h in job["alive"]}
    cancel = job["cancel"]

    def task(args):
        ip, port = args
        if cancel.is_set():
            return
        state = portscan._probe(ip, port, timeout)
        with _lock:
            job["port_done"] += 1
            if state == "open":
                by_ip[ip]["ports"].append({"port": port, "service": portscan._service_name(port)})

    jobs = [(ip, p) for ip in hosts for p in ports]
    with ThreadPoolExecutor(max_workers=PORT_WORKERS, thread_name_prefix="ipscan-port") as pool:
        list(pool.map(task, jobs))
    with _lock:
        for h in job["alive"]:
            h["ports"].sort(key=lambda x: x["port"])


def _in_net(ip, net):
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def get_max_concurrent():
    """Simultaneous scans allowed PER administrator."""
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


def running_jobs(user=None):
    """[{id, user, network, done, total}] of the running scans; of one user, or of everybody when user is None."""
    with _lock:
        return [{"id": j["id"], "user": j["user"], "network": j["network"], "done": j["done"], "total": j["total"]}
                for j in _jobs.values()
                if j["status"] == "running" and (user is None or j["user"] == user)]


def start_scan(net, user="", resolve_names=True, client_ip="", max_concurrent=None, history_path="",
               ports=None, port_timeout=portscan.DEFAULT_TIMEOUT, allow_public=False):
    """Starts a background scan and returns its job id. Raises ScanError when the user already has
    `max_concurrent` running scans."""
    limit = max_concurrent or get_max_concurrent()
    now = time.monotonic()
    ports = list(ports) if ports else None
    try:
        from ..core.tenant import resolve_tenant
        tenant_id = resolve_tenant(None)   # request context; the worker thread has none
    except Exception:  # noqa: BLE001
        tenant_id = 1
    if ports:
        if not allow_public and not (net.is_private or net.is_loopback or net.is_link_local):
            raise ScanError("Genel (public) ağlarda port taraması yalnızca Süper Yönetici tarafından yapılabilir.")
        if not allow_public and host_count(net) * len(ports) > MAX_PORT_PROBES:   # superadmin: no limit
            raise ScanError(f"Port taraması için ağ x port sayısı en fazla {MAX_PORT_PROBES:,} olabilir; "
                            "ağı daraltın veya daha az port seçin.")
    with _lock:
        _prune(now)
        own = [j for j in _jobs.values() if j["status"] == "running" and j["user"] == user]
        if len(own) >= limit:
            raise ScanError(f"Aynı anda en fazla {limit} taramanız çalışabilir ve şu an {len(own)} taramanız sürüyor; "
                            "biri bitince veya durdurulunca tekrar deneyin.")
        job = {
            "id": secrets.token_hex(8), "user": user, "network": str(net), "client_ip": client_ip,
            "total": host_count(net), "done": 0, "alive": [], "resolve_names": bool(resolve_names),
            "status": "running", "started_at": now, "started_wall": time.time(), "finished_at": 0.0,
            "cancel": threading.Event(), "history_path": history_path,
            "tenant_id": tenant_id, "ports": ports, "port_timeout": port_timeout, "port_total": 0, "port_done": 0, "phase": "hosts",
        }
        _jobs[job["id"]] = job
    threading.Thread(target=_run, args=(job, net), daemon=True, name=f"ipscan-{job['id']}").start()
    return job["id"]


def running_job_id(user):
    """Id of the viewer's newest running scan (to link back to it from the form), else None."""
    with _lock:
        own = [j for j in _jobs.values() if j["status"] == "running" and j["user"] == user]
        return max(own, key=lambda j: j["started_at"])["id"] if own else None


def get_job(job_id, user, is_superadmin=False, since=0, history_path=""):
    """JSON-safe snapshot of a job visible to user (owner or superadmin), else None. Finished scans that are no
    longer in memory (after a restart) come from the history file.
    `alive` holds only the hosts from index `since` on while running (the page polls incrementally);
    a finished job always returns the full, sorted list."""
    with _lock:
        job = _jobs.get(job_id or "")
        if job:
            if job["user"] != user and not is_superadmin:
                return None
            running = job["status"] == "running"
            start = max(0, int(since or 0)) if running else 0
            elapsed = (job["finished_at"] or time.monotonic()) - job["started_at"]
            return {
                "id": job["id"], "network": job["network"], "status": job["status"], "user": job["user"],
                "total": job["total"], "done": job["done"], "alive_count": len(job["alive"]),
                "since": start, "alive": [dict(h) for h in job["alive"][start:]], "elapsed": round(elapsed, 1),
                "method": job.get("method", ""), "truncated": False, "phase": job.get("phase", "hosts"),
                "port_total": job["port_total"], "port_done": job["port_done"],
                "ports_scanned": len(job["ports"] or []),
                "ports_map": {h["ip"]: h["ports"][:] for h in job["alive"] if h.get("ports")},
            }
    if not (history_path and job_id):
        return None
    with _hist_lock:
        rec = next((r for r in _read_history(history_path) if r.get("id") == job_id), None)
    if not rec or (rec.get("user") != user and not is_superadmin):
        return None
    return {"id": rec["id"], "network": rec["network"], "status": rec["status"], "user": rec["user"],
            "total": rec["total"], "done": rec["done"], "alive_count": rec["alive_count"], "since": 0,
            "alive": rec["alive"], "elapsed": rec["elapsed"], "method": rec.get("method", ""),
            "truncated": rec.get("truncated", False), "phase": "done", "port_total": rec.get("port_total", 0),
            "port_done": rec.get("port_done", 0), "ports_scanned": rec.get("ports_scanned", 0), "ports_map": {}}


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
