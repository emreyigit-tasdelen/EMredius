# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""İzlenen IP'ler: kayıtlı hedefleri periyodik ping ile izler; durum, gecikme (RTT) ve geçmiş saklanır.
Tablolar NMS veritabanında, her satırda tenant_id. Yalnızca ICMP echo (komut satırı ping) kullanılır."""
import csv
import io
import ipaddress
import logging
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import inventory
from ..core import get_nms_db
from ..core.tenant import resolve_tenant

log = logging.getLogger(__name__)

DEFAULT_TENANT = inventory.DEFAULT_TENANT
MAX_TARGETS = 500
KEEP_DAYS = 14
_schema_ok = set()

SCHEMA = """
CREATE TABLE IF NOT EXISTS watch_targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, ip TEXT NOT NULL, name TEXT DEFAULT '',
  status TEXT DEFAULT 'UNKNOWN', rtt_ms REAL, loss_pct INTEGER DEFAULT 0, last_check TEXT DEFAULT '', last_change TEXT DEFAULT '',
  created TEXT DEFAULT '', UNIQUE(tenant_id, ip));
CREATE TABLE IF NOT EXISTS watch_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL, ts TEXT NOT NULL, up INTEGER NOT NULL, rtt_ms REAL);
CREATE INDEX IF NOT EXISTS watch_hist_t ON watch_history(target_id, id);
"""
CSV_COLS = ["ip", "name", "status", "rtt_ms", "loss_pct", "last_check", "last_change"]
_RTT = re.compile(r"[=<]\s*([\d.,]+)\s*ms", re.I)


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _db():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        conn.commit()
        _schema_ok.add(key)
    return conn


def parse_ping(out):
    """Ping çıktısından en iyi RTT (ms); yanıt yoksa None."""
    vals = []
    for m in _RTT.finditer(out or ""):
        try:
            vals.append(float(m.group(1).replace(",", ".")))
        except ValueError:
            pass
    return min(vals) if vals else None


def ping(ip, count=2, timeout_s=1):
    """-> (up, rtt_ms, loss_pct)."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False, None, 100
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", str(count), "-w", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-n", "-c", str(count), "-W", str(timeout_s), ip]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=count * (timeout_s + 1) + 3)
        out = p.stdout or ""
    except Exception:  # noqa: BLE001
        return False, None, 100
    rtt = parse_ping(out)
    m = re.search(r"(\d+)%\s*(packet )?loss", out, re.I)
    loss = int(m.group(1)) if m else (0 if rtt is not None else 100)
    return rtt is not None, rtt, loss


def add_target(ip, name="", tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    ip = (ip or "").strip()
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return "Geçerli bir IP adresi girin."
    conn = _db()
    try:
        if conn.execute("SELECT COUNT(*) FROM watch_targets WHERE tenant_id=?", (tenant_id,)).fetchone()[0] >= MAX_TARGETS:
            return f"En fazla {MAX_TARGETS} hedef izlenebilir."
        if conn.execute("SELECT 1 FROM watch_targets WHERE tenant_id=? AND ip=?", (tenant_id, ip)).fetchone():
            return "Bu IP zaten izleniyor."
        conn.execute("INSERT INTO watch_targets (tenant_id, ip, name, created) VALUES (?,?,?,?)",
                     (tenant_id, ip, (name or "").strip()[:64], _now()))
        conn.commit()
    finally:
        conn.close()
    return ""


def delete_target(target_id, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        conn.execute("DELETE FROM watch_history WHERE target_id IN (SELECT id FROM watch_targets WHERE id=? AND tenant_id=?)",
                     (target_id, tenant_id))
        n = conn.execute("DELETE FROM watch_targets WHERE id=? AND tenant_id=?", (target_id, tenant_id)).rowcount
        conn.commit()
        return n > 0
    finally:
        conn.close()


def record(conn, target_id, up, rtt, loss, prev_status):
    now = _now()
    status = "UP" if up else "DOWN"
    change = ", last_change=?" if status != prev_status else ""
    args = [status, rtt, loss, now] + ([now] if change else []) + [target_id]
    conn.execute(f"UPDATE watch_targets SET status=?, rtt_ms=?, loss_pct=?, last_check=?{change} WHERE id=?", args)
    conn.execute("INSERT INTO watch_history (target_id, ts, up, rtt_ms) VALUES (?,?,?,?)", (target_id, now, 1 if up else 0, rtt))


def check_all(tenant_id=None):
    conn = _db()
    try:
        sql = "SELECT id, ip, status FROM watch_targets" + (" WHERE tenant_id=?" if tenant_id else "")
        rows = [dict(r) for r in conn.execute(sql, (tenant_id,) if tenant_id else ())]
    finally:
        conn.close()
    with ThreadPoolExecutor(16) as ex:
        res = list(ex.map(lambda r: ping(r["ip"]), rows))
    conn = _db()
    try:
        for r, (up, rtt, loss) in zip(rows, res):
            record(conn, r["id"], up, rtt, loss, r["status"])
        cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - KEEP_DAYS * 86400))
        conn.execute("DELETE FROM watch_history WHERE ts<?", (cutoff,))
        conn.commit()
    finally:
        conn.close()
    return len(rows)


def start_scheduler(interval_s=60):
    def loop():
        while True:
            time.sleep(interval_s)
            try:
                check_all()
            except Exception as e:  # noqa: BLE001
                log.warning("watch scheduler: %s", e)
    threading.Thread(target=loop, daemon=True, name="watch-scheduler").start()


def list_targets(tenant_id=None, q=""):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        rows = [dict(r) for r in conn.execute("SELECT * FROM watch_targets WHERE tenant_id=? ORDER BY status='DOWN' DESC, ip", (tenant_id,))]
    finally:
        conn.close()
    inv = {d["ip"]: d for d in inventory.list_devices(tenant_id)}
    ql = (q or "").lower()
    out = []
    for r in rows:
        d = inv.get(r["ip"])
        r["inv_name"] = (d.get("sys_name") or d.get("hostname") or "") if d else ""
        r["inv_vendor"] = d["vendor"] if d else ""
        if ql and ql not in f"{r['ip']} {r['name']} {r['inv_name']}".lower():
            continue
        out.append(r)
    return out


def history(target_id, tenant_id=None, limit=300):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        if not conn.execute("SELECT 1 FROM watch_targets WHERE id=? AND tenant_id=?", (target_id, tenant_id)).fetchone():
            return []
        rows = [dict(r) for r in conn.execute(
            "SELECT ts, up, rtt_ms FROM watch_history WHERE target_id=? ORDER BY id DESC LIMIT ?", (target_id, max(1, min(int(limit), 2000))))]
    finally:
        conn.close()
    return rows[::-1]


def overview(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    t = list_targets(tenant_id)
    return {"total": len(t), "up": sum(r["status"] == "UP" for r in t), "down": sum(r["status"] == "DOWN" for r in t)}


def targets_csv(rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLS)
    for r in rows:
        w.writerow([("'" + str(r.get(c, "")) if str(r.get(c, "") if r.get(c) is not None else "")[:1] in ("=", "+", "-", "@")
                     else ("" if r.get(c) is None else r.get(c))) for c in CSV_COLS])
    return buf.getvalue()
