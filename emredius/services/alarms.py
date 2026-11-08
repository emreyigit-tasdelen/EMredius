# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Alarmlar: eşik kuralları (CPU/bellek/sıcaklık/izlenen IP kapalı), SNMP trap alıcı (v1/v2c, varsayılan kapalı),
olay yaşam döngüsü (aktif/onaylı/çözüldü) ve e-posta bildirimi (varsayılan kapalı; ayar alarm_smtp_enabled=1).
Olaylar NMS veritabanında alm_events / alm_rules tablolarında, tenant_id'li. NMS poller'ın kendi `alarms` tablosu salt okunur
olarak listeye eklenir. Yapay zekâ yorumu için yalnızca boş `ai_comment` alanı vardır (services/llm.py)."""
import csv
import io
import logging
import smtplib
import socket
import threading
import time
from email.message import EmailMessage

from . import health, inventory, watch
from ..core import get_nms_db, get_setting
from ..core.tenant import all_tenant_ids, resolve_tenant

log = logging.getLogger(__name__)

DEFAULT_TENANT = inventory.DEFAULT_TENANT
METRICS = {"cpu": "CPU %", "ram": "Bellek %", "temp": "Sıcaklık °C", "host_down": "İzlenen IP kapalı"}
SEVERITIES = ("INFO", "WARNING", "CRITICAL")
STATUSES = ("active", "ack", "resolved")
_schema_ok = set()
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS alm_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL, metric TEXT NOT NULL,
  threshold REAL NOT NULL DEFAULT 0, severity TEXT NOT NULL DEFAULT 'WARNING', email_to TEXT DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
  created TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS alm_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, source TEXT NOT NULL, ev_key TEXT NOT NULL,
  device_ip TEXT DEFAULT '', severity TEXT NOT NULL DEFAULT 'WARNING', message TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'active',
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 1, ack_by TEXT DEFAULT '', ack_at TEXT DEFAULT '',
  resolved_at TEXT DEFAULT '', ai_comment TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS alm_events_k ON alm_events(tenant_id, ev_key, status);
"""
CSV_COLS = ["id", "source", "device_ip", "severity", "status", "message", "first_seen", "last_seen", "count", "ack_by"]


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


# ---------------------------------------------------------------- e-posta (varsayılan kapalı)
def mail_enabled():
    return str(get_setting("alarm_smtp_enabled", "0")) == "1" and bool(get_setting("alarm_smtp_host", ""))


def send_mail(to, subject, body):
    """Kapalıyken hiçbir şey göndermez. Doğrulamasız röle (host:port) kullanır; kimlik bilgisi saklanmaz."""
    if not to or not mail_enabled():
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = subject[:200].replace("\n", " ")
        msg["From"] = get_setting("alarm_smtp_from", "emredius@localhost")
        msg["To"] = to
        msg.set_content(body)
        with smtplib.SMTP(get_setting("alarm_smtp_host", ""), int(get_setting("alarm_smtp_port", "25") or 25), timeout=8) as s:
            s.send_message(msg)
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("alarm mail: %s", e)
        return False


# ---------------------------------------------------------------- kurallar
def add_rule(name, metric, threshold, severity="WARNING", email_to="", tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    name = (name or "").strip()[:64]
    if not name:
        return "Kural adı gerekli."
    if metric not in METRICS:
        return "Geçersiz ölçüt."
    if severity not in SEVERITIES:
        return "Geçersiz önem."
    try:
        th = float(threshold) if metric != "host_down" else 0.0
    except (TypeError, ValueError):
        return "Eşik sayı olmalı."
    email_to = (email_to or "").strip()[:200]
    if email_to and not all("@" in x and " " not in x for x in email_to.split(",")):
        return "E-posta adresleri geçersiz."
    conn = _db()
    try:
        conn.execute("INSERT INTO alm_rules (tenant_id,name,metric,threshold,severity,email_to,created) VALUES (?,?,?,?,?,?,?)",
                     (tenant_id, name, metric, th, severity, email_to, _now()))
        conn.commit()
    finally:
        conn.close()
    return ""


def delete_rule(rule_id, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        n = conn.execute("DELETE FROM alm_rules WHERE id=? AND tenant_id=?", (rule_id, tenant_id)).rowcount
        conn.commit()
        return n > 0
    finally:
        conn.close()


def toggle_rule(rule_id, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        n = conn.execute("UPDATE alm_rules SET enabled=1-enabled WHERE id=? AND tenant_id=?", (rule_id, tenant_id)).rowcount
        conn.commit()
        return n > 0
    finally:
        conn.close()


def list_rules(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        return [dict(r, metric_label=METRICS.get(r["metric"], r["metric"])) for r in
                conn.execute("SELECT * FROM alm_rules WHERE tenant_id=? ORDER BY id", (tenant_id,))]
    finally:
        conn.close()


# ---------------------------------------------------------------- olaylar
def raise_event(conn, key, source, device_ip, severity, message, tenant_id=None, email_to=""):
    """Aynı anahtarda aktif/onaylı olay varsa sayacı artırır, yoksa yeni olay açar (+ e-posta). Yeni mi döndürür."""
    tenant_id = resolve_tenant(tenant_id)
    now = _now()
    row = conn.execute("SELECT id FROM alm_events WHERE tenant_id=? AND ev_key=? AND status!='resolved'", (tenant_id, key)).fetchone()
    if row:
        conn.execute("UPDATE alm_events SET last_seen=?, count=count+1, message=? WHERE id=?", (now, message[:500], row[0]))
        return False
    conn.execute("INSERT INTO alm_events (tenant_id,source,ev_key,device_ip,severity,message,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
                 (tenant_id, source, key, device_ip, severity, message[:500], now, now))
    if email_to:
        send_mail(email_to, f"[EMREDIUS {severity}] {device_ip}", message)
    return True


def resolve_key(conn, key, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn.execute("UPDATE alm_events SET status='resolved', resolved_at=? WHERE tenant_id=? AND ev_key=? AND status!='resolved'",
                 (_now(), tenant_id, key))


def evaluate(tenant_id=None):
    """Etkin kuralları sağlık verisi ve izlenen IP durumuyla değerlendirir; aşan için olay açar, düzelenleri çözer."""
    tenant_id = resolve_tenant(tenant_id)
    rules = [r for r in list_rules(tenant_id) if r["enabled"]]
    if not rules:
        return 0
    hrows = health.health_rows(tenant_id)
    targets = watch.list_targets(tenant_id)
    opened = 0
    conn = _db()
    try:
        for r in rules:
            if r["metric"] == "host_down":
                for t in targets:
                    k = f"rule{r['id']}:{t['ip']}"
                    if t["status"] == "DOWN":
                        opened += raise_event(conn, k, "rule", t["ip"], r["severity"],
                                              f"{r['name']}: {t['name'] or t['ip']} yanıt vermiyor", tenant_id, r["email_to"])
                    else:
                        resolve_key(conn, k, tenant_id)
                continue
            col = {"cpu": "cpu", "ram": "ram", "temp": "temp"}[r["metric"]]
            for h in hrows:
                v = h.get(col)
                k = f"rule{r['id']}:{h['ip']}"
                if v is not None and v >= r["threshold"]:
                    opened += raise_event(conn, k, "rule", h["ip"], r["severity"],
                                          f"{r['name']}: {h['name']} {METRICS[r['metric']]} {v} (eşik {r['threshold']:g})", tenant_id, r["email_to"])
                elif v is not None:
                    resolve_key(conn, k, tenant_id)
        conn.commit()
    finally:
        conn.close()
    return opened


def start_scheduler(interval_s=60):
    def loop():
        while True:
            time.sleep(interval_s)
            try:
                for t in all_tenant_ids():
                    evaluate(t)
            except Exception as e:  # noqa: BLE001
                log.warning("alarm scheduler: %s", e)
    threading.Thread(target=loop, daemon=True, name="alarm-scheduler").start()


def ack(event_id, user, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        n = conn.execute("UPDATE alm_events SET status='ack', ack_by=?, ack_at=? WHERE id=? AND tenant_id=? AND status='active'",
                         ((user or "")[:64], _now(), event_id, tenant_id)).rowcount
        conn.commit()
        return n > 0
    finally:
        conn.close()


def resolve(event_id, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        n = conn.execute("UPDATE alm_events SET status='resolved', resolved_at=? WHERE id=? AND tenant_id=? AND status!='resolved'",
                         (_now(), event_id, tenant_id)).rowcount
        conn.commit()
        return n > 0
    finally:
        conn.close()


def _poller_alarms(tenant_id, status):
    """NMS poller'ın alarms tablosu (varsa), tenant'a ait cihazlar için; salt okunur."""
    conn = get_nms_db()
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT a.id, a.timestamp, a.alarm_type, a.severity, a.message, a.resolved, d.ip FROM alarms a "
            "JOIN snmp_devices d ON d.id=a.device_id ORDER BY a.id DESC LIMIT 500")]
    except Exception:  # noqa: BLE001
        return []
    finally:
        conn.close()
    ips = {d["ip"] for d in inventory.list_devices(tenant_id)}
    out = []
    for r in rows:
        if r["ip"] not in ips:
            continue
        st = "resolved" if r["resolved"] else "active"
        if status and status != st:
            continue
        out.append({"id": f"p{r['id']}", "source": "poller", "device_ip": r["ip"], "severity": str(r["severity"]).upper(),
                    "status": st, "message": r["message"] or r["alarm_type"], "first_seen": str(r["timestamp"]),
                    "last_seen": str(r["timestamp"]), "count": 1, "ack_by": "", "ai_comment": ""})
    return out


def list_events(tenant_id=None, status="", severity="", q="", source="", limit=500):
    tenant_id = resolve_tenant(tenant_id)
    sql, args = "SELECT * FROM alm_events WHERE tenant_id=?", [tenant_id]
    for col, val in (("status", status), ("severity", severity), ("source", source if source != "poller" else "")):
        if val:
            sql += f" AND {col}=?"
            args.append(val)
    if q:
        sql += " AND (message LIKE ? OR device_ip LIKE ?)"
        args += [f"%{q}%"] * 2
    sql += " ORDER BY status='resolved', id DESC LIMIT ?"
    args.append(max(1, min(int(limit), 5000)))
    conn = _db()
    try:
        rows = [dict(r) for r in conn.execute(sql, args)] if source != "poller" else []
    finally:
        conn.close()
    if source in ("", "poller"):
        ql = (q or "").lower()
        for p in _poller_alarms(tenant_id, status):
            if (not severity or p["severity"] == severity) and (not ql or ql in f"{p['message']} {p['device_ip']}".lower()):
                rows.append(p)
    rows.sort(key=lambda r: r["last_seen"], reverse=True)
    rows.sort(key=lambda r: r["status"] == "resolved")  # kararlı: aktifler önce, her grupta yeni olan üstte
    return rows[:limit]


def overview(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    ev = list_events(tenant_id, limit=5000)
    act = [e for e in ev if e["status"] == "active"]
    return {"active": len(act), "critical": sum(e["severity"] == "CRITICAL" for e in act),
            "ack": sum(e["status"] == "ack" for e in ev), "rules": len(list_rules(tenant_id)), "mail": mail_enabled()}


# ---------------------------------------------------------------- SNMP trap alıcı (v1/v2c)
def _tlv(b, o=0):
    tag = b[o]
    ln = b[o + 1]
    o += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[o:o + n], "big")
        o += n
    if o + ln > len(b):
        raise ValueError("kısa paket")
    return tag, b[o:o + ln], o + ln


def _oid(v):
    if not v:
        return ""
    parts = [str(v[0] // 40), str(v[0] % 40)]
    n = 0
    for c in v[1:]:
        n = (n << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(str(n))
            n = 0
    return ".".join(parts)


def _val(tag, v):
    if tag == 0x06:
        return _oid(v)
    if tag == 0x04:
        return v.decode("utf-8", "replace")[:120]
    if tag in (0x02, 0x41, 0x42, 0x43, 0x46):
        return str(int.from_bytes(v, "big", signed=(tag == 0x02)))
    if tag == 0x40 and len(v) == 4:
        return socket.inet_ntoa(v)
    return v.hex()[:40]


def parse_trap(data):
    """BER çözümü -> {'version','community','trap_oid','varbinds':[(oid,val)]} ya da None (v1/v2c trap değilse)."""
    try:
        _, body, _ = _tlv(data)
        t, v, o = _tlv(body)
        ver = int.from_bytes(v, "big")
        t, comm, o = _tlv(body, o)
        tag, pdu, _ = _tlv(body, o)
        vbs, trap_oid = [], ""
        if tag == 0xA7 and ver == 1:                       # SNMPv2c-Trap-PDU
            p = 0
            for _ in range(3):
                _, _, p = _tlv(pdu, p)
            _, vb, _ = _tlv(pdu, p)
        elif tag == 0xA4 and ver == 0:                     # v1 Trap-PDU
            p = 0
            _, ent, p = _tlv(pdu, p)
            for _ in range(4):
                _, _, p = _tlv(pdu, p)
            trap_oid = _oid(ent)
            _, vb, _ = _tlv(pdu, p)
        else:
            return None
        p = 0
        while p < len(vb):
            _, pair, p = _tlv(vb, p)
            _, oid, q = _tlv(pair)
            tg, val, _ = _tlv(pair, q)
            o_s, v_s = _oid(oid), _val(tg, val)
            if o_s == "1.3.6.1.6.3.1.1.4.1.0":
                trap_oid = v_s
            else:
                vbs.append((o_s, v_s))
        return {"version": "v2c" if ver == 1 else "v1", "community": comm.decode("utf-8", "replace"),
                "trap_oid": trap_oid or "unknown", "varbinds": vbs}
    except Exception:  # noqa: BLE001
        return None


def handle_trap(data, src_ip, tenant_id=None):
    """Bilinen (envanterdeki) bir cihazdan gelen trap için olay açar. Bilinmeyen kaynak yok sayılır."""
    tenant_id = resolve_tenant(tenant_id)
    t = parse_trap(data)
    if not t or src_ip not in {d["ip"] for d in inventory.list_devices(tenant_id)}:
        return False
    sev = "WARNING"
    if t["trap_oid"].endswith(("1.3.6.1.6.3.1.1.5.3", ".5.3")):       # linkDown
        sev = "CRITICAL"
    elif t["trap_oid"].endswith(".5.4"):                              # linkUp
        sev = "INFO"
    detail = ", ".join(f"{o}={v}" for o, v in t["varbinds"][:4])
    conn = _db()
    try:
        raise_event(conn, f"trap:{src_ip}:{t['trap_oid']}", "trap", src_ip, sev, f"SNMP trap {t['trap_oid']} {detail}".strip(), tenant_id)
        conn.commit()
    finally:
        conn.close()
    return True


def start_trap_listener(port, bind="0.0.0.0"):
    if not port:
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((bind, int(port)))
    except OSError as e:
        log.warning("trap listener %s açılamadı: %s", port, e)
        return False

    def rx():
        while True:
            try:
                data, addr = sock.recvfrom(8192)
                handle_trap(data, addr[0])
            except Exception as e:  # noqa: BLE001
                log.debug("trap rx: %s", e)
    threading.Thread(target=rx, daemon=True, name="trap-rx").start()
    return True


def events_csv(rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLS)
    for r in rows:
        w.writerow([("'" + str(r.get(c, "")) if str(r.get(c, ""))[:1] in ("=", "+", "-", "@") else r.get(c, "")) for c in CSV_COLS])
    return buf.getvalue()


# ---------------------------------------------------------------- SSH cihaz alarmı (günlük tarama, varsayılan kapalı)
import hashlib
import re

_SSH_CRIT = re.compile(r"(emerg|alert|critical|%[A-Z0-9_-]+-[0-2]-|power supply|fan fail|over.?temp|temperature .*(high|alarm)|link.?down|interface .* down|failed)", re.I)
_SSH_WARN = re.compile(r"(warning|%[A-Z0-9_-]+-[3-4]-|flap|err(or)?|denied|authentication fail|unreachable)", re.I)
_ssh_last = {"at": "", "result": ""}


def classify_log_line(line):
    """Günlük satırından önem: CRITICAL / WARNING / None (ilgisiz)."""
    if _SSH_CRIT.search(line):
        return "CRITICAL"
    if _SSH_WARN.search(line):
        return "WARNING"
    return None


def ssh_settings():
    def num(k, d):
        v = str(get_setting(k, str(d)) or d)
        return int(v) if v.isdigit() else d
    return {"enabled": str(get_setting("alarm_ssh_enabled", "0")) == "1", "cred_id": num("alarm_ssh_cred_id", 0),
            "minutes": max(5, min(num("alarm_ssh_minutes", 15), 1440)), "last": _ssh_last["at"], "result": _ssh_last["result"]}


def scan_ssh_logs(secret_key, cred_id, tenant_id=None, per_device=20):
    """SSH'li aktif cihazların günlüğünü okur; önemli satırlar için olay açar (aynı satır tekrar açılmaz). -> (olay, hata)."""
    tenant_id = resolve_tenant(tenant_id)
    from . import configs, vendors
    cred = configs._cred(secret_key, cred_id, tenant_id)
    if not cred or not configs.ssh_available():
        return 0, 1
    opened = errors = 0
    conn = _db()
    try:
        for d in inventory.list_devices(tenant_id, status="ONLINE"):
            if not d.get("ssh_ok"):
                continue
            try:
                out = configs._clean_output(configs._ssh_run(d["ip"], cred, vendors.log_commands(d.get("vendor"))))
            except Exception as e:  # noqa: BLE001
                errors += 1
                log.debug("ssh alarm %s: %s", d["ip"], e)
                continue
            n = 0
            for line in out.split("\n")[-300:]:
                line = line.strip()[:300]
                sev = classify_log_line(line) if len(line) > 12 else None
                if not sev or n >= per_device:
                    continue
                key = "ssh:%s:%s" % (d["ip"], hashlib.sha1(re.sub(r"\d", "#", line).encode()).hexdigest()[:16])
                opened += raise_event(conn, key, "ssh", d["ip"], sev, line, tenant_id)
                n += 1
        conn.commit()
    finally:
        conn.close()
    _ssh_last.update(at=_now(), result="%d yeni olay, %d erişim hatası" % (opened, errors))
    return opened, errors


def start_ssh_scheduler(secret_key, check_s=300):
    def loop():
        due = 0.0
        while True:
            time.sleep(check_s)
            try:
                st = ssh_settings()
                if not st["enabled"] or not st["cred_id"] or time.time() < due:
                    continue
                due = time.time() + st["minutes"] * 60
                for t in all_tenant_ids():
                    scan_ssh_logs(secret_key, st["cred_id"], t)
            except Exception as e:  # noqa: BLE001
                log.warning("ssh alarm scheduler: %s", e)
    threading.Thread(target=loop, daemon=True, name="alarm-ssh-scheduler").start()
