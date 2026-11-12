# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Raporlar: NetFlow top-talker raporu (en çok trafik üreten/alan IP, konuşma, uygulama) CSV/PDF olarak anında veya zamanlanmış
(günlük/haftalık) üretilir; üretilen dosyalar rp_runs'ta saklanır (kiracı başına son 30). E-posta gönderimi varsayılan KAPALI:
ayar report_mail_enabled=1 VE Alarmlar'daki SMTP sunucusu tanımlı olmalı. Akış verisi flows toplayıcısından (flow_rollup) okunur."""
import csv
import io
import logging
import smtplib
import threading
import time
from email.message import EmailMessage

from . import flows
from ..core import get_nms_db, get_setting
from ..core.tenant import all_tenant_ids, resolve_tenant

log = logging.getLogger(__name__)

KEEP_RUNS = 30
EVERY = {"daily": 86400, "weekly": 604800}
FORMATS = ("csv", "pdf")
_schema_ok = set()
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS rp_schedules (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL, win TEXT NOT NULL DEFAULT '24h',
  fmt TEXT NOT NULL DEFAULT 'csv', every TEXT NOT NULL DEFAULT 'daily', email_to TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1, last_run INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS rp_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, schedule_id INTEGER NOT NULL DEFAULT 0,
  name TEXT NOT NULL, fmt TEXT NOT NULL, created_at TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0, mailed INTEGER NOT NULL DEFAULT 0,
  content BLOB);
"""


def _db():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        conn.commit()
        _schema_ok.add(key)
    return conn


def human(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


# ---------------------------------------------------------------- içerik
def sections(window="24h", exporter="", limit=20):
    """-> (başlık, [(bölüm adı, [sütun], [satırlar])]) ; veri okunamazsa ValueError."""
    data, err = flows.report_overview(window, exporter, limit=limit)
    if err:
        raise ValueError(err)
    w = data["window"]
    secs = [
        ("En cok trafik ureten IP'ler (kaynak)", ["IP", "Bayt", "Paket", "Akis"],
         [[r["ip"], r["bytes"], r["pkts"], r["flows"]] for r in data["talkers_src"]]),
        ("En cok trafik alan IP'ler (hedef)", ["IP", "Bayt", "Paket", "Akis"],
         [[r["ip"], r["bytes"], r["pkts"], r["flows"]] for r in data["talkers_dst"]]),
        ("En buyuk konusmalar", ["Kaynak", "Hedef", "Bayt", "Paket", "Akis"],
         [[r["src"], r["dst"], r["bytes"], r["pkts"], r["flows"]] for r in data["conversations"]]),
        ("Uygulamalar", ["Protokol", "Servis", "Bayt", "Paket", "Akis"],
         [[r["proto_name"], r["service"], r["bytes"], r["pkts"], r["flows"]] for r in data["applications"]]),
    ]
    title = f"EMREDIUS NetFlow Top-Talker Raporu - son {w} - toplam {human(data['total_bytes'])}, {data['total_flows']} akis"
    return title, secs


def to_csv(title, secs):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow([title])
    for name, cols, rows in secs:
        w.writerow([])
        w.writerow([name])
        w.writerow(cols)
        w.writerows(rows)
    return out.getvalue().encode("utf-8-sig")


def _pdf_text(s):
    tr = str.maketrans({"ç": "c", "Ç": "C", "ğ": "g", "Ğ": "G", "ı": "i", "İ": "I", "ö": "o", "Ö": "O", "ş": "s", "Ş": "S",
                        "ü": "u", "Ü": "U"})
    s = str(s).translate(tr).encode("latin-1", "replace").decode("latin-1")
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(lines):
    """Düz metin satırlarından minimal çok sayfalı PDF (Helvetica 9pt, A4). Harici kütüphane gerekmez."""
    per_page = 62
    pages = [lines[i:i + per_page] for i in range(0, len(lines), per_page)] or [[]]
    objs = []  # 1: katalog, 2: sayfalar, 3: font, sonra sayfa/içerik çiftleri
    kids = [f"{4 + 2 * i} 0 R" for i in range(len(pages))]
    objs.append("<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(pages)} >>")
    objs.append("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")
    for i, pg in enumerate(pages):
        body = "BT /F1 8 Tf 11 TL 36 806 Td\n" + "".join(f"({_pdf_text(l)}) '\n" for l in pg) + "ET"
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents {5 + 2 * i} 0 R "
                    f"/Resources << /Font << /F1 3 0 R >> >> >>")
        objs.append(f"<< /Length {len(body.encode('latin-1', 'replace'))} >>\nstream\n{body}\nendstream")
    out = bytearray(b"%PDF-1.4\n")
    offs = []
    for n, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{n} 0 obj\n".encode() + o.encode("latin-1", "replace") + b"\nendobj\n"
    x = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for o in offs:
        out += f"{o:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()
    return bytes(out)


def to_pdf(title, secs):
    lines = [title, time.strftime("Olusturma: %Y-%m-%d %H:%M:%S"), ""]
    for name, cols, rows in secs:
        lines += [name, "  " + " | ".join(cols)]
        for r in rows:
            lines.append("  " + " | ".join(human(v) if c == "Bayt" else str(v) for c, v in zip(cols, r)))
        lines.append("")
    wrapped = []
    for l in lines:
        wrapped += [l[i:i + 105] for i in range(0, len(l), 105)] or [""]
    return make_pdf(wrapped)


def build(window="24h", fmt="csv", exporter=""):
    title, secs = sections(window, exporter)
    return (to_pdf(title, secs) if fmt == "pdf" else to_csv(title, secs)), title


# ---------------------------------------------------------------- e-posta (varsayılan kapalı)
def mail_enabled():
    return str(get_setting("report_mail_enabled", "0")) == "1" and bool(get_setting("alarm_smtp_host", ""))


def send_mail(to, subject, filename, content, fmt):
    if not to or not mail_enabled():
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = subject[:200].replace("\n", " ")
        msg["From"] = get_setting("alarm_smtp_from", "emredius@localhost")
        msg["To"] = to
        msg.set_content("EMREDIUS zamanlanmis rapor ektedir.")
        msg.add_attachment(content, maintype="application", subtype="pdf" if fmt == "pdf" else "csv", filename=filename)
        with smtplib.SMTP(get_setting("alarm_smtp_host", ""), int(get_setting("alarm_smtp_port", "25") or 25), timeout=8) as s:
            s.send_message(msg)
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("report mail: %s", e)
        return False


# ---------------------------------------------------------------- üretim / saklama
def generate(name="NetFlow top-talker", window="24h", fmt="csv", schedule_id=0, email_to="", tenant_id=None):
    """Raporu üretip rp_runs'a yazar. -> (run_id, hata)"""
    tenant_id = resolve_tenant(tenant_id)
    fmt = fmt if fmt in FORMATS else "csv"
    window = window if window in flows.WINDOWS else "24h"
    try:
        content, title = build(window, fmt)
    except ValueError as e:
        return 0, str(e)
    fname = f"top-talkers_{window}_{time.strftime('%Y%m%d_%H%M')}.{fmt}"
    mailed = send_mail(email_to, title, fname, content, fmt) if email_to else False
    conn = _db()
    try:
        cur = conn.execute("INSERT INTO rp_runs (tenant_id,schedule_id,name,fmt,created_at,size,mailed,content) VALUES (?,?,?,?,?,?,?,?)",
                           (tenant_id, int(schedule_id), f"{name} ({window})", fmt, time.strftime("%Y-%m-%d %H:%M:%S"),
                            len(content), 1 if mailed else 0, content))
        conn.execute("DELETE FROM rp_runs WHERE tenant_id=? AND id NOT IN (SELECT id FROM rp_runs WHERE tenant_id=? "
                     "ORDER BY id DESC LIMIT ?)", (tenant_id, tenant_id, KEEP_RUNS))
        conn.commit()
        return cur.lastrowid, ""
    finally:
        conn.close()


def list_runs(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        return [dict(r) for r in conn.execute("SELECT id,schedule_id,name,fmt,created_at,size,mailed FROM rp_runs "
                                              "WHERE tenant_id=? ORDER BY id DESC", (tenant_id,))]
    finally:
        conn.close()


def get_run(run_id, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        r = conn.execute("SELECT name,fmt,content FROM rp_runs WHERE id=? AND tenant_id=?", (run_id, tenant_id)).fetchone()
        return (r[0], r[1], bytes(r[2] or b"")) if r else None
    finally:
        conn.close()


def add_schedule(name, window, fmt, every, email_to="", tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    name = (name or "").strip()[:64]
    email_to = (email_to or "").strip()[:120]
    if not name:
        return "Ad gerekli."
    if window not in flows.WINDOWS or fmt not in FORMATS or every not in EVERY:
        return "Pencere, biçim veya sıklık geçersiz."
    if email_to and ("@" not in email_to or any(c in email_to for c in "\r\n ")):
        return "Geçersiz e-posta."
    conn = _db()
    try:
        conn.execute("INSERT INTO rp_schedules (tenant_id,name,win,fmt,every,email_to) VALUES (?,?,?,?,?,?)",
                     (tenant_id, name, window, fmt, every, email_to))
        conn.commit()
    finally:
        conn.close()
    return ""


def list_schedules(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        rows = [dict(r) for r in conn.execute("SELECT * FROM rp_schedules WHERE tenant_id=? ORDER BY id", (tenant_id,))]
    finally:
        conn.close()
    for r in rows:
        r["last"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["last_run"])) if r["last_run"] else "-"
    return rows


def schedule_action(sid, action, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        row = conn.execute("SELECT * FROM rp_schedules WHERE id=? AND tenant_id=?", (sid, tenant_id)).fetchone()
        if not row:
            return False
        if action == "delete":
            conn.execute("DELETE FROM rp_schedules WHERE id=?", (sid,))
        elif action == "toggle":
            conn.execute("UPDATE rp_schedules SET enabled=1-enabled WHERE id=?", (sid,))
        elif action != "run":
            return False
        conn.commit()
    finally:
        conn.close()
    if action == "run":
        run_schedule(dict(row), tenant_id)
    return True


def run_schedule(s, tenant_id):
    rid, err = generate(s["name"], s["win"], s["fmt"], s["id"], s["email_to"], tenant_id)
    conn = _db()
    try:
        conn.execute("UPDATE rp_schedules SET last_run=? WHERE id=?", (int(time.time()), s["id"]))
        conn.commit()
    finally:
        conn.close()
    return rid, err


def run_due(tenant_id=None, now=None):
    """Zamanı gelen etkin zamanlamaları çalıştırır. -> çalışan sayısı"""
    tenant_id = resolve_tenant(tenant_id)
    now = int(now or time.time())
    n = 0
    with _lock:
        for s in list_schedules(tenant_id):
            if s["enabled"] and now - s["last_run"] >= EVERY.get(s["every"], 86400):
                run_schedule(s, tenant_id)
                n += 1
    return n


def start_scheduler(interval_s=60):
    def loop():
        while True:
            time.sleep(interval_s)
            try:
                for t in all_tenant_ids():
                    run_due(t)
            except Exception as e:  # noqa: BLE001
                log.warning("reports scheduler: %s", e)
    threading.Thread(target=loop, daemon=True, name="reports-scheduler").start()
