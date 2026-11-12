# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Kara liste / Karantina / Uygulama kayıtları. YALNIZCA kayıt ve işaretleme: veri silinmez, NAS/cihaza (CoA, VLAN, ACL)
hiçbir şey yazılmaz. Her işlem nac_events'e düşer (Uygulama Kayıtları sayfası). Tablolar NMS veritabanında, tenant_id'li."""
import csv
import io
import re
import threading
import time

from ..core import USERNAME_RE, get_nms_db, normalize_mac
from ..core.tenant import resolve_tenant

KINDS = {"blacklist": "Kara Liste", "quarantine": "Karantina"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS nac_marks (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, kind TEXT NOT NULL,
  mac TEXT NOT NULL DEFAULT '', username TEXT NOT NULL DEFAULT '', match TEXT NOT NULL DEFAULT 'exact',
  reason TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, expires_at TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1, released_by TEXT NOT NULL DEFAULT '', released_at TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS nac_marks_k ON nac_marks(tenant_id, kind, active);
CREATE TABLE IF NOT EXISTS nac_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, at TEXT NOT NULL, kind TEXT NOT NULL,
  action TEXT NOT NULL, mac TEXT NOT NULL DEFAULT '', username TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS nac_events_t ON nac_events(tenant_id, id);
"""
_schema_ok = set()
_lock = threading.Lock()


class MarkError(ValueError):
    pass


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


def _event(conn, tenant_id, kind, action, mac, username, actor, detail):
    conn.execute("INSERT INTO nac_events (tenant_id,at,kind,action,mac,username,actor,detail) VALUES (?,?,?,?,?,?,?,?)",
                 (tenant_id, _now(), kind, action, mac, username, actor, detail[:300]))


def _expire(conn, tenant_id):
    now = _now()
    for r in conn.execute("SELECT id,kind,mac,username FROM nac_marks WHERE tenant_id=? AND active=1 AND expires_at<>'' "
                          "AND expires_at<=?", (tenant_id, now)).fetchall():
        conn.execute("UPDATE nac_marks SET active=0, released_by='sistem', released_at=? WHERE id=?", (now, r["id"]))
        _event(conn, tenant_id, r["kind"], "expire", r["mac"], r["username"], "sistem", "süre doldu")


def add_mark(kind, mac="", username="", reason="", hours=0, actor="", tenant_id=None, match="exact"):
    if kind not in KINDS:
        raise MarkError("Geçersiz tür.")
    mac = (mac or "").strip()
    username = (username or "").strip()
    match = "regex" if match == "regex" else "exact"
    if match == "regex":
        for v in (mac, username):
            if v:
                if len(v) > 200:
                    raise MarkError("Düzenli ifade çok uzun.")
                try:
                    re.compile(v)
                except re.error:
                    raise MarkError("Geçersiz düzenli ifade.")
    elif mac:
        mac = normalize_mac(mac) or ""
        if not mac:
            raise MarkError("Geçersiz MAC adresi.")
    if match == "exact" and username and not USERNAME_RE.match(username):
        raise MarkError("Geçersiz kullanıcı adı.")
    if not mac and not username:
        raise MarkError("MAC veya kullanıcı adı gerekli.")
    try:
        hours = max(0, min(int(hours or 0), 24 * 365))
    except (TypeError, ValueError):
        raise MarkError("Geçersiz süre.")
    exp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + hours * 3600)) if hours else ""
    tenant_id = resolve_tenant(tenant_id)
    with _lock:
        conn = _db()
        try:
            _expire(conn, tenant_id)
            dup = conn.execute("SELECT 1 FROM nac_marks WHERE tenant_id=? AND kind=? AND active=1 AND mac=? AND username=? AND match=?",
                               (tenant_id, kind, mac, username, match)).fetchone()
            if dup:
                raise MarkError("Bu kayıt zaten etkin.")
            cur = conn.execute("INSERT INTO nac_marks (tenant_id,kind,mac,username,match,reason,created_by,created_at,expires_at) "
                               "VALUES (?,?,?,?,?,?,?,?,?)", (tenant_id, kind, mac, username, match, (reason or "")[:200], actor,
                                                            _now(), exp))
            _event(conn, tenant_id, kind, "add", mac, username, actor, (reason or "")[:200])
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def release(mark_id, actor="", tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    with _lock:
        conn = _db()
        try:
            r = conn.execute("SELECT * FROM nac_marks WHERE id=? AND tenant_id=? AND active=1", (mark_id, tenant_id)).fetchone()
            if not r:
                return False
            conn.execute("UPDATE nac_marks SET active=0, released_by=?, released_at=? WHERE id=?", (actor, _now(), mark_id))
            _event(conn, tenant_id, r["kind"], "release", r["mac"], r["username"], actor, "")
            conn.commit()
            return True
        finally:
            conn.close()


def list_marks(kind, active_only=True, tenant_id=None, limit=1000):
    tenant_id = resolve_tenant(tenant_id)
    with _lock:
        conn = _db()
        try:
            _expire(conn, tenant_id)
            conn.commit()
            sql = "SELECT * FROM nac_marks WHERE tenant_id=? AND kind=?" + (" AND active=1" if active_only else "")
            return [dict(r) for r in conn.execute(sql + " ORDER BY id DESC LIMIT ?",
                                                  (tenant_id, kind, max(1, min(int(limit), 5000))))]
        finally:
            conn.close()


def status_of(mac="", username="", tenant_id=None):
    """Bu MAC veya kullanıcı için etkin işaretler (kara liste / karantina)."""
    tenant_id = resolve_tenant(tenant_id)
    mac = (normalize_mac(mac) or "") if mac else ""
    if not mac and not username:
        return []
    with _lock:
        conn = _db()
        try:
            _expire(conn, tenant_id)
            conn.commit()
            rows = [dict(r) for r in conn.execute("SELECT * FROM nac_marks WHERE tenant_id=? AND active=1", (tenant_id,))]
            return [r for r in rows if _hit(r, mac, username or "")]
        finally:
            conn.close()


def list_events(tenant_id=None, limit=500):
    tenant_id = resolve_tenant(tenant_id)
    with _lock:
        conn = _db()
        try:
            return [dict(r) for r in conn.execute("SELECT * FROM nac_events WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                                                  (tenant_id, max(1, min(int(limit), 5000))))]
        finally:
            conn.close()


def _hit(row, mac, username):
    if row["match"] == "regex":
        for pat, val in ((row["mac"], mac), (row["username"], username)):
            if pat and val:
                try:
                    if re.fullmatch(pat, val, re.I):
                        return True
                except re.error:
                    pass
        return False
    return bool((row["mac"] and row["mac"] == mac) or (row["username"] and row["username"] == username))


IMPORT_COLS = ["kind", "match", "value", "reason", "expires_at"]
TEMPLATE = ",".join(IMPORT_COLS) + chr(13) + chr(10) + "mac,exact,aa:bb:cc:dd:ee:ff,kayip cihaz,2027-01-01 00:00:00" + chr(13) + chr(10) + "user,regex,^test.*,test hesaplari," + chr(13) + chr(10)


def export_csv(kind, tenant_id=None):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(IMPORT_COLS)
    for m in reversed(list_marks(kind, tenant_id=tenant_id, limit=5000)):
        w.writerow(["mac" if m["mac"] else "user", m["match"], m["mac"] or m["username"], m["reason"], m["expires_at"]])
    return out.getvalue()


def import_csv(kind, text, actor="", tenant_id=None):
    """kind,match,value,reason,expires_at sütunlu CSV -> {"added", "errors": [...]}. Hatalı satırlar atlanır."""
    added, errors = 0, []
    for n, row in enumerate(csv.DictReader(io.StringIO(text or "")), start=2):
        if n > 5001:
            errors.append("En fazla 5000 satır alınır.")
            break
        k = (row.get("kind") or "").strip().lower()
        val = (row.get("value") or "").strip()
        exp = (row.get("expires_at") or "").strip()
        hours = 0
        if exp:
            try:
                hours = max(1, int((time.mktime(time.strptime(exp[:19], "%Y-%m-%d %H:%M:%S")) - time.time()) / 3600) + 1)
            except ValueError:
                errors.append(f"satır {n}: geçersiz expires_at")
                continue
            if hours <= 1 and time.mktime(time.strptime(exp[:19], "%Y-%m-%d %H:%M:%S")) < time.time():
                errors.append(f"satır {n}: süresi geçmiş")
                continue
        if k not in ("mac", "user"):
            errors.append(f"satır {n}: kind mac veya user olmalı")
            continue
        try:
            add_mark(kind, mac=val if k == "mac" else "", username=val if k == "user" else "", reason=row.get("reason") or "",
                     hours=hours, actor=actor, tenant_id=tenant_id, match=(row.get("match") or "exact").strip().lower())
            added += 1
        except MarkError as e:
            errors.append(f"satır {n}: {e}")
    return {"added": added, "errors": errors[:50]}
