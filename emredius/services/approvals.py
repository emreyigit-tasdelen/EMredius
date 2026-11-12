# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Misafir onayları (sponsor onayı): erişim talepleri bekler; onaylanınca mevcut kupon üretimiyle (GUEST- hesabı) kimlik bilgisi çıkar.
Talepler NMS veritabanında, tenant_id'li. Reddedilen/onaylanan kayıt yalnızca talep listesinden silinir (RADIUS hesabına dokunulmaz)."""
import time

from ..core import get_db, get_nms_db
from ..core.tenant import resolve_tenant
from . import vouchers
from .radius_users import ServiceError

_schema_ok = set()
STATUSES = {"pending": "Bekliyor", "approved": "Onaylandı", "rejected": "Reddedildi"}
MAX_PENDING = 500

SCHEMA = """
CREATE TABLE IF NOT EXISTS guest_approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL, email TEXT DEFAULT '',
  sponsor TEXT DEFAULT '', reason TEXT DEFAULT '', duration TEXT NOT NULL DEFAULT '1d', status TEXT NOT NULL DEFAULT 'pending',
  code TEXT DEFAULT '', decided_by TEXT DEFAULT '', decided_at TEXT DEFAULT '', created TEXT DEFAULT '');
"""


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


def list_requests(tenant_id=None, status=""):
    tenant_id = resolve_tenant(tenant_id)
    c = _db()
    try:
        q, args = "SELECT * FROM guest_approvals WHERE tenant_id=?", [tenant_id]
        if status in STATUSES:
            q, args = q + " AND status=?", args + [status]
        return [dict(r) for r in c.execute(q + " ORDER BY (status='pending') DESC, id DESC LIMIT 1000", args)]
    finally:
        c.close()


def add_request(name, email="", sponsor="", reason="", duration="1d", tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    name, email, sponsor, reason = [(v or "").strip() for v in (name, email, sponsor, reason)]
    if not name or len(name) > 80 or len(email) > 120 or len(sponsor) > 80 or len(reason) > 200:
        raise ServiceError("Ad gerekli; alanlar en fazla 80/120/80/200 karakter olabilir.")
    if duration not in vouchers.VOUCHER_DURATIONS:
        raise ServiceError("Geçersiz süre.")
    c = _db()
    try:
        if c.execute("SELECT COUNT(*) FROM guest_approvals WHERE tenant_id=? AND status='pending'", (tenant_id,)).fetchone()[0] >= MAX_PENDING:
            raise ServiceError("Bekleyen talep sınırına ulaşıldı.")
        c.execute("INSERT INTO guest_approvals (tenant_id, name, email, sponsor, reason, duration, created) VALUES (?,?,?,?,?,?,?)",
                  (tenant_id, name, email, sponsor, reason, duration, _now()))
        c.commit()
    finally:
        c.close()
    return name


def _pending(c, rec_id, tenant_id):
    row = c.execute("SELECT * FROM guest_approvals WHERE id=? AND tenant_id=?", (rec_id, tenant_id)).fetchone()
    if not row:
        raise ServiceError("Talep bulunamadı.")
    if row["status"] != "pending":
        raise ServiceError("Talep zaten karara bağlanmış.")
    return row


def approve(rec_id, user, tenant_id=None):
    """Kupon üretir (GUEST- hesabı) ve talebe bağlar. Returns (code, pin)."""
    tenant_id = resolve_tenant(tenant_id)
    c = _db()
    try:
        row = _pending(c, rec_id, tenant_id)
        desc = f"Onaylı misafir: {row['name']}" + (f" (sponsor {row['sponsor']})" if row["sponsor"] else "")
        res = vouchers.generate_vouchers(vouchers.validate_generate(1, row["duration"], "first_login", "", "", desc[:255]))
        code = res["codes"][0]
        c.execute("UPDATE guest_approvals SET status='approved', code=?, decided_by=?, decided_at=? WHERE id=?",
                  (code, (user or "")[:64], _now(), rec_id))
        c.commit()
    finally:
        c.close()
    return code, credentials(code)


def credentials(code):
    """Onaylanan hesabın PIN'i (radcheck); bulunamazsa boş."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM radcheck WHERE username=%s AND attribute='Cleartext-Password' LIMIT 1", (code,))
            r = cur.fetchone()
            return r["value"] if r else ""
    finally:
        conn.close()


def reject(rec_id, user, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    c = _db()
    try:
        row = _pending(c, rec_id, tenant_id)
        c.execute("UPDATE guest_approvals SET status='rejected', decided_by=?, decided_at=? WHERE id=?", ((user or "")[:64], _now(), rec_id))
        c.commit()
        return row["name"]
    finally:
        c.close()


def delete_request(rec_id, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    c = _db()
    try:
        row = c.execute("SELECT name, status FROM guest_approvals WHERE id=? AND tenant_id=?", (rec_id, tenant_id)).fetchone()
        if not row:
            raise ServiceError("Talep bulunamadı.")
        if row["status"] == "pending":
            raise ServiceError("Bekleyen talep silinemez; önce karara bağlayın.")
        c.execute("DELETE FROM guest_approvals WHERE id=?", (rec_id,))
        c.commit()
        return row["name"]
    finally:
        c.close()
