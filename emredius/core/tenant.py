# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Çok kiracılı yapı: kiracı tablosu, yönetici->kiracı eşlemesi ve istek bağlamındaki geçerli kiracı.
Servisler `tenant_id=None` alır; None ise `resolve_tenant` geçerli kiracıyı verir (istek yoksa 1). Süper yönetici oturumda kiracı
değiştirebilir; diğer yöneticiler atandıkları kiracıda (atama yoksa 1) çalışır. API (/api/v1/*) `?tenant=<id>` ile kiracı seçer."""
import time

from flask import g, has_request_context, request, session

from .db import get_nms_db

DEFAULT_TENANT = 1
_schema_ok = set()

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, created TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS tenant_admins (
  username TEXT PRIMARY KEY, tenant_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tenant_owner (
  kind TEXT NOT NULL, okey TEXT NOT NULL, tenant_id INTEGER NOT NULL, PRIMARY KEY (kind, okey));
"""
# RADIUS/TACACS kayıtları çekirdek tablolara dokunmadan bu eşleme tablosuyla kiracıya bağlanır; kaydı olmayan = Varsayılan kiracı
OWNER_KINDS = ("radius_user", "nas", "tacacs_client", "tacacs_user")
# kiracıya ait veri tutan tablolar (kiracı silinirken boş olmalı)
DATA_TABLES = ["inv_devices", "inv_ranges", "topo_links", "eq_ports", "eq_macs", "eq_chassis", "watch_targets", "alm_rules",
               "alm_events", "dash_boards", "cfg_creds", "cfg_backups", "cfg_templates", "cfg_rules", "ipam_subnets", "ipam_addrs",
               "flow_rollup"]


def _db():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        conn.execute("INSERT OR IGNORE INTO tenants (id, name, created) VALUES (1, 'Varsayılan', ?)", (time.strftime("%Y-%m-%d %H:%M:%S"),))
        conn.commit()
        _schema_ok.add(key)
    return conn


def list_tenants():
    conn = _db()
    try:
        admins = {}
        for r in conn.execute("SELECT username, tenant_id FROM tenant_admins ORDER BY username"):
            admins.setdefault(r[1], []).append(r[0])
        return [{"id": r["id"], "name": r["name"], "created": r["created"], "admins": admins.get(r["id"], [])}
                for r in conn.execute("SELECT * FROM tenants ORDER BY id")]
    finally:
        conn.close()


def all_tenant_ids():
    try:
        return [t["id"] for t in list_tenants()] or [DEFAULT_TENANT]
    except Exception:  # noqa: BLE001
        return [DEFAULT_TENANT]


def add_tenant(name):
    name = (name or "").strip()[:64]
    if not name:
        return "Kiracı adı gerekli."
    conn = _db()
    try:
        if conn.execute("SELECT 1 FROM tenants WHERE name=?", (name,)).fetchone():
            return "Bu ad zaten kullanılıyor."
        conn.execute("INSERT INTO tenants (name, created) VALUES (?, ?)", (name, time.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
    finally:
        conn.close()
    return ""


def rename_tenant(tid, name):
    name = (name or "").strip()[:64]
    if not name:
        return "Kiracı adı gerekli."
    conn = _db()
    try:
        if conn.execute("SELECT 1 FROM tenants WHERE name=? AND id!=?", (name, tid)).fetchone():
            return "Bu ad zaten kullanılıyor."
        n = conn.execute("UPDATE tenants SET name=? WHERE id=?", (name, tid)).rowcount
        conn.commit()
        return "" if n else "Kiracı yok."
    finally:
        conn.close()


def tenant_usage(conn, tid):
    n = 0
    for t in DATA_TABLES:
        try:
            n += conn.execute(f"SELECT COUNT(*) FROM {t} WHERE tenant_id=?", (tid,)).fetchone()[0]  # noqa: S608 (sabit tablo adları)
        except Exception:  # noqa: BLE001
            pass
    return n


def delete_tenant(tid):
    """Varsayılan kiracı ve verisi olan kiracı silinmez (veri silme yok)."""
    if tid == DEFAULT_TENANT:
        return "Varsayılan kiracı silinemez."
    conn = _db()
    try:
        if not conn.execute("SELECT 1 FROM tenants WHERE id=?", (tid,)).fetchone():
            return "Kiracı yok."
        if tenant_usage(conn, tid):
            return "Kiracıda veri var; önce verisi taşınmalı/temizlenmeli (otomatik silinmez)."
        conn.execute("DELETE FROM tenant_admins WHERE tenant_id=?", (tid,))
        conn.execute("DELETE FROM tenants WHERE id=?", (tid,))
        conn.commit()
    finally:
        conn.close()
    return ""


def assign_admin(username, tid):
    username = (username or "").strip()[:64]
    if not username:
        return "Kullanıcı adı gerekli."
    conn = _db()
    try:
        if not conn.execute("SELECT 1 FROM tenants WHERE id=?", (tid,)).fetchone():
            return "Kiracı yok."
        conn.execute("INSERT INTO tenant_admins (username, tenant_id) VALUES (?, ?) ON CONFLICT(username) DO UPDATE SET tenant_id=excluded.tenant_id",
                     (username, tid))
        conn.commit()
    finally:
        conn.close()
    return ""


def unassign_admin(username):
    conn = _db()
    try:
        conn.execute("DELETE FROM tenant_admins WHERE username=?", ((username or "")[:64],))
        conn.commit()
    finally:
        conn.close()


def tenant_exists(tid):
    conn = _db()
    try:
        return conn.execute("SELECT 1 FROM tenants WHERE id=?", (tid,)).fetchone() is not None
    finally:
        conn.close()


def admin_tenant(username):
    conn = _db()
    try:
        r = conn.execute("SELECT tenant_id FROM tenant_admins WHERE username=?", ((username or "")[:64],)).fetchone()
        return r[0] if r else DEFAULT_TENANT
    finally:
        conn.close()


def current_tenant():
    if not has_request_context():
        return DEFAULT_TENANT
    cached = g.get("_tenant")
    if cached:
        return cached
    t = DEFAULT_TENANT
    try:
        if request.path.startswith("/api/v1/"):
            asked = request.args.get("tenant", type=int)
            t = asked if asked and tenant_exists(asked) else DEFAULT_TENANT
        elif session.get("role") == "superadmin":
            asked = session.get("tenant_id") or DEFAULT_TENANT
            t = asked if asked == DEFAULT_TENANT or tenant_exists(asked) else DEFAULT_TENANT
        else:
            t = admin_tenant(session.get("user"))
    except Exception:  # noqa: BLE001
        t = DEFAULT_TENANT
    g._tenant = t
    return t


def resolve_tenant(t):
    return current_tenant() if t is None else t


def current_tenant_name():
    try:
        tid = current_tenant()
        return next((x["name"] for x in list_tenants() if x["id"] == tid), "")
    except Exception:  # noqa: BLE001
        return ""


def set_owner(kind, key, tid=None):
    """Kaydı kiracıya bağlar (tid None -> geçerli kiracı). Varsayılan kiracıya bağlamak eşlemeyi siler."""
    if kind not in OWNER_KINDS or not str(key or "").strip():
        return "Geçersiz kayıt."
    tid = resolve_tenant(tid)
    key = str(key).strip().lower()[:128]
    conn = _db()
    try:
        if tid != DEFAULT_TENANT and not conn.execute("SELECT 1 FROM tenants WHERE id=?", (tid,)).fetchone():
            return "Kiracı yok."
        if tid == DEFAULT_TENANT:
            conn.execute("DELETE FROM tenant_owner WHERE kind=? AND okey=?", (kind, key))
        else:
            conn.execute("INSERT INTO tenant_owner (kind, okey, tenant_id) VALUES (?,?,?) ON CONFLICT(kind, okey) DO UPDATE SET tenant_id=excluded.tenant_id",
                         (kind, key, tid))
        conn.commit()
    finally:
        conn.close()
    return ""


def set_owners(kind, keys, tid=None):
    """Toplu bağlama; eşleme hatası asıl işlemi bozmaz."""
    for k in keys:
        try:
            set_owner(kind, k, tid)
        except Exception:  # noqa: BLE001
            pass


def filter_owned(kind, rows, keyfn, tid=None):
    """Satırları kiracıya göre süzer. Eşleme tablosu okunamazsa süzme yapılmaz (tek kiracı davranışı korunur)."""
    tid = resolve_tenant(tid)
    try:
        conn = _db()
        try:
            owners = {r[0]: r[1] for r in conn.execute("SELECT okey, tenant_id FROM tenant_owner WHERE kind=?", (kind,))}
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        return list(rows)
    return [r for r in rows if owners.get(str(keyfn(r) or "").strip().lower(), DEFAULT_TENANT) == tid]
