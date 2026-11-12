# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""APN envanteri: hatlar (lines), sağlayıcılar (providers), konumlar (locations). Tablolar NMS veritabanında, tenant_id'li.
Hat -> sağlayıcı, konum, NAS IP'si, IP havuzu (ippools) ve profil (RADIUS grubu = Gruplar & Profiller) ile ilişkilendirilir.
Salt envanterdir: RADIUS kayıtlarına yazmaz."""
import time

from ..core import GROUPNAME_RE, get_nms_db, is_valid_ip
from ..core.tenant import resolve_tenant
from .radius_users import ServiceError

_schema_ok = set()
STATUSES = {"active": "Aktif", "suspended": "Askıda", "retired": "Kullanım dışı"}
MAX_ROWS = 5000

SCHEMA = """
CREATE TABLE IF NOT EXISTS apn_providers (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL,
  contact TEXT DEFAULT '', note TEXT DEFAULT '', created TEXT DEFAULT '', UNIQUE(tenant_id, name));
CREATE TABLE IF NOT EXISTS apn_locations (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL,
  address TEXT DEFAULT '', note TEXT DEFAULT '', created TEXT DEFAULT '', UNIQUE(tenant_id, name));
CREATE TABLE IF NOT EXISTS apn_lines (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL,
  iccid TEXT DEFAULT '', msisdn TEXT DEFAULT '', provider_id INTEGER, location_id INTEGER, nas_ip TEXT DEFAULT '',
  pool_name TEXT DEFAULT '', profile TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'active', note TEXT DEFAULT '',
  created TEXT DEFAULT '', UNIQUE(tenant_id, name));
"""
# alan adı -> (başlık, azami uzunluk)
SPECS = {
    "providers": {"table": "apn_providers", "title": "Sağlayıcılar", "fields": {"name": ("Ad", 64), "contact": ("İletişim", 120), "note": ("Not", 200)}},
    "locations": {"table": "apn_locations", "title": "Konumlar", "fields": {"name": ("Ad", 64), "address": ("Adres", 200), "note": ("Not", 200)}},
    "lines": {"table": "apn_lines", "title": "Hatlar",
              "fields": {"name": ("Ad", 64), "iccid": ("ICCID", 24), "msisdn": ("MSISDN", 20), "note": ("Not", 200)}},
}


def _db():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        conn.commit()
        _schema_ok.add(key)
    return conn


def _spec(kind):
    if kind not in SPECS:
        raise ServiceError("Geçersiz kayıt türü.")
    return SPECS[kind]


def _clean(kind, form, conn, tenant_id):
    spec = _spec(kind)
    out = {}
    for col, (label, maxlen) in spec["fields"].items():
        v = (form.get(col) or "").strip()
        if len(v) > maxlen:
            raise ServiceError(f"{label} en fazla {maxlen} karakter olabilir.")
        out[col] = v
    if not out["name"]:
        raise ServiceError("Ad gerekli.")
    if kind != "lines":
        return out
    for col, tbl in (("provider_id", "apn_providers"), ("location_id", "apn_locations")):
        raw = (form.get(col) or "").strip()
        if raw:
            if not raw.isdigit() or not conn.execute(f"SELECT 1 FROM {tbl} WHERE id=? AND tenant_id=?", (int(raw), tenant_id)).fetchone():
                raise ServiceError("Seçilen sağlayıcı/konum bulunamadı.")
            out[col] = int(raw)
        else:
            out[col] = None
    nas = (form.get("nas_ip") or "").strip()
    if nas and not is_valid_ip(nas):
        raise ServiceError("NAS IP adresi geçersiz.")
    prof = (form.get("profile") or "").strip()
    if prof and not GROUPNAME_RE.fullmatch(prof):
        raise ServiceError("Profil (grup) adı geçersiz.")
    status = (form.get("status") or "active").strip()
    if status not in STATUSES:
        raise ServiceError("Geçersiz durum.")
    out.update(nas_ip=nas, pool_name=(form.get("pool_name") or "").strip()[:48], profile=prof, status=status)
    return out


def save(kind, form, rec_id=None, tenant_id=None):
    """Ekler (rec_id yok) ya da günceller. Kayıt adını döndürür."""
    tenant_id = resolve_tenant(tenant_id)
    c = _db()
    try:
        d = _clean(kind, form, c, tenant_id)
        tbl = _spec(kind)["table"]
        try:
            if rec_id is None:
                if c.execute(f"SELECT COUNT(*) FROM {tbl} WHERE tenant_id=?", (tenant_id,)).fetchone()[0] >= MAX_ROWS:
                    raise ServiceError("Kayıt sınırına ulaşıldı.")
                cols = ["tenant_id", "created"] + list(d)
                c.execute(f"INSERT INTO {tbl} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                          [tenant_id, time.strftime("%Y-%m-%d %H:%M:%S")] + list(d.values()))
            else:
                if not c.execute(f"SELECT 1 FROM {tbl} WHERE id=? AND tenant_id=?", (rec_id, tenant_id)).fetchone():
                    raise ServiceError("Kayıt bulunamadı.")
                c.execute(f"UPDATE {tbl} SET {','.join(k + '=?' for k in d)} WHERE id=? AND tenant_id=?", list(d.values()) + [rec_id, tenant_id])
        except Exception as e:  # noqa: BLE001  UNIQUE ihlali dahil
            if isinstance(e, ServiceError):
                raise
            raise ServiceError("Bu ad zaten kullanılıyor.") from None
        c.commit()
        return d["name"]
    finally:
        c.close()


def delete(kind, rec_id, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    tbl = _spec(kind)["table"]
    c = _db()
    try:
        row = c.execute(f"SELECT name FROM {tbl} WHERE id=? AND tenant_id=?", (rec_id, tenant_id)).fetchone()
        if not row:
            raise ServiceError("Kayıt bulunamadı.")
        col = {"providers": "provider_id", "locations": "location_id"}.get(kind)
        if col and c.execute(f"SELECT 1 FROM apn_lines WHERE {col}=? AND tenant_id=?", (rec_id, tenant_id)).fetchone():
            raise ServiceError("Bu kayda bağlı hatlar var; önce hatları değiştirin.")
        c.execute(f"DELETE FROM {tbl} WHERE id=? AND tenant_id=?", (rec_id, tenant_id))
        c.commit()
        return row["name"]
    finally:
        c.close()


def get(kind, rec_id, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    c = _db()
    try:
        row = c.execute(f"SELECT * FROM {_spec(kind)['table']} WHERE id=? AND tenant_id=?", (rec_id, tenant_id)).fetchone()
        if not row:
            raise ServiceError("Kayıt bulunamadı.")
        return dict(row)
    finally:
        c.close()


def overview(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    c = _db()
    try:
        providers = [dict(r) for r in c.execute("SELECT * FROM apn_providers WHERE tenant_id=? ORDER BY name", (tenant_id,))]
        locations = [dict(r) for r in c.execute("SELECT * FROM apn_locations WHERE tenant_id=? ORDER BY name", (tenant_id,))]
        lines = [dict(r) for r in c.execute("""
            SELECT l.*, p.name AS provider, o.name AS location FROM apn_lines l
            LEFT JOIN apn_providers p ON p.id = l.provider_id LEFT JOIN apn_locations o ON o.id = l.location_id
            WHERE l.tenant_id=? ORDER BY l.name""", (tenant_id,))]
    finally:
        c.close()
    return {"providers": providers, "locations": locations, "lines": lines}
