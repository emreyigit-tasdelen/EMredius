# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""IP Havuzları: FreeRADIUS radippool tablosu (adres satırları) + Framed-Pool atamaları (radreply / radgroupreply).
Havuz üst verisi NMS veritabanında (tenant_id'li); adresler RADIUS veritabanındaki radippool'a yazılır. sqlippool modülü sitede
etkin olmayabilir: etkinse havuz adresleri dağıtır, değilse yalnızca Framed-Pool özniteliği gönderilir."""
import ipaddress
import re
import time

from ..core import get_db, get_nms_db
from ..core.tenant import resolve_tenant
from .radius_users import ServiceError

MAX_ADDRS = 4096
NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,30}")  # radippool.pool_name varchar(30)
_schema_ok = set()

SCHEMA = """
CREATE TABLE IF NOT EXISTS ip_pools (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL UNIQUE,
  start_ip TEXT NOT NULL, end_ip TEXT NOT NULL, note TEXT DEFAULT '', created TEXT DEFAULT '');
"""

RADIPPOOL_DDL = """
CREATE TABLE IF NOT EXISTS radippool (
  id int(11) unsigned NOT NULL AUTO_INCREMENT, pool_name varchar(30) NOT NULL, framedipaddress varchar(15) NOT NULL DEFAULT '',
  nasipaddress varchar(15) NOT NULL DEFAULT '', calledstationid VARCHAR(30) NOT NULL DEFAULT '',
  callingstationid VARCHAR(30) NOT NULL DEFAULT '', expiry_time DATETIME NULL DEFAULT NULL,
  username varchar(64) NOT NULL DEFAULT '', pool_key varchar(30) NOT NULL DEFAULT '',
  PRIMARY KEY (id), KEY radippool_poolname_expire (pool_name, expiry_time), KEY framedipaddress (framedipaddress),
  KEY radippool_nasip_poolkey_ipaddress (nasipaddress, pool_key, framedipaddress)
) ENGINE=InnoDB
"""


def _db():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        conn.commit()
        _schema_ok.add(key)
    return conn


def parse_range(start, end, cidr=""):
    """CIDR veya başlangıç-bitiş -> (başlangıç, bitiş) IPv4Address. Raises ServiceError."""
    try:
        if (cidr or "").strip():
            n = ipaddress.ip_network(cidr.strip(), strict=False)
            if n.version != 4:
                raise ValueError
            hosts = list(n.hosts()) if n.num_addresses > 2 else list(n)
            if not hosts:
                raise ValueError
            a, b = hosts[0], hosts[-1]
        else:
            a, b = ipaddress.IPv4Address((start or "").strip()), ipaddress.IPv4Address((end or "").strip())
    except ValueError:
        raise ServiceError("Geçerli bir IPv4 CIDR veya başlangıç/bitiş adresi girin.") from None
    if int(b) < int(a):
        raise ServiceError("Bitiş adresi başlangıçtan küçük olamaz.")
    if int(b) - int(a) + 1 > MAX_ADDRS:
        raise ServiceError(f"Bir havuz en fazla {MAX_ADDRS} adres içerebilir.")
    return a, b


def _stats():
    """pool_name -> (toplam, kullanımda) radippool'dan; RADIUS DB'ye ulaşılamazsa boş."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pool_name, COUNT(*) AS total, SUM(username IS NOT NULL AND username <> '') AS used "
                        "FROM radippool GROUP BY pool_name")
            return {r["pool_name"]: (int(r["total"] or 0), int(r["used"] or 0)) for r in cur.fetchall()}
    finally:
        conn.close()


def _assignments():
    """pool_name -> {'users': n, 'groups': n}"""
    out = {}
    conn = get_db()
    try:
        with conn.cursor() as cur:
            for tbl, key in (("radreply", "users"), ("radgroupreply", "groups")):
                cur.execute(f"SELECT value, COUNT(DISTINCT {'username' if key == 'users' else 'groupname'}) AS n "
                            f"FROM {tbl} WHERE attribute = 'Framed-Pool' GROUP BY value")
                for r in cur.fetchall():
                    out.setdefault(r["value"], {"users": 0, "groups": 0})[key] = int(r["n"] or 0)
    finally:
        conn.close()
    return out


def list_pools(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    c = _db()
    try:
        pools = [dict(r) for r in c.execute("SELECT * FROM ip_pools WHERE tenant_id=? ORDER BY name", (tenant_id,))]
    finally:
        c.close()
    try:
        stats, asg = _stats(), _assignments()
    except Exception:  # noqa: BLE001  RADIUS DB yok: yalnızca üst veri
        stats, asg = {}, {}
    for p in pools:
        total, used = stats.get(p["name"], (0, 0))
        p.update(total=total, used=used, free=total - used, pct=round(100 * used / total) if total else 0,
                 users=asg.get(p["name"], {}).get("users", 0), groups=asg.get(p["name"], {}).get("groups", 0))
    return pools


def add_pool(name, start="", end="", cidr="", note="", tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    name = (name or "").strip()
    if not NAME_RE.fullmatch(name):
        raise ServiceError("Geçersiz havuz adı (1-30 karakter; harf, rakam ve . _ - kullanılabilir).")
    a, b = parse_range(start, end, cidr)
    c = _db()
    try:
        if c.execute("SELECT 1 FROM ip_pools WHERE name=?", (name,)).fetchone():
            raise ServiceError("Bu havuz adı zaten kullanılıyor.")
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(RADIPPOOL_DDL)  # tablo yoksa oluşturur (FreeRADIUS standart şeması)
                conn.begin()
                cur.executemany("INSERT INTO radippool (pool_name, framedipaddress, nasipaddress, calledstationid, "
                                "callingstationid, username, pool_key) VALUES (%s, %s, '', '', '', '', '')",
                                [(name, str(ipaddress.IPv4Address(i))) for i in range(int(a), int(b) + 1)])
            conn.commit()
        except ServiceError:
            raise
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        c.execute("INSERT INTO ip_pools (tenant_id, name, start_ip, end_ip, note, created) VALUES (?,?,?,?,?,?)",
                  (tenant_id, name, str(a), str(b), (note or "").strip()[:200], time.strftime("%Y-%m-%d %H:%M:%S")))
        c.commit()
    finally:
        c.close()
    return name, int(b) - int(a) + 1


def _owned(c, name, tenant_id):
    row = c.execute("SELECT * FROM ip_pools WHERE name=? AND tenant_id=?", ((name or "").strip(), tenant_id)).fetchone()
    if not row:
        raise ServiceError("Havuz bulunamadı.")
    return row


def delete_pool(name, tenant_id=None):
    """Havuzu ve adres satırlarını siler; atama varsa reddeder (kullanıcı/grup verisine dokunmaz)."""
    tenant_id = resolve_tenant(tenant_id)
    c = _db()
    try:
        row = _owned(c, name, tenant_id)
        a = _assignments().get(row["name"], {})
        if a.get("users") or a.get("groups"):
            raise ServiceError(f"Havuz atanmış ({a.get('users', 0)} kullanıcı, {a.get('groups', 0)} grup); önce atamaları kaldırın.")
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM radippool WHERE pool_name = %s", (row["name"],))
            conn.commit()
        finally:
            conn.close()
        c.execute("DELETE FROM ip_pools WHERE id=?", (row["id"],))
        c.commit()
        return row["name"]
    finally:
        c.close()


def assign(name, kind, target, tenant_id=None):
    """Kullanıcıya (radreply) veya gruba (radgroupreply) Framed-Pool := havuz atar; öncekini değiştirir."""
    tenant_id = resolve_tenant(tenant_id)
    target = (target or "").strip()
    if kind not in ("user", "group") or not target or len(target) > 64:
        raise ServiceError("Atama hedefi geçersiz.")
    c = _db()
    try:
        pool = _owned(c, name, tenant_id)["name"]
    finally:
        c.close()
    tbl, col = ("radreply", "username") if kind == "user" else ("radgroupreply", "groupname")
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(f"DELETE FROM {tbl} WHERE {col} = %s AND attribute = 'Framed-Pool'", (target,))
            cur.execute(f"INSERT INTO {tbl} ({col}, attribute, op, value) VALUES (%s, 'Framed-Pool', ':=', %s)", (target, pool))
        conn.commit()
    finally:
        conn.close()
    return pool, target


def unassign(name, kind, target, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    c = _db()
    try:
        pool = _owned(c, name, tenant_id)["name"]
    finally:
        c.close()
    tbl, col = ("radreply", "username") if kind == "user" else ("radgroupreply", "groupname")
    conn = get_db()
    try:
        with conn.cursor() as cur:
            n = cur.execute(f"DELETE FROM {tbl} WHERE {col} = %s AND attribute = 'Framed-Pool' AND value = %s", ((target or "").strip(), pool))
        conn.commit()
        return n
    finally:
        conn.close()


def assignments_of(name, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    c = _db()
    try:
        pool = _owned(c, name, tenant_id)["name"]
    finally:
        c.close()
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT username FROM radreply WHERE attribute='Framed-Pool' AND value=%s ORDER BY username LIMIT 500", (pool,))
            users = [r["username"] for r in cur.fetchall()]
            cur.execute("SELECT DISTINCT groupname FROM radgroupreply WHERE attribute='Framed-Pool' AND value=%s ORDER BY groupname LIMIT 500", (pool,))
            groups = [r["groupname"] for r in cur.fetchall()]
        return users, groups
    finally:
        conn.close()
