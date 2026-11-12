# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Bildirimler: kullanıcı başına gelen kutusu.
Olaylar (`publish`) bir sayfa anahtarına (page_key: ipscan, snmp, alarms ...) bağlıdır ve herkese değil, o sayfaya yetkisi olan
rollere düşer. Bir role sayfa yetkisi verildiği an `notif_access.since_ts` olarak kaydedilir; yalnızca o andan SONRAKİ olaylar
görünür, öncekiler asla gelmez. Yetki kalkınca satır silinir (bildirimler gizlenir), tekrar verilirse yeni since_ts başlar.
Çevrimdışı kullanıcı girdiğinde gelen kutusunu görür: bildirimler kalıcıdır, okundu durumu kullanıcı başınadır.
Hedefli bildirim (`target_user`) yalnızca o kullanıcıya düşer. Veriler NMS SQLite veritabanındadır (tenant_id'li)."""
import logging
import threading
import time

from ..core import get_nms_db
from ..core import rbac
from ..core.tenant import resolve_tenant

log = logging.getLogger(__name__)

RETENTION_DAYS = 30
MAX_PER_TENANT = 2000
SEVERITIES = ("info", "success", "warning", "danger")
_schema_ok = set()
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, page_key TEXT NOT NULL DEFAULT '',
  target_user TEXT NOT NULL DEFAULT '', ntype TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT 'info',
  title TEXT NOT NULL, body TEXT DEFAULT '', link TEXT DEFAULT '', dedupe_key TEXT DEFAULT '', created_ts REAL NOT NULL);
CREATE INDEX IF NOT EXISTS notifications_t ON notifications(tenant_id, created_ts);
CREATE TABLE IF NOT EXISTS notif_access (
  role_key TEXT NOT NULL, page_key TEXT NOT NULL, since_ts REAL NOT NULL, PRIMARY KEY (role_key, page_key));
CREATE TABLE IF NOT EXISTS notif_read (user TEXT NOT NULL, notif_id INTEGER NOT NULL, PRIMARY KEY (user, notif_id));
CREATE TABLE IF NOT EXISTS known_hosts (tenant_id INTEGER NOT NULL, ip TEXT NOT NULL, first_seen REAL NOT NULL, PRIMARY KEY (tenant_id, ip));
CREATE TABLE IF NOT EXISTS notif_state (user TEXT PRIMARY KEY, read_all_ts REAL NOT NULL DEFAULT 0);
"""


def _db():
    conn = get_nms_db()
    key = conn.execute("PRAGMA database_list").fetchone()[2]
    if key not in _schema_ok:
        conn.executescript(SCHEMA)
        conn.commit()
        _schema_ok.add(key)
    return conn


# ---------------------------------------------------------------- yetki anı (since_ts)
def sync_role(conn, role_key, perms=None, now=None):
    """notif_access'i rolün güncel sayfa yetkileriyle eşler: yeni sayfa -> since_ts=şimdi, kalkan sayfa -> silinir."""
    now = now or time.time()
    perms = rbac.get_role_permissions(role_key) if perms is None else perms
    have = {r[0] for r in conn.execute("SELECT page_key FROM notif_access WHERE role_key=?", (role_key,))}
    for p in perms - have:
        conn.execute("INSERT OR IGNORE INTO notif_access (role_key, page_key, since_ts) VALUES (?,?,?)", (role_key, p, now))
    for p in have - perms:
        conn.execute("DELETE FROM notif_access WHERE role_key=? AND page_key=?", (role_key, p))
    conn.commit()


def sync_all(now=None):
    """Tüm rolleri (admin_roles + varsayılanlar + superadmin) eşler; yetki değişince ve olay yayınlanırken çağrılır."""
    from ..core.db import get_db
    roles = {"superadmin": {"*"}}
    for k, v in rbac.DEFAULT_ROLE_PAGES.items():
        roles[k] = set(v)
    try:
        c = get_db()
        try:
            with c.cursor() as cur:
                cur.execute("SELECT role_key, allowed_pages FROM admin_roles")
                for r in cur.fetchall():
                    raw = (r.get("allowed_pages") or "").strip()
                    roles[r["role_key"]] = {"*"} if raw == "*" else {p.strip() for p in raw.split(",") if p.strip()}
        finally:
            c.close()
    except Exception:  # noqa: BLE001 - DB yoksa varsayılan roller yeter
        pass
    conn = _db()
    try:
        for rk, perms in roles.items():
            sync_role(conn, rk, perms, now)
    finally:
        conn.close()


# ---------------------------------------------------------------- yayın
def publish(page_key, title, body="", link="", ntype="", severity="info", dedupe_key="", target_user="",
            tenant_id=None):
    """Bildirim ekler; aynı dedupe_key zaten varsa eklemez. Hiçbir zaman istisna fırlatmaz. Dönüş: yeni id veya None."""
    try:
        tenant_id = resolve_tenant(tenant_id)
        severity = severity if severity in SEVERITIES else "info"
        try:
            sync_all()      # yetkisi bu olaydan hemen önce verilen kullanıcı since_ts'in doğru olması için
        except Exception:  # noqa: BLE001
            log.debug("notif sync_all failed", exc_info=True)
        conn = _db()
        try:
            if dedupe_key and conn.execute("SELECT 1 FROM notifications WHERE tenant_id=? AND dedupe_key=?",
                                           (tenant_id, dedupe_key)).fetchone():
                return None
            cur = conn.execute(
                "INSERT INTO notifications (tenant_id,page_key,target_user,ntype,severity,title,body,link,dedupe_key,created_ts) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (tenant_id, page_key, target_user, ntype, severity, str(title)[:200], str(body)[:600], link[:300],
                 dedupe_key[:200], time.time()))
            conn.execute("DELETE FROM notifications WHERE created_ts < ?", (time.time() - RETENTION_DAYS * 86400,))
            conn.execute("DELETE FROM notifications WHERE tenant_id=? AND id NOT IN "
                         "(SELECT id FROM notifications WHERE tenant_id=? ORDER BY id DESC LIMIT ?)",
                         (tenant_id, tenant_id, MAX_PER_TENANT))
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        log.warning("notification publish failed", exc_info=True)
        return None


# ---------------------------------------------------------------- gelen kutusu
_VISIBLE = ("n.tenant_id=? AND (n.target_user=? OR (n.target_user='' AND EXISTS ("
            "SELECT 1 FROM notif_access a WHERE a.role_key=? AND (a.page_key='*' OR a.page_key=n.page_key) "
            "AND n.created_ts>=a.since_ts)))")


def _ensure_role(conn, role):
    if not conn.execute("SELECT 1 FROM notif_access WHERE role_key=? LIMIT 1", (role,)).fetchone():
        sync_role(conn, role)


def inbox(user, role, limit=30, only_unread=False, tenant_id=None, status="", offset=0):
    """{'items': [...], 'unread': n, 'total': m} — kullanıcının görebildiği bildirimler, yeniden eskiye.
    status: 'all' (varsayılan) | 'unread' | 'read'; only_unread=True 'unread' ile aynıdır."""
    tenant_id = resolve_tenant(tenant_id)
    limit = max(1, min(int(limit or 30), 100))
    offset = max(0, int(offset or 0))
    status = status if status in ("all", "unread", "read") else ("unread" if only_unread else "all")
    conn = _db()
    try:
        _ensure_role(conn, role)
        st = conn.execute("SELECT read_all_ts FROM notif_state WHERE user=?", (user,)).fetchone()
        all_ts = st[0] if st else 0
        base = (f"FROM notifications n LEFT JOIN notif_read r ON r.notif_id=n.id AND r.user=? WHERE {_VISIBLE}")
        args = (user, tenant_id, user, role)
        unread_sql = " AND r.notif_id IS NULL AND n.created_ts>?"
        unread = conn.execute(f"SELECT COUNT(*) {base}{unread_sql}", args + (all_ts,)).fetchone()[0]
        extra, eargs = "", ()
        if status == "unread":
            extra, eargs = unread_sql, (all_ts,)
        elif status == "read":
            extra, eargs = " AND (r.notif_id IS NOT NULL OR n.created_ts<=?)", (all_ts,)
        total = conn.execute(f"SELECT COUNT(*) {base}{extra}", args + eargs).fetchone()[0]
        rows = conn.execute(
            f"SELECT n.id,n.page_key,n.ntype,n.severity,n.title,n.body,n.link,n.created_ts,"
            f"(r.notif_id IS NOT NULL OR n.created_ts<=?) AS is_read {base}{extra} ORDER BY n.id DESC LIMIT ? OFFSET ?",
            (all_ts,) + args + eargs + (limit, offset)).fetchall()
        items = [{"id": r[0], "page": r[1], "type": r[2], "severity": r[3], "title": r[4], "body": r[5], "link": r[6],
                  "ts": r[7], "read": bool(r[8])} for r in rows]
        return {"items": items, "unread": unread, "total": total}
    finally:
        conn.close()


def mark_read(user, role, ids=None, everything=False, tenant_id=None):
    """Seçilen (yalnızca görebildiği) bildirimleri veya hepsini okundu yapar."""
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        _ensure_role(conn, role)
        if everything:
            conn.execute("INSERT INTO notif_state (user, read_all_ts) VALUES (?,?) "
                         "ON CONFLICT(user) DO UPDATE SET read_all_ts=excluded.read_all_ts", (user, time.time()))
        else:
            for i in [int(x) for x in (ids or [])][:100]:
                if conn.execute(f"SELECT 1 FROM notifications n WHERE n.id=? AND {_VISIBLE}", (i, tenant_id, user, role)).fetchone():
                    conn.execute("INSERT OR IGNORE INTO notif_read (user, notif_id) VALUES (?,?)", (user, i))
        conn.execute("DELETE FROM notif_read WHERE notif_id NOT IN (SELECT id FROM notifications)")
        conn.commit()
    finally:
        conn.close()


def remember_hosts(ips, tenant_id=None):
    """IP tarama için: bilinen cihaz listesini günceller. Dönüş: (yeni_ip_listesi, onceden_kayit_var_mi)."""
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        had = conn.execute("SELECT 1 FROM known_hosts WHERE tenant_id=? LIMIT 1", (tenant_id,)).fetchone() is not None
        new = []
        now = time.time()
        for ip in ips:
            if conn.execute("INSERT OR IGNORE INTO known_hosts (tenant_id, ip, first_seen) VALUES (?,?,?)",
                            (tenant_id, ip, now)).rowcount:
                new.append(ip)
        conn.commit()
        return new, had
    finally:
        conn.close()
