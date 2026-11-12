# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""IPAM: alt ağ planı, adres kayıtları (rezerve/statik), doluluk ve boş adresler, keşifle (Aktif Cihazlar envanteri) karşılaştırma.
Tablolar NMS veritabanında, tenant_id'li. Yalnızca IPv4. Büyük alt ağlar asla tek tek dolaşılmaz (yalnızca kayıtlı/keşfedilen adresler ve
ilk boş adres araması, üst sınırlı)."""
import csv
import io
import ipaddress
import time

from . import inventory
from ..core import get_nms_db
from ..core.tenant import resolve_tenant

DEFAULT_TENANT = inventory.DEFAULT_TENANT
MIN_PREFIX = 8
MAX_SUBNETS = 1000
MAX_ADDRS = 20000
FREE_SCAN_LIMIT = 70000
_schema_ok = set()

SCHEMA = """
CREATE TABLE IF NOT EXISTS ipam_subnets (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, cidr TEXT NOT NULL, name TEXT DEFAULT '',
  vlan INTEGER, gateway TEXT DEFAULT '', site TEXT DEFAULT '', note TEXT DEFAULT '', created TEXT DEFAULT '',
  UNIQUE(tenant_id, cidr));
CREATE TABLE IF NOT EXISTS ipam_addrs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id INTEGER NOT NULL DEFAULT 1, ip TEXT NOT NULL, name TEXT DEFAULT '',
  owner TEXT DEFAULT '', kind TEXT NOT NULL DEFAULT 'static', note TEXT DEFAULT '', created TEXT DEFAULT '',
  UNIQUE(tenant_id, ip));
"""
KINDS = {"static": "Statik", "reserved": "Rezerve", "gateway": "Ağ geçidi", "dhcp": "DHCP havuzu"}


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


def _net(cidr):
    try:
        n = ipaddress.ip_network((cidr or "").strip(), strict=False)
    except ValueError:
        return None
    return n if n.version == 4 and n.prefixlen >= MIN_PREFIX else None


def add_subnet(cidr, name="", vlan=None, gateway="", site="", note="", tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    n = _net(cidr)
    if not n:
        return f"Geçerli bir IPv4 alt ağı girin (en geniş /{MIN_PREFIX})."
    gw = (gateway or "").strip()
    if gw:
        try:
            if ipaddress.ip_address(gw) not in n:
                return "Ağ geçidi alt ağın içinde olmalı."
        except ValueError:
            return "Ağ geçidi geçerli bir IP değil."
    try:
        vlan = int(vlan) if str(vlan or "").strip() else None
        if vlan is not None and not 1 <= vlan <= 4094:
            return "VLAN 1-4094 olmalı."
    except ValueError:
        return "VLAN sayı olmalı."
    conn = _db()
    try:
        if conn.execute("SELECT COUNT(*) FROM ipam_subnets WHERE tenant_id=?", (tenant_id,)).fetchone()[0] >= MAX_SUBNETS:
            return f"En fazla {MAX_SUBNETS} alt ağ."
        for r in conn.execute("SELECT cidr FROM ipam_subnets WHERE tenant_id=?", (tenant_id,)):
            o = ipaddress.ip_network(r[0])
            if o == n:
                return "Bu alt ağ zaten tanımlı."
            if o.overlaps(n) and o.prefixlen == n.prefixlen:
                return f"{r[0]} ile çakışıyor."
        conn.execute("INSERT INTO ipam_subnets (tenant_id,cidr,name,vlan,gateway,site,note,created) VALUES (?,?,?,?,?,?,?,?)",
                     (tenant_id, str(n), (name or "").strip()[:64], vlan, gw, (site or "").strip()[:64], (note or "").strip()[:200], _now()))
        conn.commit()
    finally:
        conn.close()
    return ""


def delete_subnet(sid, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        n = conn.execute("DELETE FROM ipam_subnets WHERE id=? AND tenant_id=?", (sid, tenant_id)).rowcount
        conn.commit()
        return n > 0
    finally:
        conn.close()


def add_addr(ip, name="", owner="", kind="static", note="", tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return "Geçerli bir IP girin."
    if a.version != 4 or kind not in KINDS:
        return "IPv4 adresi ve geçerli tür gerekli."
    conn = _db()
    try:
        if conn.execute("SELECT COUNT(*) FROM ipam_addrs WHERE tenant_id=?", (tenant_id,)).fetchone()[0] >= MAX_ADDRS:
            return f"En fazla {MAX_ADDRS} adres kaydı."
        if conn.execute("SELECT 1 FROM ipam_addrs WHERE tenant_id=? AND ip=?", (tenant_id, str(a))).fetchone():
            return "Bu adres zaten kayıtlı."
        conn.execute("INSERT INTO ipam_addrs (tenant_id,ip,name,owner,kind,note,created) VALUES (?,?,?,?,?,?,?)",
                     (tenant_id, str(a), (name or "").strip()[:64], (owner or "").strip()[:64], kind, (note or "").strip()[:200], _now()))
        conn.commit()
    finally:
        conn.close()
    return ""


def delete_addr(aid, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    conn = _db()
    try:
        n = conn.execute("DELETE FROM ipam_addrs WHERE id=? AND tenant_id=?", (aid, tenant_id)).rowcount
        conn.commit()
        return n > 0
    finally:
        conn.close()


def _load(tenant_id):
    conn = _db()
    try:
        subnets = [dict(r) for r in conn.execute("SELECT * FROM ipam_subnets WHERE tenant_id=?", (tenant_id,))]
        addrs = [dict(r) for r in conn.execute("SELECT * FROM ipam_addrs WHERE tenant_id=?", (tenant_id,))]
    finally:
        conn.close()
    disc = {d["ip"]: d for d in inventory.list_devices(tenant_id, limit=20000)}
    return subnets, addrs, disc


def _usable(n):
    return max(n.num_addresses - 2, 1) if n.prefixlen < 31 else n.num_addresses


def _in(n, ip):
    try:
        return ipaddress.ip_address(ip) in n
    except ValueError:
        return False


def _stat(s, addrs, disc):
    n = ipaddress.ip_network(s["cidr"])
    planned = {a["ip"] for a in addrs if _in(n, a["ip"])}
    found = {ip for ip, d in disc.items() if d["status"] == "ONLINE" and _in(n, ip)}
    used = planned | found
    total = _usable(n)
    s2 = dict(s, total=total, planned=len(planned), discovered=len(found), used=len(used), free=max(total - len(used), 0),
              percent=min(100, round(len(used) * 100 / total)) if total else 0,
              unplanned=len(found - planned), missing=len(planned - found), net=n)
    return s2


def list_subnets(tenant_id=None, q=""):
    tenant_id = resolve_tenant(tenant_id)
    subnets, addrs, disc = _load(tenant_id)
    ql = (q or "").lower()
    out = []
    for s in subnets:
        st = _stat(s, addrs, disc)
        if ql and ql not in f"{s['cidr']} {s['name']} {s['site']} {s['gateway']} {s['vlan'] or ''}".lower():
            continue
        out.append(st)
    out.sort(key=lambda x: (int(x["net"].network_address), x["net"].prefixlen))
    for st in out:
        st["parent"] = next((p["cidr"] for p in out if p["net"] != st["net"] and st["net"].subnet_of(p["net"])), "")
    for st in out:
        del st["net"]
    return out


def free_addresses(cidr, tenant_id=None, count=20):
    """Alt ağdaki ilk boş (planlı de keşfedilmiş de olmayan) adresler; arama üst sınırlıdır."""
    tenant_id = resolve_tenant(tenant_id)
    n = _net(cidr)
    if not n:
        return []
    subnets, addrs, disc = _load(tenant_id)
    taken = {a["ip"] for a in addrs} | set(disc)
    out, seen = [], 0
    for h in (n.hosts() if n.prefixlen < 31 else n):
        seen += 1
        if str(h) not in taken:
            out.append(str(h))
            if len(out) >= count:
                break
        if seen >= FREE_SCAN_LIMIT:
            break
    return out


def compare(cidr, tenant_id=None):
    """Alt ağdaki adresler: ok (planda + keşifte), planned_only (planda var, keşifte yok), unplanned (keşifte var, planda yok)."""
    tenant_id = resolve_tenant(tenant_id)
    n = _net(cidr)
    if not n:
        return None
    subnets, addrs, disc = _load(tenant_id)
    plan = {a["ip"]: a for a in addrs if _in(n, a["ip"])}
    found = {ip: d for ip, d in disc.items() if _in(n, ip)}
    rows = []
    for ip in sorted(set(plan) | set(found), key=lambda x: int(ipaddress.ip_address(x))):
        a, d = plan.get(ip), found.get(ip)
        online = bool(d and d["status"] == "ONLINE")
        state = "ok" if a and online else "planned_only" if a else "unplanned" if online else "offline"
        rows.append({"ip": ip, "state": state, "kind": a["kind"] if a else "", "name": (a or {}).get("name") or (d or {}).get("sys_name") or (d or {}).get("hostname") or "",
                     "owner": (a or {}).get("owner", ""), "addr_id": a["id"] if a else None, "mac": (d or {}).get("mac", ""),
                     "vendor": (d or {}).get("vendor", ""), "last_seen": (d or {}).get("last_seen", "")})
    return rows


def overview(tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    subs = list_subnets(tenant_id)
    return {"subnets": len(subs), "unplanned": sum(s["unplanned"] for s in subs), "missing": sum(s["missing"] for s in subs),
            "full": sum(1 for s in subs if s["percent"] >= 90)}


CSV_COLS = ["cidr", "name", "vlan", "gateway", "site", "total", "used", "free", "percent", "unplanned", "missing", "parent"]


def subnets_csv(rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLS)
    for r in rows:
        w.writerow([("'" + str(r[c]) if str(r[c])[:1] in ("=", "+", "-", "@") else ("" if r[c] is None else r[c])) for c in CSV_COLS])
    return buf.getvalue()
