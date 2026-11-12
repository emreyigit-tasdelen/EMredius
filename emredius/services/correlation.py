# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Korelasyon: bir kullanıcı adı, MAC veya IP için tüm kaynakları tek görünümde birleştirir:
RADIUS kimlik doğrulama (radpostauth) + oturumlar (radacct) + bağlı olduğu cihaz/port (MAC geçmişi) + ARP IP + etkin
kara liste/karantina işaretleri. Yalnız okur."""
import logging
import re

from . import machist, nacmarks
from ..core import get_db, normalize_mac
from ..core.tenant import resolve_tenant

log = logging.getLogger(__name__)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def kind_of(q):
    q = (q or "").strip()
    if normalize_mac(q):
        return "mac"
    if _IP_RE.match(q):
        return "ip"
    return "user" if q else ""


def _rows(sql, args):
    try:
        conn = get_db()
    except Exception:  # noqa: BLE001
        return []
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchall()
    except Exception as e:  # noqa: BLE001
        log.debug("correlation: %s", e)
        return []
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


def lookup(q, days=30, tenant_id=None):
    tenant_id = resolve_tenant(tenant_id)
    q = (q or "").strip()[:64]
    days = max(1, min(int(days or 30), 365))
    out = {"query": q, "kind": kind_of(q), "users": [], "macs": [], "ips": [], "auth": [], "sessions": [], "ports": [],
           "marks": []}
    if not out["kind"]:
        return out
    users, macs, ips = set(), set(), set()
    if out["kind"] == "mac":
        macs.add(normalize_mac(q))
    elif out["kind"] == "ip":
        ips.add(q)
        for r in _rows("SELECT DISTINCT username, callingstationid FROM radacct WHERE framedipaddress=%s "
                       "AND acctstarttime >= DATE_SUB(NOW(), INTERVAL %s DAY) LIMIT 50", (q, days)):
            if r["username"]:
                users.add(r["username"])
            if normalize_mac(r["callingstationid"] or ""):
                macs.add(normalize_mac(r["callingstationid"]))
    else:
        users.add(q)
        macs.update(machist.user_macs(q))
    h = machist.history(tenant_id=tenant_id, q=next(iter(macs)) if len(macs) == 1 and out["kind"] == "mac" else q, days=days)
    macs.update(h["macs"])
    out["ports"] = h["ports"]
    out["sessions"] = h["sessions"] if h["sessions"] else machist.radius_sessions(sorted(macs), q if out["kind"] == "user" else "", days)
    for s in out["sessions"]:
        if s["user"]:
            users.add(s["user"])
        if s["ip"]:
            ips.add(s["ip"])
    names = sorted(users)[:20]
    if names:
        out["auth"] = [{"authdate": str(r["authdate"]), "username": r["username"], "reply": r["reply"]} for r in _rows(
            "SELECT authdate, username, reply FROM radpostauth WHERE username IN (%s) AND "
            "authdate >= DATE_SUB(NOW(), INTERVAL %%s DAY) ORDER BY authdate DESC LIMIT 200" % ",".join(["%s"] * len(names)),
            names + [days])]
    marks = []
    for u in names or [""]:
        for m in sorted(macs)[:20] or [""]:
            for mk in nacmarks.status_of(m, u, tenant_id):
                if mk["id"] not in {x["id"] for x in marks}:
                    marks.append(mk)
    out.update(users=names, macs=sorted(macs)[:50], ips=sorted(ips)[:50], marks=marks)
    return out
