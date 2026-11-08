# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Dashboard KPI/grafik verisi (RADIUS radpostauth/radacct + SNMP + alarm tabloları).

Hesaplanamayan her bölüm eksik kalır ve arayüzde gizlenir; uydurma değer yoktur.
radpostauth'ta NAS, ret nedeni ve karar süresi sütunu yok: bu veriler üretilmez.
"""
import logging
from collections import Counter

from ..core import get_db, get_nms_db, lookup_mac_vendor
from ..core.tenant import current_tenant

log = logging.getLogger(__name__)

# aralık -> (saniye, trend kovası saniye)
RANGES = {"1h": (3600, 300), "24h": (86400, 3600), "7d": (7 * 86400, 86400), "30d": (30 * 86400, 86400)}
DEFAULT_RANGE = "24h"
# radpostauth.authdate indeksli değil: son N satırla sınırla (id birincil anahtar, tarama kısa kalır)
AUTH_ROW_WINDOW = 500000
TOP_N = 6
_WIN = ("id >= (SELECT GREATEST(COALESCE(MAX(id), 0) - %s, 0) FROM radpostauth) "
        "AND authdate >= NOW() - INTERVAL %s SECOND")


def normalize_range(value):
    return value if value in RANGES else DEFAULT_RANGE


def _auth(cur, seconds, bucket):
    cur.execute(f"SELECT reply, COUNT(*) AS n FROM radpostauth WHERE {_WIN} GROUP BY reply", (AUTH_ROW_WINDOW, seconds))
    acc = rej = 0
    for r in cur.fetchall():
        if r["reply"] == "Access-Accept":
            acc += r["n"]
        elif r["reply"] == "Access-Reject":
            rej += r["n"]
    if not acc + rej:
        return None
    cur.execute(
        f"""SELECT FROM_UNIXTIME((UNIX_TIMESTAMP(authdate) DIV %s) * %s) AS t, reply, COUNT(*) AS n
            FROM radpostauth WHERE {_WIN} AND reply IN ('Access-Accept','Access-Reject') GROUP BY t, reply ORDER BY t""",
        (bucket, bucket, AUTH_ROW_WINDOW, seconds))
    series = {}
    for r in cur.fetchall():
        key = r["t"].strftime("%Y-%m-%d %H:%M")
        series.setdefault(key, [0, 0])[0 if r["reply"] == "Access-Accept" else 1] += r["n"]
    labels = sorted(series)
    return {"accept": acc, "reject": rej, "rate": round(acc * 100.0 / (acc + rej), 1),
            "trend": {"labels": labels, "accept": [series[k][0] for k in labels], "reject": [series[k][1] for k in labels]}}


def _endpoints(cur, seconds):
    cur.execute("SELECT DISTINCT callingstationid AS mac FROM radacct WHERE acctstarttime >= NOW() - INTERVAL %s SECOND "
                "AND callingstationid <> '' LIMIT 5000", (seconds,))
    macs = [r["mac"] for r in cur.fetchall()]
    if not macs:
        return None
    vendors = Counter((lookup_mac_vendor(m) or "Bilinmeyen") for m in macs)
    cur.execute("SELECT COUNT(DISTINCT callingstationid) AS n FROM radacct WHERE acctstoptime IS NULL AND callingstationid <> ''")
    return {"seen": len(macs), "active": cur.fetchone()["n"], "dist": _top(vendors)}


def _rejected_endpoints(cur, seconds):
    cur.execute(f"""SELECT COUNT(DISTINCT username) AS n FROM radpostauth WHERE {_WIN}
                    AND reply = 'Access-Reject' AND (username LIKE '%%:%%' OR username LIKE '%%-%%')""",
                (AUTH_ROW_WINDOW, seconds))
    return cur.fetchone()["n"]


def _top(counter, n=TOP_N):
    items = counter.most_common()
    head = items[:n]
    rest = sum(v for _, v in items[n:])
    if rest:
        head.append(("Diğer", rest))
    return {"labels": [str(k) for k, _ in head], "data": [int(v) for _, v in head]} if head else None


def _sessions(cur, seconds):
    out = {}
    cur.execute("SELECT COUNT(*) AS s, COUNT(DISTINCT username) AS u FROM radacct WHERE acctstoptime IS NULL")
    r = cur.fetchone()
    out["sessions"] = {"active": r["s"], "users": r["u"]}
    cur.execute("SELECT nasname, shortname FROM nas")
    names = {n["nasname"]: n["shortname"] for n in cur.fetchall()}
    cur.execute("SELECT nasipaddress AS ip, COUNT(*) AS n FROM radacct WHERE acctstoptime IS NULL "
                "GROUP BY nasipaddress ORDER BY n DESC LIMIT 10")
    rows = cur.fetchall()
    if rows:
        out["nas_sessions"] = [{"name": names.get(r["ip"]) or r["ip"], "sessions": r["n"]} for r in rows]
    cur.execute("SELECT nasipaddress AS ip, COUNT(*) AS n FROM radacct WHERE acctstarttime >= NOW() - INTERVAL %s SECOND "
                "GROUP BY nasipaddress", (seconds,))
    out["nas_dist"] = _top(Counter({(names.get(r["ip"]) or r["ip"]): r["n"] for r in cur.fetchall()}))
    return out


def _radius(seconds, bucket, out):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            for name, fn in (
                ("auth", lambda: _auth(cur, seconds, bucket)),
                ("endpoints", lambda: _endpoints(cur, seconds)),
                ("rejected_endpoints", lambda: _rejected_endpoints(cur, seconds)),
                ("_sessions", lambda: _sessions(cur, seconds)),
            ):
                try:
                    val = fn()
                except Exception as e:  # noqa: BLE001
                    log.warning("dashboard_stats %s: %s", name, e)
                    continue
                if name == "_sessions":
                    out.update(val)
                else:
                    out[name] = val
    finally:
        conn.close()


def _snmp_alarms(out):
    try:
        conn = get_nms_db()
        try:
            r = conn.execute("SELECT COUNT(*) AS n, SUM(CASE WHEN status='ONLINE' THEN 1 ELSE 0 END) AS up "
                             "FROM snmp_devices WHERE tenant_id=?", (current_tenant(),)).fetchone()
            if r["n"]:
                out["devices"] = {"total": r["n"], "online": r["up"] or 0}
        finally:
            conn.close()
    except Exception as e:  # noqa: BLE001
        log.warning("dashboard_stats snmp: %s", e)
    try:
        from . import alarms
        ev = [e for e in alarms.list_events(limit=500) if e["status"] == "active"]
        out["alarms"] = {"count": len(ev), "list": [
            {"severity": e["severity"], "message": e["message"], "device_ip": e.get("device_ip", ""),
             "last_seen": e["last_seen"]} for e in ev[:8]]}
    except Exception as e:  # noqa: BLE001
        log.warning("dashboard_stats alarms: %s", e)


def get_stats(range_key=DEFAULT_RANGE):
    range_key = normalize_range(range_key)
    seconds, bucket = RANGES[range_key]
    raw = {}
    try:
        _radius(seconds, bucket, raw)
    except Exception as e:  # noqa: BLE001
        log.warning("dashboard_stats radius unavailable: %s", e)
    _snmp_alarms(raw)
    return build(raw, range_key)


def build(raw, range_key):
    """Ham değerlerden kart/grafik listesi; eksik olan bölüm dahil edilmez."""
    cards = []

    def card(key, label, value, icon, color, suffix=""):
        cards.append({"key": key, "label": label, "value": value, "icon": icon, "color": color, "suffix": suffix})

    ep, auth, ses, dev, alm = (raw.get(k) for k in ("endpoints", "auth", "sessions", "devices", "alarms"))
    if ep:
        card("seen", "Görülen Endpoint", ep["seen"], "fa-laptop", "blue")
        card("active_endpoints", "Aktif Endpoint", ep["active"], "fa-wifi", "green")
    if raw.get("rejected_endpoints") is not None and auth:
        card("rejected", "Reddedilen Endpoint", raw["rejected_endpoints"], "fa-ban", "red")
    if auth:
        card("auth_count", "Kimlik Doğrulama", auth["accept"] + auth["reject"], "fa-key", "purple")
        card("rate", "Başarı Oranı", auth["rate"], "fa-circle-check", "green", "%")
    if ses:
        card("users", "Aktif Kullanıcı", ses["users"], "fa-users", "blue")
        card("sessions", "Aktif Oturum", ses["active"], "fa-plug", "amber")
    if dev:
        card("devices", "Raporlayan Ağ Cihazı", dev["online"], "fa-network-wired", "purple", f" / {dev['total']}")
    if alm is not None:
        card("alarms", "Alarm", alm["count"], "fa-bell", "red" if alm["count"] else "green")
    return {
        "range": range_key, "cards": cards,
        "auth_result": {"labels": ["Kabul", "Ret"], "data": [auth["accept"], auth["reject"]]} if auth else None,
        "nas_dist": raw.get("nas_dist"),
        "endpoint_dist": ep["dist"] if ep else None,
        "trend": auth["trend"] if auth else None,
        "alarms": alm["list"] if alm and alm["list"] else None,
        "nas_sessions": raw.get("nas_sessions"),
    }
