# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Anomaliler: radpostauth / radacct verisinden türetilen şüpheli davranışlar (yalnız okuma, hiçbir şey değiştirmez).
Dedektörler: brute_force (çok sayıda ret), multi_mac_user (bir kullanıcı çok cihaz), shared_mac (bir MAC çok kullanıcı),
multi_nas_user (bir kullanıcı çok NAS)."""
import logging

from ..core import get_db, get_setting, set_setting

log = logging.getLogger(__name__)

DEFAULTS = {"brute_force": 5, "multi_mac_user": 3, "shared_mac": 2, "multi_nas_user": 3, "concurrent_sessions": 3}
LABELS = {"brute_force": "Çok sayıda reddedilen giriş", "multi_mac_user": "Bir kullanıcı, çok sayıda cihaz (MAC)",
          "shared_mac": "Bir MAC, birden fazla kullanıcı", "multi_nas_user": "Bir kullanıcı, çok sayıda NAS",
          "concurrent_sessions": "Eşzamanlı oturum sınırı aşıldı"}
SEVERITY = {"brute_force": "high", "shared_mac": "medium", "multi_mac_user": "medium", "multi_nas_user": "low", "concurrent_sessions": "high"}


def thresholds():
    out = {}
    for k, d in DEFAULTS.items():
        try:
            out[k] = max(2, int(get_setting("anomaly_" + k, d) or d))
        except (TypeError, ValueError):
            out[k] = d
    return out


def _item(kind, subject, count, detail):
    return {"kind": kind, "label": LABELS[kind], "severity": SEVERITY[kind], "subject": subject, "count": int(count),
            "detail": detail}


def classify(rejects, user_macs, mac_users, user_nas, th=None, open_sessions=None):
    """Saf fonksiyon: sayım sözlüklerinden anomali listesi. rejects={user:n}; user_macs={user:[mac]}; mac_users={mac:[user]};
    user_nas={user:[nas]}."""
    th = th or DEFAULTS
    out = []
    for u, n in rejects.items():
        if n >= th["brute_force"]:
            out.append(_item("brute_force", u, n, f"{n} ret"))
    for u, macs in user_macs.items():
        if len(macs) >= th["multi_mac_user"]:
            out.append(_item("multi_mac_user", u, len(macs), ", ".join(sorted(macs)[:6])))
    for m, users in mac_users.items():
        if len(users) >= th["shared_mac"]:
            out.append(_item("shared_mac", m, len(users), ", ".join(sorted(users)[:6])))
    for u, nas in user_nas.items():
        if len(nas) >= th["multi_nas_user"]:
            out.append(_item("multi_nas_user", u, len(nas), ", ".join(sorted(nas)[:6])))
    for u, n in (open_sessions or {}).items():
        if n >= th["concurrent_sessions"]:
            out.append(_item("concurrent_sessions", u, n, f"{n} açık oturum"))
    order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda x: (order[x["severity"]], -x["count"], x["subject"]))
    return out


def detect(days=1):
    days = max(1, min(int(days or 1), 30))
    th = thresholds()
    rejects, user_macs, mac_users, user_nas, open_sessions = {}, {}, {}, {}, {}
    try:
        conn = get_db()
    except Exception:  # noqa: BLE001
        return {"items": [], "thresholds": th, "available": False}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username, COUNT(*) AS n FROM radpostauth WHERE reply='Access-Reject' AND "
                        "authdate >= DATE_SUB(NOW(), INTERVAL %s DAY) GROUP BY username", (days,))
            rejects = {r["username"]: int(r["n"]) for r in cur.fetchall()}
            cur.execute("SELECT username, COUNT(*) AS n FROM radacct WHERE acctstoptime IS NULL AND username<>'' "
                        "GROUP BY username")
            open_sessions = {r["username"]: int(r["n"]) for r in cur.fetchall()}
            cur.execute("SELECT DISTINCT username, callingstationid, nasipaddress FROM radacct WHERE username<>'' AND "
                        "acctstarttime >= DATE_SUB(NOW(), INTERVAL %s DAY) LIMIT 50000", (days,))
            for r in cur.fetchall():
                u, m, n = r["username"], (r["callingstationid"] or "").lower().replace("-", ":"), r["nasipaddress"]
                if m and u.lower().replace("-", ":") != m:  # MAB kullanıcı adı = MAC: kendi MAC'i sayılmaz
                    user_macs.setdefault(u, set()).add(m)
                    mac_users.setdefault(m, set()).add(u)
                if n:
                    user_nas.setdefault(u, set()).add(str(n))
    except Exception as e:  # noqa: BLE001
        log.debug("anomalies detect: %s", e)
        return {"items": [], "thresholds": th, "available": False}
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass
    return {"items": classify(rejects, user_macs, mac_users, user_nas, th, open_sessions), "thresholds": th, "available": True}


def save_thresholds(values):
    """values: {kind: int}. Yalnız bilinen anahtarlar, 2..1000. -> kaydedilen sözlük"""
    saved = {}
    for k in DEFAULTS:
        if k in values:
            try:
                v = int(values[k])
            except (TypeError, ValueError):
                continue
            if 2 <= v <= 1000:
                set_setting("anomaly_" + k, str(v))
                saved[k] = v
    return saved
