# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Kimlik doğrulama günlüğü: radpostauth (RADIUS Access-Accept/Reject) arama ve özet. Parola sütunu ASLA okunmaz."""
import logging

from ..core import get_db

log = logging.getLogger(__name__)

RESULTS = {"accept": "Access-Accept", "reject": "Access-Reject"}
COLS = ["authdate", "username", "reply"]


def _close(conn):
    try:
        conn.close()
    except Exception:  # noqa: BLE001
        pass


def search(q="", result="", days=1, limit=500):
    """-> {"rows", "accept", "reject"}; veritabanı yoksa boş döner."""
    days = max(1, min(int(days or 1), 365))
    limit = max(1, min(int(limit or 500), 5000))
    where, args = ["authdate >= DATE_SUB(NOW(), INTERVAL %s DAY)"], [days]
    q = (q or "").strip()[:64]
    if q:
        where.append("username LIKE %s")
        args.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if result in RESULTS:
        where.append("reply=%s")
        args.append(RESULTS[result])
    out = {"rows": [], "accept": 0, "reject": 0}
    try:
        conn = get_db()
    except Exception:  # noqa: BLE001
        return out
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT authdate, username, reply FROM radpostauth WHERE " + " AND ".join(where) +
                        " ORDER BY authdate DESC, id DESC LIMIT %s", args + [limit])
            out["rows"] = [{"authdate": str(r["authdate"]), "username": r["username"], "reply": r["reply"]}
                           for r in cur.fetchall()]
            cur.execute("SELECT reply, COUNT(*) AS n FROM radpostauth WHERE authdate >= DATE_SUB(NOW(), INTERVAL %s DAY) "
                        "GROUP BY reply", (days,))
            for r in cur.fetchall():
                if r["reply"] == RESULTS["accept"]:
                    out["accept"] = int(r["n"])
                elif r["reply"] == RESULTS["reject"]:
                    out["reject"] = int(r["n"])
    except Exception as e:  # noqa: BLE001
        log.debug("authlog search: %s", e)
    finally:
        _close(conn)
    return out


def to_csv(rows):
    from . import equipment
    return equipment._csv(rows, COLS)
