# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Dashboard (landing page) data: RADIUS summary counters, latest live sessions, top traffic users."""
import logging

from ..core import get_db

log = logging.getLogger(__name__)

ACTIVE_SESSION_LIMIT = 5
TOP_USER_LIMIT = 5


def _empty_summary():
    return {
        "total_users": 0,
        "active_sessions": 0,
        "total_nas": 0,
        "total_bytes": 0,
        "active_list": [],
        "top_users": [],
        "db_error": True,
    }


def get_summary():
    """Returns the dashboard figures. If the database is unreachable the page still renders (zeros + db_error)."""
    try:
        conn = get_db()
    except Exception as e:
        log.warning("dashboard: database unavailable (%s)", e)
        return _empty_summary()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(DISTINCT username) AS total FROM radcheck WHERE attribute = 'Cleartext-Password'")
            total_users = cur.fetchone()["total"]

            cur.execute("SELECT COUNT(*) AS active FROM radacct WHERE acctstoptime IS NULL")
            active_sessions = cur.fetchone()["active"]

            cur.execute("SELECT COUNT(*) AS total FROM nas")
            total_nas = cur.fetchone()["total"]

            cur.execute("SELECT SUM(acctinputoctets) AS up, SUM(acctoutputoctets) AS down FROM radacct")
            traffic = cur.fetchone()

            cur.execute(
                """SELECT radacctid, username, framedipaddress, callingstationid, nasipaddress,
                          acctstarttime, acctsessiontime, acctinputoctets, acctoutputoctets
                   FROM radacct WHERE acctstoptime IS NULL ORDER BY radacctid DESC LIMIT %s""",
                (ACTIVE_SESSION_LIMIT,),
            )
            active_list = cur.fetchall()

            cur.execute(
                """SELECT username, SUM(COALESCE(acctinputoctets, 0) + COALESCE(acctoutputoctets, 0)) AS total_bytes
                   FROM radacct GROUP BY username ORDER BY total_bytes DESC LIMIT %s""",
                (TOP_USER_LIMIT,),
            )
            top_users = cur.fetchall()
    except Exception as e:
        log.warning("dashboard: query failed (%s)", e)
        return _empty_summary()
    finally:
        conn.close()

    return {
        "total_users": total_users or 0,
        "active_sessions": active_sessions or 0,
        "total_nas": total_nas or 0,
        "total_bytes": int(traffic["up"] or 0) + int(traffic["down"] or 0),
        "active_list": list(active_list),
        "top_users": list(top_users),
        "db_error": False,
    }


def top_traffic_chart(top_users):
    """Chart.js data for the top-traffic bar chart: plain str/float lists (MariaDB SUM() returns Decimal,
    usernames come from the NAS and are passed to the page only as JSON)."""
    labels = [str(u["username"] or "-") for u in top_users] or ["Veri Yok"]
    data = [round(float(u["total_bytes"] or 0) / (1024 * 1024), 2) for u in top_users] or [0]
    return {"labels": labels, "data": data}
