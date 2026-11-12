#!/usr/bin/env python3
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only smoke test against the REAL configuration of this host (staging or live): builds the app from
EMREDIUS_ENV_FILE, opens a session as an existing active superadmin (no password involved, in-process test
client only) and GETs every route without URL parameters plus the vendor static files. Nothing is written
except what the panel itself logs. Exit code 1 when a page answers 5xx or a static file is missing.

  EMREDIUS_ENV_FILE=/etc/emredius/staging.env .venv/bin/python scripts/smoke.py [--user NAME]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from emredius import create_app  # noqa: E402
from emredius.core import get_db  # noqa: E402

SKIP = {"/logout", "/api/logs/stream", "/backup/download-source-bundle"}
STATIC = ["/static/vendor/fontawesome/css/all.min.css", "/static/vendor/fontawesome/webfonts/fa-solid-900.woff2",
          "/static/chart.js", "/static/vendor/vis-network.min.js", "/static/vendor/qrcode.min.js",
          "/static/vendor/swagger-ui/swagger-ui-bundle.js", "/static/js/app.js", "/static/css/base.css"]


def pick_superadmin(name=None):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            if name:
                cur.execute("SELECT username FROM admin_users WHERE username = %s AND status = 'active'", (name,))
            else:
                cur.execute("SELECT username FROM admin_users WHERE role = 'superadmin' AND status = 'active' "
                            "ORDER BY id LIMIT 1")
            row = cur.fetchone()
    finally:
        conn.close()
    return row["username"] if row else None


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--user")
    args = p.parse_args(argv)
    app = create_app({"START_BACKGROUND_JOBS": False, "SESSION_COOKIE_SECURE": False})
    user = pick_superadmin(args.user)
    if not user:
        print("FAIL: no active superadmin in admin_users")
        return 1
    client = app.test_client()
    with client.session_transaction() as s:
        s.update(logged_in=True, user=user, role="superadmin", role_label="superadmin", _csrf_token="smoke")
    bad = []
    count = 0
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        if rule.arguments or "GET" not in rule.methods or rule.rule in SKIP or rule.rule.startswith("/static"):
            continue
        code = client.get(rule.rule).status_code
        count += 1
        print(f"{code} {rule.rule}")
        if code >= 500:
            bad.append(f"{code} {rule.rule}")
    for path in STATIC:
        resp = client.get(path)
        code = resp.status_code
        resp.close()
        print(f"{code} {path}")
        if code != 200:
            bad.append(f"{code} {path}")
    print(f"\n{count} routes + {len(STATIC)} static files checked as '{user}'; {len(bad)} problem(s)")
    for b in bad:
        print("PROBLEM", b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
