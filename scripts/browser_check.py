#!/usr/bin/env python3
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Real-browser check of every panel page (headless Chromium via Playwright). Reports per page: HTTP status,
console errors, JS page errors, failed/4xx/5xx sub-requests and hangs (load slower than --slow seconds).

No password is involved: `mint` (run on the host, with the staging/live env) builds the app in-process and signs a
superadmin session cookie; `run` drives the browser with that cookie against any base URL; `all` does both over ssh
(tunnel to the staging port) so it can be run from a workstation that has Playwright:

  python scripts/browser_check.py all [--host SERVER] [--remote-dir /opt/emredius_stage]
  EMREDIUS_ENV_FILE=/etc/emredius/staging.env .venv/bin/python scripts/browser_check.py mint > session.json
  python scripts/browser_check.py run --base-url http://127.0.0.1:5100 --session session.json

Needs `pip install playwright && playwright install chromium` only where the browser runs. Exit 1 on any problem.
"""
import argparse
import json
import os
import shlex
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# streams, downloads and session-ending pages: not meaningful to open in a browser tab
SKIP = {"/logout", "/api/logs/stream", "/snmp/topology/stream", "/backup/download-source-bundle", "/ipam/detail"}
# token API (401 without Authorization is correct), static files, downloads
SKIP_PREFIXES = ("/static", "/download", "/api/v1/")
# data endpoints that answer 503 by design while their backend is not installed (NetFlow collector DB)
ALLOW_STATUS = {"/netflow/data": {503}, "/netflow/export.csv": {503}}
# console noise that is not a page bug
IGNORED_CONSOLE = ("favicon", "Download is starting")


def collect_routes(app):
    """Parameter-free GET page rules the browser should open."""
    out = []
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        if rule.arguments or "GET" not in rule.methods or rule.rule in SKIP or rule.rule.startswith(SKIP_PREFIXES):
            continue
        out.append(rule.rule)
    return out


def mint(user=None):
    """Signed session cookie for an active superadmin + the route list, as a dict (no secrets besides the cookie)."""
    from emredius import create_app
    from emredius.core import get_db
    app = create_app({"START_BACKGROUND_JOBS": False, "SESSION_COOKIE_SECURE": False})
    conn = get_db()
    try:
        with conn.cursor() as cur:
            if user:
                cur.execute("SELECT username FROM admin_users WHERE username = %s AND status = 'active'", (user,))
            else:
                cur.execute("SELECT username FROM admin_users WHERE role = 'superadmin' AND status = 'active' "
                            "ORDER BY id LIMIT 1")
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        raise SystemExit("no active superadmin in admin_users")
    data = {"logged_in": True, "user": row["username"], "role": "superadmin", "role_label": "superadmin",
            "_csrf_token": "browser-check"}
    cookie = app.session_interface.get_signing_serializer(app).dumps(data)
    return {"cookie_name": app.config.get("SESSION_COOKIE_NAME", "session"), "cookie": cookie,
            "routes": collect_routes(app)}


def _tolerated(bad):
    """'<status> <url>' of a sub-request that ALLOW_STATUS lists as an expected answer."""
    status, _, url = bad.partition(" ")
    path = "/" + url.split("://", 1)[-1].split("/", 1)[-1].split("?")[0]
    return status.isdigit() and int(status) in ALLOW_STATUS.get(path, ())


def evaluate(page_result, slow):
    """Problems of one page result dict (status, seconds, console, pageerrors, failed, bad, error)."""
    problems = []
    if page_result.get("error"):
        problems.append("navigation: " + page_result["error"])
    status = page_result.get("status")
    allowed = ALLOW_STATUS.get(page_result.get("path"), ())
    if status is not None and status >= 400 and status not in allowed:
        problems.append(f"HTTP {status}")
    if page_result.get("seconds", 0) > slow:
        problems.append(f"slow: {page_result['seconds']:.1f}s > {slow}s")
    tolerated = [b for b in page_result.get("bad", []) if _tolerated(b)]
    problems += ["console: " + m for m in page_result.get("console", [])
                 if not ((allowed or tolerated) and "Failed to load resource" in m)]
    problems += ["pageerror: " + m for m in page_result.get("pageerrors", [])]
    problems += ["request failed: " + m for m in page_result.get("failed", [])]
    problems += ["sub-request: " + m for m in page_result.get("bad", []) if m not in tolerated]
    return problems


def run_browser(base_url, session, slow=10.0, only=None, headless=True):
    from playwright.sync_api import sync_playwright
    base_url = base_url.rstrip("/")
    host = base_url.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
    routes = [r for r in session["routes"] if not only or r in only]
    results = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        ctx = browser.new_context(ignore_https_errors=True)
        ctx.add_cookies([{"name": session["cookie_name"], "value": session["cookie"], "domain": host, "path": "/"}])
        for path in routes:
            page = ctx.new_page()
            res = {"path": path, "status": None, "seconds": 0.0, "console": [], "pageerrors": [], "failed": [], "bad": [],
                   "error": ""}
            page.on("console", lambda m, r=res: r["console"].append(m.text[:200])
                    if m.type == "error" and not any(i in m.text for i in IGNORED_CONSOLE) else None)
            page.on("pageerror", lambda e, r=res: r["pageerrors"].append(str(e)[:200]))
            page.on("requestfailed", lambda q, r=res: r["failed"].append(f"{q.url[:120]} {q.failure}")
                    if "ERR_ABORTED" not in str(q.failure) else None)
            page.on("response", lambda p, r=res, b=base_url: r["bad"].append(f"{p.status} {p.url[:120]}")
                    if p.status >= 400 and p.url.startswith(b) and p.request.resource_type != "document" else None)
            t0 = time.time()
            try:
                resp = page.goto(base_url + path, wait_until="load", timeout=int(slow * 1000) + 5000)
                res["status"] = resp.status if resp else None
                if "/login" in page.url and path != "/login":
                    res["error"] = "redirected to login (session not accepted)"
            except Exception as e:  # timeout = hang
                msg = str(e).splitlines()[0][:200]
                if "Download is starting" not in msg:
                    res["error"] = msg
            res["seconds"] = time.time() - t0
            page.close()
            results[path] = res
        browser.close()
    return results


def report(results, slow):
    bad = 0
    for path, res in results.items():
        problems = evaluate(res, slow)
        print(f"{'FAIL' if problems else 'ok  '} {res['status'] or '---'} {res['seconds']:5.1f}s {path}")
        for p in problems:
            print("       " + p)
        bad += bool(problems)
    print(f"\n{len(results)} pages checked in a real browser; {bad} with problems")
    return 1 if bad else 0


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_all(args):
    ssh = ["ssh", "-o", "ConnectTimeout=8", args.host]
    remote = (f"cd {shlex.quote(args.remote_dir)} && EMREDIUS_ENV_FILE={shlex.quote(args.env_file)} "
              ".venv/bin/python scripts/browser_check.py mint" + (f" --user {shlex.quote(args.user)}" if args.user else ""))
    out = subprocess.run(ssh + [remote], capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        print("mint failed:", out.stderr.strip()[-300:])
        return 1
    session = json.loads(out.stdout[out.stdout.index("{"):])
    port = _free_port()
    tunnel = subprocess.Popen(["ssh", "-N", "-o", "ExitOnForwardFailure=yes", "-L", f"{port}:127.0.0.1:{args.remote_port}",
                               args.host])
    try:
        for _ in range(40):
            try:
                socket.create_connection(("127.0.0.1", port), 0.5).close()
                break
            except OSError:
                time.sleep(0.25)
        return report(run_browser(f"http://127.0.0.1:{port}", session, args.slow), args.slow)
    finally:
        tunnel.terminate()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mint")
    m.add_argument("--user")
    r = sub.add_parser("run")
    r.add_argument("--base-url", required=True)
    r.add_argument("--session", required=True, help="JSON file written by `mint`")
    r.add_argument("--slow", type=float, default=10.0)
    r.add_argument("--only", nargs="*")
    a = sub.add_parser("all")
    a.add_argument("--host", default="SERVER")
    a.add_argument("--remote-dir", default="/opt/emredius_stage")
    a.add_argument("--env-file", default="/etc/emredius/staging.env")
    a.add_argument("--remote-port", type=int, default=5100)
    a.add_argument("--user")
    a.add_argument("--slow", type=float, default=10.0)
    args = p.parse_args(argv)
    if args.cmd == "mint":
        print(json.dumps(mint(args.user)))
        return 0
    if args.cmd == "run":
        with open(args.session, encoding="utf-8") as f:
            session = json.load(f)
        return report(run_browser(args.base_url, session, args.slow, args.only), args.slow)
    return run_all(args)


if __name__ == "__main__":
    sys.exit(main())
