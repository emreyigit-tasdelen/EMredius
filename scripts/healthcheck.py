#!/usr/bin/env python3
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end health check with the dedicated accounts from scripts/healthcheck_setup.py:
  1. panel: real HTTPS login (nginx -> gunicorn -> MariaDB), dashboard 200, logout
  2. RADIUS: Access-Request via radclient to 127.0.0.1:1812, expects Access-Accept
Prints only OK/FAIL lines (never a password, secret or radclient output). Exit code 1 on any failure.

  .venv/bin/python scripts/healthcheck.py [--env /etc/emredius/healthcheck.env] [--skip-radius]
"""
import argparse
import http.cookiejar
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_ENV = "/etc/emredius/healthcheck.env"
REQUIRED = ("HC_URL", "HC_ADMIN_USER", "HC_ADMIN_PASS", "HC_RADIUS_USER", "HC_RADIUS_PASS", "HC_RADIUS_SECRET")
TIMEOUT = 15


def read_env(path):
    vals = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                vals[k.strip()] = v.strip()
    return vals


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def _opener(follow, jar):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # loopback to our own nginx with its own certificate
    ctx.verify_mode = ssl.CERT_NONE
    handlers = [urllib.request.HTTPSHandler(context=ctx),
                urllib.request.HTTPCookieProcessor(jar)]
    if not follow:
        handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers)


def _open(opener, url, data=None):
    """-> (status, location or final path)"""
    try:
        with opener.open(url, data=data, timeout=TIMEOUT) as r:
            return r.status, urllib.parse.urlparse(r.geturl()).path
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Location", "")


def check_panel(env):
    base = env["HC_URL"].rstrip("/")
    jar = http.cookiejar.CookieJar()
    op = _opener(False, jar)
    code, _ = _open(op, base + "/login")
    if code != 200:
        return False, f"login sayfası {code}"
    form = urllib.parse.urlencode({"username": env["HC_ADMIN_USER"], "password": env["HC_ADMIN_PASS"]}).encode()
    code, loc = _open(op, base + "/login", form)
    path = urllib.parse.urlparse(loc).path
    if code not in (302, 303) or path.startswith("/login"):
        return False, f"giriş başarısız ({code} {path or '-'})"
    op = _opener(True, jar)  # same session cookie, now following redirects
    code, final = _open(op, base + path)
    if code != 200 or final.startswith("/login"):
        return False, f"dashboard {code} {final}"
    _open(op, base + "/logout")
    return True, f"giriş + dashboard ({path})"


def radclient_input(env):
    for k in ("HC_RADIUS_USER", "HC_RADIUS_PASS"):
        if any(c in env[k] for c in "\"\\\n\r"):
            raise ValueError(f"{k} geçersiz karakter içeriyor")
    return (f'User-Name = "{env["HC_RADIUS_USER"]}"\n'
            f'User-Password = "{env["HC_RADIUS_PASS"]}"\n'
            "NAS-IP-Address = 127.0.0.1\n")


def check_radius(env, run=subprocess.run):
    fd, secret_path = tempfile.mkstemp(prefix="hc-", suffix=".secret")  # 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(env["HC_RADIUS_SECRET"] + "\n")
        try:
            r = run(["radclient", "-r", "2", "-t", "3", "-S", secret_path, "127.0.0.1:1812", "auth"],
                    input=radclient_input(env), capture_output=True, text=True, timeout=30)
        except FileNotFoundError:
            return False, "radclient yok"
        except subprocess.TimeoutExpired:
            return False, "radclient zaman aşımı"
        out = (r.stdout or "") + (r.stderr or "")
        if "Access-Accept" in out:
            return True, "Access-Accept"
        if "Access-Reject" in out:
            return False, "Access-Reject"
        return False, f"yanıt yok (çıkış kodu {r.returncode})"
    finally:
        os.unlink(secret_path)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--env", default=DEFAULT_ENV)
    p.add_argument("--skip-radius", action="store_true")
    args = p.parse_args(argv)
    try:
        env = read_env(args.env)
    except OSError as e:
        print(f"FAIL env: {args.env} okunamadı ({e.strerror})")
        return 1
    missing = [k for k in REQUIRED if not env.get(k)]
    if missing:
        print("FAIL env: eksik " + ", ".join(missing))
        return 1
    checks = [("panel", check_panel)] + ([] if args.skip_radius else [("radius", check_radius)])
    failed = 0
    for name, fn in checks:
        try:
            ok, msg = fn(env)
        except Exception as e:  # noqa: BLE001 - report, never dump values
            ok, msg = False, type(e).__name__
        print(f"{'OK' if ok else 'FAIL'} {name}: {msg}")
        failed += not ok
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
