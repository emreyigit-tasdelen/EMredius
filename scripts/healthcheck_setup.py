#!/usr/bin/env python3
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""One-time setup for scripts/healthcheck.py. Creates, with random passwords generated here:
  - panel admin  'healthcheck'          (role auditor = read-only, no 2FA)
  - RADIUS user  'emredius-healthcheck' (accepted only with NAS-IP-Address 127.0.0.1)
finds the EXISTING localhost RADIUS client secret (clients.conf or nas table; nothing is changed there) and
writes everything to the healthcheck env file with mode 0600. No secret is ever printed.

  EMREDIUS_ENV_FILE=/etc/emredius/emredius.env .venv/bin/python scripts/healthcheck_setup.py
"""
import argparse
import os
import re
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DEFAULT_OUT = "/etc/emredius/healthcheck.env"
CLIENTS_CONF = "/etc/raddb/clients.conf"
ADMIN_USER = "healthcheck"
RADIUS_USER = "emredius-healthcheck"
DESCRIPTION = "EMredius otomatik sağlık kontrolü (silmeyin)"
LOCAL_NAMES = {"localhost", "127.0.0.1", "127.0.0.1/32"}


def _strip(v):
    v = v.strip().rstrip(";").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v


def parse_clients_conf(text):
    """Top-level `client NAME { ... }` blocks -> [{"name", "ipaddr", "secret"}] (nested blocks ignored)."""
    clients, cur, depth = [], None, 0
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if depth == 0:
            m = re.match(r"^client\s+(\S+)\s*\{", line)
            if m:
                cur = {"name": m.group(1), "ipaddr": "", "secret": ""}
                depth = 1
                if "}" in line[m.end():]:
                    clients.append(cur)
                    cur, depth = None, 0
            continue
        if depth == 1 and "=" in line and "{" not in line:
            k, v = line.split("=", 1)
            k = k.strip()
            if k in ("ipaddr", "ipv4addr"):
                cur["ipaddr"] = _strip(v)
            elif k == "secret":
                cur["secret"] = _strip(v)
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            clients.append(cur)
            cur, depth = None, 0
    return clients


def localhost_secret_from_conf(text):
    for c in parse_clients_conf(text):
        if c["secret"] and (c["ipaddr"] in LOCAL_NAMES or (not c["ipaddr"] and c["name"] in LOCAL_NAMES)):
            return c["secret"]
    return None


def localhost_secret_from_db(cur):
    cur.execute("SELECT secret FROM nas WHERE nasname IN ('127.0.0.1', 'localhost', '127.0.0.1/32') LIMIT 1")
    row = cur.fetchone()
    return (row or {}).get("secret") or None


def find_secret(conf_path, cur):
    try:
        with open(conf_path, "r", encoding="utf-8", errors="replace") as f:
            s = localhost_secret_from_conf(f.read())
        if s:
            return s
    except OSError:
        pass
    try:
        return localhost_secret_from_db(cur)
    except Exception:  # nas table may not exist
        return None


def render_env(values):
    return "".join(f"{k}={v}\n" for k, v in values.items())


def write_secret_file(path, content):
    """Creates the file 0600; refuses to overwrite."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(path, 0o600)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default=DEFAULT_OUT)
    p.add_argument("--clients-conf", default=CLIENTS_CONF)
    p.add_argument("--url", default="https://127.0.0.1")
    args = p.parse_args(argv)
    if os.path.exists(args.out):
        print(f"FAIL: {args.out} zaten var, dokunulmadı")
        return 1

    from emredius.config import build_config
    from emredius.core import db, get_db
    from emredius.services.admins import create_admin
    from emredius.services.radius_users import ServiceError, upsert_meta

    db.configure(build_config())  # standalone script: no create_app(), so set up the pool like maintenance.py
    conn = get_db()
    try:
        with conn.cursor() as cur:
            secret = find_secret(args.clients_conf, cur)
            if not secret:
                print("FAIL: localhost RADIUS client secret bulunamadı (clients.conf / nas)")
                return 1
            cur.execute("SELECT 1 AS x FROM radcheck WHERE username = %s LIMIT 1", (RADIUS_USER,))
            if cur.fetchone():
                print(f"FAIL: RADIUS kullanıcısı {RADIUS_USER} zaten var")
                return 1
    finally:
        conn.close()

    admin_pw = secrets.token_urlsafe(24)
    radius_pw = secrets.token_urlsafe(24)
    try:
        create_admin(ADMIN_USER, "Sağlık Kontrolü", "", "auditor", "web", admin_pw)
    except ServiceError as e:
        print(f"FAIL: admin oluşturulamadı: {e}")
        return 1
    print(f"OK admin {ADMIN_USER} (auditor)")

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, 'Cleartext-Password', ':=', %s)",
                        (RADIUS_USER, radius_pw))
            cur.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, 'NAS-IP-Address', '==', "
                        "'127.0.0.1')", (RADIUS_USER,))
            upsert_meta(cur, RADIUS_USER, DESCRIPTION, None)
        conn.commit()
    finally:
        conn.close()
    print(f"OK radius {RADIUS_USER}")

    write_secret_file(args.out, render_env({
        "HC_URL": args.url, "HC_ADMIN_USER": ADMIN_USER, "HC_ADMIN_PASS": admin_pw,
        "HC_RADIUS_USER": RADIUS_USER, "HC_RADIUS_PASS": radius_pw, "HC_RADIUS_SECRET": secret,
    }))
    print(f"OK {args.out} (0600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
