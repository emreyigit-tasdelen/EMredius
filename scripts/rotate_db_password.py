#!/usr/bin/env python3
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Rotates the MariaDB password of the RADIUS DB user (default 'radius') used by FreeRADIUS and the panel.

  rotate:   rotate_db_password.py --backup-dir /root/emredius_dbpw_<TS>
  rollback: rotate_db_password.py --backup-dir /root/emredius_dbpw_<TS> --restore

- the new password is generated here (secrets.token_urlsafe(32)) and never printed or put on a command line:
  SQL goes to `mysql` on stdin, connecting as root over the unix socket (MYSQL_DEFAULTS_FILE / my.cnf)
- the FreeRADIUS sql module config is backed up (0600) first, then its first `password = ...` line (the one the
  panel reads, see emredius/config.py) is replaced atomically, keeping mode, owner and SELinux label
- the new password is verified with a real login before the config is written; on any failure after ALTER USER
  the old password is put back
Prints only OK/FAIL lines. Exit code 1 on failure. Restart radiusd and the panel afterwards.
"""
import argparse
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

DEFAULT_CONF = "/etc/raddb/mods-available/sql"
DEFAULT_ROOT_CNF = "/etc/emredius/my.cnf"
PW_LINE = re.compile(r'^(\s*)password\s*=\s*"?([^"\n]*)"?\s*$')


def find_password(text):
    """-> (line index, indent, password) of the first `password = ...` line, or None."""
    for i, line in enumerate(text.splitlines(True)):
        m = PW_LINE.match(line)
        if m:
            return i, m.group(1), m.group(2)
    return None


def replace_password(text, new_pw):
    found = find_password(text)
    if found is None:
        raise ValueError("password satırı yok")
    i, indent, _ = found
    lines = text.splitlines(True)
    nl = "\n" if lines[i].endswith("\n") else ""
    lines[i] = f'{indent}password = "{new_pw}"{nl}'
    return "".join(lines)


def _sql_quote(value):
    if any(c in value for c in "'\\\n\r\0"):
        raise ValueError("şifre geçersiz karakter içeriyor")
    return "'" + value + "'"


def mysql(sql, root_cnf, run=subprocess.run):
    r = run(["mysql", f"--defaults-extra-file={root_cnf}", "-N", "-B"], input=sql, capture_output=True,
            text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError("mysql çıkış kodu %d" % r.returncode)
    return r.stdout


def user_hosts(user, root_cnf, run=subprocess.run):
    out = mysql(f"SELECT host FROM mysql.user WHERE user = {_sql_quote(user)};", root_cnf, run)
    return [h.strip() for h in out.splitlines() if h.strip()]


def alter_password(user, hosts, pw, root_cnf, run=subprocess.run):
    sql = "".join(f"ALTER USER {_sql_quote(user)}@{_sql_quote(h)} IDENTIFIED BY {_sql_quote(pw)};\n" for h in hosts)
    mysql(sql + "FLUSH PRIVILEGES;\n", root_cnf, run)


def can_login(user, pw, run=subprocess.run):
    """Real TCP login as the user (FreeRADIUS uses server=localhost; the panel 127.0.0.1)."""
    fd, path = tempfile.mkstemp(prefix="dbpw-", suffix=".cnf")  # 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"[client]\nuser={user}\npassword={pw}\nhost=127.0.0.1\nprotocol=tcp\n")
        r = run(["mysql", f"--defaults-extra-file={path}", "-N", "-B"], input="SELECT 1;\n",
                capture_output=True, text=True, timeout=30)
        return r.returncode == 0 and r.stdout.strip() == "1"
    finally:
        os.unlink(path)


def write_like(path, text, ref):
    """Atomic replace of `path` with `text`, copying mode/owner of `ref` (the file being replaced)."""
    st = os.stat(ref)
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".sql.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, st.st_mode & 0o7777)
        os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    if shutil.which("restorecon"):
        subprocess.run(["restorecon", path], capture_output=True)


def rotate(conf, backup_dir, user, root_cnf):
    conf = os.path.realpath(conf)
    with open(conf, "r", encoding="utf-8") as f:
        text = f.read()
    found = find_password(text)
    if found is None:
        print("FAIL: config'te password satırı yok")
        return 1
    old_pw = found[2]
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    backup = os.path.join(backup_dir, "sql")
    if os.path.exists(backup):
        print(f"FAIL: {backup} zaten var (önceki rotasyon), dokunulmadı")
        return 1
    shutil.copy2(conf, backup)
    os.chmod(backup, 0o600)
    print(f"OK yedek {backup} (0600)")

    hosts = user_hosts(user, root_cnf)
    if not hosts:
        print(f"FAIL: MariaDB'de {user} kullanıcısı yok")
        return 1
    new_pw = secrets.token_urlsafe(32)
    try:
        alter_password(user, hosts, new_pw, root_cnf)
        if not can_login(user, new_pw):
            raise RuntimeError("yeni şifreyle giriş yapılamadı")
        write_like(conf, replace_password(text, new_pw), conf)
        with open(conf, "r", encoding="utf-8") as f:
            if (find_password(f.read()) or (0, "", ""))[2] != new_pw:
                raise RuntimeError("config doğrulanamadı")
    except Exception as e:  # put the old password back, config untouched or restored
        alter_password(user, hosts, old_pw, root_cnf)
        write_like(conf, text, conf)
        print(f"FAIL: {type(e).__name__}: geri alındı")
        return 1
    print(f"OK ALTER USER {user}@{{{','.join(hosts)}}}")
    print(f"OK {conf} güncellendi (izin/sahip korundu)")
    return 0


def restore(conf, backup_dir, user, root_cnf):
    conf = os.path.realpath(conf)
    backup = os.path.join(backup_dir, "sql")
    with open(backup, "r", encoding="utf-8") as f:
        text = f.read()
    found = find_password(text)
    if found is None:
        print("FAIL: yedekte password satırı yok")
        return 1
    hosts = user_hosts(user, root_cnf)
    alter_password(user, hosts, found[2], root_cnf)
    write_like(conf, text, conf)
    ok = can_login(user, found[2])
    print(f"{'OK' if ok else 'FAIL'} eski şifre ve config geri yüklendi")
    return 0 if ok else 1


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--conf", default=DEFAULT_CONF)
    p.add_argument("--backup-dir", required=True)
    p.add_argument("--user", default="radius")
    p.add_argument("--root-cnf", default=os.environ.get("MYSQL_DEFAULTS_FILE", DEFAULT_ROOT_CNF))
    p.add_argument("--restore", action="store_true")
    args = p.parse_args(argv)
    try:
        fn = restore if args.restore else rotate
        return fn(args.conf, args.backup_dir, args.user, args.root_cnf)
    except Exception as e:  # noqa: BLE001 - never print values
        print(f"FAIL: {type(e).__name__}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
