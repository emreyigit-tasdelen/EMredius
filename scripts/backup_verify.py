#!/usr/bin/env python3
# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Restore test of the newest DB backup (run by emredius-backup-verify.timer, see deploy/systemd/).

Loads the latest dump from BACKUP_DIR (radius_full_system_*.tar.gz or radius_backup_*.sql.gz, SHA256 sidecar
checked) into an ISOLATED scratch database (radius_restore_test), compares the table list and row counts with the
source database, then drops the scratch database. The source database is only read; the dump is refused if it
contains USE / CREATE DATABASE / DROP DATABASE statements, so it cannot write anywhere else.

  EMREDIUS_ENV_FILE=/etc/emredius/emredius.env .venv/bin/python scripts/backup_verify.py [--fresh] [--tolerance 0.05]

--fresh dumps the source database now instead of using the newest backup (for hosts without backups, e.g. staging).
Exit code 0 = restore verified, 1 = failed. Output ends with a VERIFY_OK / VERIFY_FAILED line."""
import argparse
import gzip
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TEST_DB = "radius_restore_test"
_FORBIDDEN = re.compile(rb"^\s*(USE\s|CREATE\s+DATABASE|DROP\s+DATABASE)", re.I | re.M)
_BACKUP_RE = re.compile(r"^radius_(full_system|backup)_.*\.(tar|sql)\.gz$")
_TIMEOUT = 900


class VerifyError(Exception):
    pass


def latest_backup(backup_dir):
    names = [n for n in os.listdir(backup_dir) if _BACKUP_RE.match(n)]
    if not names:
        raise VerifyError(f"no backup found in {backup_dir}")
    return os.path.join(backup_dir, max(names, key=lambda n: os.path.getmtime(os.path.join(backup_dir, n))))


def check_sha(path):
    side = path + ".sha256"
    if not os.path.exists(side):
        return "no sha256 sidecar"
    from emredius.services.backups import sha256_file
    want = open(side, encoding="utf-8").read().split()[0]
    if sha256_file(path) != want:
        raise VerifyError("SHA256 mismatch: " + os.path.basename(path))
    return "sha256 ok"


def extract_sql(path, out_path):
    """Writes the SQL dump of a backup archive to out_path."""
    try:
        if path.endswith(".tar.gz"):
            with tarfile.open(path, "r:gz") as tar:
                member = tar.getmember("radius_database.sql")
                with tar.extractfile(member) as src, open(out_path, "wb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
        else:
            with gzip.open(path, "rb") as src, open(out_path, "wb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
    except (OSError, KeyError, tarfile.TarError, EOFError) as e:
        raise VerifyError(f"archive unreadable: {e}")


def check_dump_safe(sql_path):
    """Refuses dumps that could touch another database; requires mysqldump's completion trailer."""
    with open(sql_path, "rb") as f:
        head_ok = False
        tail = b""
        for block in iter(lambda: f.read(1024 * 1024), b""):
            if _FORBIDDEN.search(block):
                raise VerifyError("dump contains USE/CREATE DATABASE/DROP DATABASE; refusing to load it")
            head_ok = True
            tail = (tail + block)[-512:]
    if not head_ok:
        raise VerifyError("dump is empty")
    if b"Dump completed" not in tail:
        raise VerifyError("dump is truncated (no 'Dump completed' trailer)")


class Mysql:
    """The mysql / mysqldump CLI with the defaults file (no password on any command line)."""

    def __init__(self, defaults_file):
        self.base = [f"--defaults-extra-file={defaults_file}"]

    def query(self, sql, db=None):
        cmd = ["mysql"] + self.base + ["-N", "-B"] + ([db] if db else []) + ["-e", sql]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)
        if p.returncode != 0:
            raise VerifyError("mysql: " + p.stderr.strip()[:300])
        return [line.split("\t") for line in p.stdout.splitlines() if line]

    def load(self, sql_path, db):
        with open(sql_path, "rb") as f:
            p = subprocess.run(["mysql"] + self.base + [db], stdin=f, capture_output=True, timeout=_TIMEOUT)
        if p.returncode != 0:
            raise VerifyError("restore failed: " + p.stderr.decode("utf-8", "replace").strip()[:300])

    def dump(self, db, out_path):
        cmd = ["mysqldump"] + self.base + ["--single-transaction", "--routines", "--triggers", "--events", db]
        with open(out_path, "wb") as f:
            p = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=_TIMEOUT)
        if p.returncode != 0:
            raise VerifyError("mysqldump: " + p.stderr.decode("utf-8", "replace").strip()[:300])


def table_counts(my, db):
    tables = [r[0] for r in my.query(
        f"SELECT table_name FROM information_schema.tables WHERE table_schema = '{db}' AND table_type = 'BASE TABLE'")]
    return {t: int(my.query(f"SELECT COUNT(*) FROM `{t}`", db)[0][0]) for t in sorted(tables)}


def compare(source, restored, tolerance):
    """Problems between source and restored {table: rows}. The backup is older than the source, so the row count may
    drift by `tolerance` (fraction, at least 500 rows: live telemetry tables grow and are purged); an empty restore of a filled table always fails."""
    problems = [f"table missing in restore: {t}" for t in sorted(set(source) - set(restored))]
    problems += [f"unexpected table in restore: {t}" for t in sorted(set(restored) - set(source))]
    for t in sorted(set(source) & set(restored)):
        s, r = source[t], restored[t]
        if s and not r:
            problems.append(f"{t}: restored empty (source {s})")
        elif abs(s - r) > max(500, tolerance * s):
            problems.append(f"{t}: rows {r} vs source {s}")
    return problems


def verify(cfg, fresh=False, tolerance=0.05, keep=False, out=print):
    src_db = cfg["DB_NAME"]
    if TEST_DB == src_db or not re.fullmatch(r"radius_restore_test", TEST_DB):
        raise VerifyError("refusing: scratch database name collides with the source")
    my = Mysql(cfg["MYSQL_DEFAULTS_FILE"])
    with tempfile.TemporaryDirectory(prefix="emredius_verify_") as work:
        sql = os.path.join(work, "dump.sql")
        if fresh:
            my.dump(src_db, sql)
            out("source: fresh dump of " + src_db)
        else:
            path = latest_backup(cfg["BACKUP_DIR"])
            out(f"source: {path} ({check_sha(path)})")
            extract_sql(path, sql)
        check_dump_safe(sql)
        my.query(f"DROP DATABASE IF EXISTS `{TEST_DB}`")
        my.query(f"CREATE DATABASE `{TEST_DB}` CHARACTER SET utf8mb4")
        try:
            my.load(sql, TEST_DB)
            restored, source = table_counts(my, TEST_DB), table_counts(my, src_db)
        finally:
            if not keep:
                my.query(f"DROP DATABASE IF EXISTS `{TEST_DB}`")
    problems = compare(source, restored, tolerance)
    out(f"tables: {len(restored)} restored / {len(source)} in {src_db}; rows restored {sum(restored.values())} / "
        f"source {sum(source.values())}")
    return problems


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--fresh", action="store_true")
    p.add_argument("--tolerance", type=float, default=0.05)
    p.add_argument("--keep", action="store_true", help="leave the scratch database (debugging)")
    args = p.parse_args(argv)
    from emredius.config import build_config
    cfg = build_config()
    try:
        problems = verify(cfg, args.fresh, args.tolerance, args.keep)
    except (VerifyError, OSError, subprocess.TimeoutExpired) as e:
        print(f"VERIFY_FAILED: {e}")
        return 1
    for pr in problems:
        print("PROBLEM", pr)
    print("VERIFY_FAILED" if problems else "VERIFY_OK")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
