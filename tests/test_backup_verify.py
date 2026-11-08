# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""scripts/backup_verify.py: dump safety checks, row-count comparison, archive extraction (no MariaDB needed)."""
import gzip
import importlib.util
import os
import tarfile

import pytest

from conftest import ROOT

_spec = importlib.util.spec_from_file_location("backup_verify", os.path.join(ROOT, "scripts", "backup_verify.py"))
bv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bv)

OK_SQL = b"CREATE TABLE t (a int);\nINSERT INTO t VALUES (1);\n-- Dump completed on 2026-10-21\n"


def test_extract_from_full_and_sql_archives(tmp_path):
    (tmp_path / "radius_database.sql").write_bytes(OK_SQL)
    full = tmp_path / "radius_full_system_1.tar.gz"
    with tarfile.open(full, "w:gz") as t:
        t.add(tmp_path / "radius_database.sql", arcname="radius_database.sql")
    plain = tmp_path / "radius_backup_1.sql.gz"
    plain.write_bytes(gzip.compress(OK_SQL))
    for src in (full, plain):
        out = tmp_path / "out.sql"
        bv.extract_sql(str(src), str(out))
        assert out.read_bytes() == OK_SQL
    with pytest.raises(bv.VerifyError):
        bv.extract_sql(str(tmp_path / "radius_backup_missing.sql.gz"), str(tmp_path / "x"))


@pytest.mark.parametrize("bad", [b"USE `radius`;\n", b"create database radius;\n", b"DROP DATABASE radius;\n"])
def test_dump_touching_other_databases_is_refused(tmp_path, bad):
    p = tmp_path / "d.sql"
    p.write_bytes(bad + OK_SQL)
    with pytest.raises(bv.VerifyError, match="refusing"):
        bv.check_dump_safe(str(p))


def test_truncated_or_empty_dump_is_refused(tmp_path):
    p = tmp_path / "d.sql"
    p.write_bytes(b"CREATE TABLE t (a int);\n")
    with pytest.raises(bv.VerifyError, match="truncated"):
        bv.check_dump_safe(str(p))
    p.write_bytes(b"")
    with pytest.raises(bv.VerifyError, match="empty"):
        bv.check_dump_safe(str(p))
    p.write_bytes(OK_SQL)
    bv.check_dump_safe(str(p))


def test_compare_counts():
    src = {"a": 1000, "b": 10, "c": 5}
    assert bv.compare(src, {"a": 980, "b": 10, "c": 5}, 0.05) == []
    probs = " ".join(bv.compare(src, {"a": 100, "b": 0, "d": 1}, 0.05))
    assert "a: rows 100" in probs and "b: restored empty" in probs
    assert "table missing in restore: c" in probs and "unexpected table in restore: d" in probs


def test_latest_backup_and_sha(tmp_path):
    with pytest.raises(bv.VerifyError):
        bv.latest_backup(str(tmp_path))
    old, new = tmp_path / "radius_backup_1.sql.gz", tmp_path / "radius_full_system_2.tar.gz"
    old.write_bytes(b"x"); new.write_bytes(b"y")
    os.utime(old, (1, 1))
    assert bv.latest_backup(str(tmp_path)) == str(new)
    assert bv.check_sha(str(new)) == "no sha256 sidecar"
    (tmp_path / (new.name + ".sha256")).write_text("0" * 64 + "\n")
    with pytest.raises(bv.VerifyError, match="mismatch"):
        bv.check_sha(str(new))


def test_scratch_db_name_is_fixed():
    assert bv.TEST_DB == "radius_restore_test"
