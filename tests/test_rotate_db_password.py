# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
import contextlib
import importlib.util
import io
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("rotate_db_password", os.path.join(ROOT, "scripts", "rotate_db_password.py"))
rot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rot)

OLD = "OldPw-12345"
CONF = 'sql {\n\tdriver = "rlm_sql_mysql"\n\tserver = "localhost"\n\tlogin = "radius"\n\tpassword = "%s"\n' \
       '\tmysql {\n\t\ttls {\n\t\t}\n\t}\n}\n' % OLD


def _setup(tmp_path, monkeypatch, login_ok=True):
    conf = tmp_path / "sql"
    conf.write_text(CONF, encoding="utf-8")
    os.chmod(conf, 0o640)
    state = {"pw": OLD, "sql": []}

    def fake_mysql(sql, root_cnf, run=None):
        state["sql"].append(sql)
        if sql.startswith("SELECT host"):
            return "localhost\n127.0.0.1\n"
        state["pw"] = sql.split("IDENTIFIED BY '", 1)[1].split("'", 1)[0]
        return ""

    monkeypatch.setattr(rot, "mysql", fake_mysql)
    monkeypatch.setattr(rot, "can_login", lambda user, pw, run=None: login_ok and pw == state["pw"])
    return conf, state


def _run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = rot.main(argv)
    return rc, out.getvalue()


def test_find_and_replace_keep_layout():
    assert rot.find_password(CONF)[1:] == ("\t", OLD)
    new = rot.replace_password(CONF, "N3w_pw-x")
    assert '\tpassword = "N3w_pw-x"\n' in new and new.replace("N3w_pw-x", OLD) == CONF


def test_rotate_updates_db_and_conf_without_printing(tmp_path, monkeypatch):
    conf, state = _setup(tmp_path, monkeypatch)
    bdir = tmp_path / "bk"
    rc, out = _run(["--conf", str(conf), "--backup-dir", str(bdir)])
    assert rc == 0, out
    new = state["pw"]
    assert new != OLD and len(new) >= 40
    assert rot.find_password(conf.read_text(encoding="utf-8"))[2] == new
    assert oct(os.stat(conf).st_mode & 0o777) == "0o640"
    assert (bdir / "sql").read_text(encoding="utf-8") == CONF and oct(os.stat(bdir / "sql").st_mode & 0o777) == "0o600"
    assert new not in out and OLD not in out
    assert all("'localhost'" in s and "'127.0.0.1'" in s for s in state["sql"][1:])
    # a second run must not overwrite the backup of the original
    rc, out = _run(["--conf", str(conf), "--backup-dir", str(bdir)])
    assert rc == 1 and "zaten var" in out
    # rollback
    rc, out = _run(["--conf", str(conf), "--backup-dir", str(bdir), "--restore"])
    assert rc == 0 and state["pw"] == OLD and conf.read_text(encoding="utf-8") == CONF


def test_rotate_reverts_when_new_password_does_not_work(tmp_path, monkeypatch):
    conf, state = _setup(tmp_path, monkeypatch, login_ok=False)
    rc, out = _run(["--conf", str(conf), "--backup-dir", str(tmp_path / "bk")])
    assert rc == 1 and "geri alındı" in out
    assert state["pw"] == OLD and conf.read_text(encoding="utf-8") == CONF


def test_sql_quote_rejects_quotes():
    import pytest
    with pytest.raises(ValueError):
        rot._sql_quote("a'b")
