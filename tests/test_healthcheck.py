# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
import contextlib
import importlib.util
import io
import os
import stat
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PW = "Sekret-Pw-123"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "scripts", name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


hc = _load("healthcheck")
setup = _load("healthcheck_setup")

CLIENTS = """
# comment { with brace
client localhost {
    ipaddr = 127.0.0.1
    proto = *
    secret = "loc-secret"   # trailing comment
    limit {
        max_connections = 16
        secret = nested-ignored
    }
}
client switch1 {
    ipaddr = 10.0.0.1
    secret = other
}
"""


def _env(**kw):
    e = {"HC_URL": "https://127.0.0.1", "HC_ADMIN_USER": "healthcheck", "HC_ADMIN_PASS": PW,
         "HC_RADIUS_USER": "emredius-healthcheck", "HC_RADIUS_PASS": PW, "HC_RADIUS_SECRET": PW}
    e.update(kw)
    return e


def _run_main(m, argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = m.main(argv)
    return rc, buf.getvalue()


def test_parse_clients_conf_localhost_secret():
    cs = setup.parse_clients_conf(CLIENTS)
    assert [(c["name"], c["ipaddr"], c["secret"]) for c in cs] == [
        ("localhost", "127.0.0.1", "loc-secret"), ("switch1", "10.0.0.1", "other")]
    assert setup.localhost_secret_from_conf(CLIENTS) == "loc-secret"
    assert setup.localhost_secret_from_conf("client sw { ipaddr = 10.0.0.2\n secret = x\n}\n") is None
    assert setup.localhost_secret_from_conf("client localhost {\n secret = 'q'\n}\n") == "q"


def test_write_secret_file_is_0600_and_never_overwrites(tmp_path):
    p = str(tmp_path / "hc.env")
    setup.write_secret_file(p, setup.render_env(_env()))
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert hc.read_env(p) == _env()
    with pytest.raises(FileExistsError):
        setup.write_secret_file(p, "X=1\n")
    rc, out = _run_main(setup, ["--out", p])
    assert rc == 1 and "zaten var" in out


def test_radius_accept_reject_and_secret_handling():
    seen = {}

    def fake_run(cmd, input=None, **kw):
        path = cmd[cmd.index("-S") + 1]
        seen.update(cmd=cmd, input=input, mode=stat.S_IMODE(os.stat(path).st_mode),
                    secret=open(path, encoding="utf-8").read().strip(), path=path)
        return subprocess.CompletedProcess(cmd, 0, f"Sent Access-Request User-Password = \"{PW}\"\n"
                                                   "Received Access-Accept Id 1\n", "")

    assert hc.check_radius(_env(), run=fake_run) == (True, "Access-Accept")
    assert PW not in " ".join(seen["cmd"])  # never on the command line
    assert seen["mode"] == 0o600 and seen["secret"] == PW and not os.path.exists(seen["path"])
    assert 'User-Name = "emredius-healthcheck"' in seen["input"] and "NAS-IP-Address = 127.0.0.1" in seen["input"]

    def reject(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 1, "Received Access-Reject\n", "")
    assert hc.check_radius(_env(), run=reject) == (False, "Access-Reject")

    def missing(cmd, **kw):
        raise FileNotFoundError
    assert hc.check_radius(_env(), run=missing) == (False, "radclient yok")
    with pytest.raises(ValueError):
        hc.radclient_input(_env(HC_RADIUS_PASS='a"b'))


def test_panel_flow(monkeypatch):
    calls = []
    answers = {}

    def fake_open(opener, url, data=None):
        calls.append((url, data is not None))
        return answers[(url, data is not None)]

    monkeypatch.setattr(hc, "_open", fake_open)
    answers.update({("https://127.0.0.1/login", False): (200, "/login"),
                    ("https://127.0.0.1/login", True): (302, "https://127.0.0.1/"),
                    ("https://127.0.0.1/", False): (200, "/"),
                    ("https://127.0.0.1/logout", False): (200, "/login")})
    ok, msg = hc.check_panel(_env())
    assert ok and PW not in msg and calls[-1][0].endswith("/logout")

    answers[("https://127.0.0.1/login", True)] = (200, "")  # wrong password re-renders the form
    assert hc.check_panel(_env())[0] is False
    answers[("https://127.0.0.1/login", True)] = (302, "/login/2fa")
    assert hc.check_panel(_env()) == (False, "giriş başarısız (302 /login/2fa)")


def test_main_prints_no_secrets(tmp_path, monkeypatch):
    p = str(tmp_path / "hc.env")
    setup.write_secret_file(p, setup.render_env(_env()))
    monkeypatch.setattr(hc, "check_panel", lambda env: (True, "giriş + dashboard (/)"))
    monkeypatch.setattr(hc, "check_radius", lambda env: (_ for _ in ()).throw(RuntimeError(PW)))
    rc, out = _run_main(hc, ["--env", p])
    assert rc == 1 and "OK panel" in out and "FAIL radius: RuntimeError" in out and PW not in out
    rc, out = _run_main(hc, ["--env", p, "--skip-radius"])
    assert rc == 0 and "radius" not in out
    rc, out = _run_main(hc, ["--env", str(tmp_path / "none.env")])
    assert rc == 1 and out.startswith("FAIL env")
    open(p + "2", "w").write("HC_URL=x\n")
    rc, out = _run_main(hc, ["--env", p + "2"])
    assert rc == 1 and "HC_ADMIN_PASS" in out
