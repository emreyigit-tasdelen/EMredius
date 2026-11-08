# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import cli


def test_cli_page_superadmin_only(client):
    login_as(client, "network_admin")
    assert client.get("/cli").status_code == 302
    tok = login_as(client, "network_admin")
    r = client.post("/api/cli/execute", data={"command": "id"}, headers={"X-CSRF-Token": tok})
    assert r.status_code in (302, 403)
    login_as(client, "superadmin")
    body = client.get("/terminal").get_data(as_text=True)
    assert "/static/js/cli.js" in body and "pickTabSuggestion(\\'" not in body


def test_check_command():
    assert cli.check_command("rm -rf /")[1]
    assert cli.check_command("sudo reboot")[1]
    assert cli.check_command("vim /etc/x")[1]
    assert cli.check_command("top")[0].startswith("top -b")
    assert cli.check_command("ls -la") == ("ls -la", None)


def test_execute_refused_in_dry_run(client):
    tok = login_as(client, "superadmin")
    res = client.post("/api/cli/execute", data={"command": "echo hi"}, headers={"X-CSRF-Token": tok}).get_json()
    assert res["returncode"] == -1 and "SYSTEM_DRY_RUN" in res["stderr"] and res["stdout"] == ""
    res = client.post("/api/cli/execute", data={"command": "mkfs.ext4 /dev/sda"}, headers={"X-CSRF-Token": tok}).get_json()
    assert res["success"] is False and "GÜVENLİK" in res["error"]
    assert client.post("/api/cli/execute", data={"command": "id"}).status_code in (400, 403)


def test_execute_runs_outside_dry_run(monkeypatch):
    monkeypatch.setattr(cli, "is_dry_run", lambda: False)
    res = cli.execute("echo hi | tr a-z A-Z")
    assert res["returncode"] == 0 and res["stdout"].strip() == "HI"


def test_autocomplete(client, tmp_path):
    (tmp_path / "abc.txt").write_text("x")
    (tmp_path / "abd").mkdir()
    assert cli.autocomplete(str(tmp_path) + "/ab") == [str(tmp_path / "abc.txt"), str(tmp_path / "abd") + "/"]
    assert "systemctl" in cli.autocomplete("systemc")
    tok = login_as(client, "superadmin")
    r = client.post("/api/cli/autocomplete", data={"prefix": "journ"}, headers={"X-CSRF-Token": tok}).get_json()
    assert "journalctl" in r["matches"]


def test_help_and_catalog(client, monkeypatch):
    out = cli.execute("help")
    assert out["returncode"] == 0 and "FreeRADIUS" in out["stdout"] and "emr-users" in out["stdout"]
    assert "Ağ Tanılama" in cli.execute("help ağ")["stdout"]
    assert cli.execute("emr-nope")["returncode"] == 127
    for _n, _i, _c, cmds in cli.CATALOG:
        for c, _d in cmds:
            assert cli.check_command(c)[1] is None, c
    login_as(client, "superadmin")
    body = client.get("/cli").get_data(as_text=True)
    assert 'data-cmd="emr-users"' in body and "traceroute" in body


def test_builtin_db_and_output_cap(monkeypatch):
    monkeypatch.setattr(cli, "_db_rows", lambda sql: [{"n": 7, "authdate": "t", "username": "u", "reply": "Access-Accept"}])
    assert "7" in cli.execute("emr-users")["stdout"]
    assert "Access-Accept" in cli.execute("emr-lastauth")["stdout"]
    monkeypatch.setattr(cli, "is_dry_run", lambda: False)
    monkeypatch.setattr(cli, "MAX_OUTPUT", 100)
    res = cli.execute("seq 1 5000")
    assert "KESİLDİ" in res["stdout"] and len(res["stdout"]) < 200


def test_builtin_audit_logged(client, monkeypatch):
    tok = login_as(client, "superadmin")
    r = client.post("/api/cli/execute", data={"command": "help"}, headers={"X-CSRF-Token": tok}).get_json()
    assert r["success"] and r["returncode"] == 0
