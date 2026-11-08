# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import configs as cf, inventory as inv

K = "test-secret-key"


def _dev(ip="10.0.0.1", vendor="Cisco"):
    c = inv._db()
    c.execute("INSERT INTO inv_devices (tenant_id,ip,sys_name,vendor,status) VALUES (1,?,?,?,'ONLINE')", (ip, "sw-" + ip[-1], vendor))
    c.commit(); c.close()


def test_crypto_versions_diff_compliance(app):
    t = cf.encrypt(K, "s3cret")
    assert "s3cret" not in t and cf.decrypt(K, t) == "s3cret" and cf.decrypt("other", t) == "" and cf.decrypt(K, "") == ""
    with app.app_context():
        _dev()
        assert cf.manual_backup("9.9.9.9", "x")[0] is None
        assert cf.manual_backup("10.0.0.1", "  ")[0] is None
        v1, e = cf.manual_backup("10.0.0.1", "hostname sw\nservice password-encryption\n")
        assert v1 == 1 and not e
        assert cf.manual_backup("10.0.0.1", "hostname sw\nservice password-encryption")[0] == 1       # aynı içerik: yeni sürüm yok
        v2, _ = cf.manual_backup("10.0.0.1", "hostname sw2\nservice password-encryption\nntp server 1.1.1.1")
        assert v2 == 2 and [v["version"] for v in cf.list_versions("10.0.0.1")] == [2, 1]
        d = cf.diff("10.0.0.1", 1, 2)
        assert d["added"] == 2 and d["removed"] == 1 and cf.diff("10.0.0.1", 1, 9) is None
        assert cf.get_version("10.0.0.1", 1, tenant_id=2) is None
        assert cf.add_rule("", "must_contain", "x") and cf.add_rule("r", "zzz", "x") and cf.add_rule("r", "must_contain", "([")
        assert cf.add_rule("şifreleme", "must_contain", r"^service password-encryption", "cisco") == ""
        assert cf.add_rule("telnet yok", "must_not_contain", r"transport input telnet") == ""
        assert cf.add_rule("ntp", "must_contain", r"^ntp server", "juniper") == ""        # üretici uymuyor: atlanır
        c = cf.compliance()[0]
        assert c["state"] == "ok" and c["rules"] == 2 and c["version"] == 2
        cf.manual_backup("10.0.0.1", "line vty\n transport input telnet")
        assert cf.compliance()[0]["violations"] == ["şifreleme", "telnet yok"] and cf.overview()["violations"] == 1
        assert "şifreleme" in cf.compliance_csv(cf.compliance()) and cf.compliance(tenant_id=2) == []


def test_templates_and_push_guards(app, monkeypatch):
    cmds, err = cf.render_template("hostname {{hostname}}\nsnmp-server community {{ comm }} ro\n\nntp {{ip}}", {"comm": "abc"}, {"ip": "10.0.0.1", "sys_name": "sw1"})
    assert err == "" and cmds == ["hostname sw1", "snmp-server community abc ro", "ntp 10.0.0.1"]
    assert cf.render_template("x {{nope}}", {})[0] is None
    assert cf.render_template("x {{a}}", {"a": "1\nreload"})[0] == ["x 1 reload"]               # satır enjeksiyonu engellenir
    with app.app_context():
        _dev(); _dev("10.0.0.2", "Huawei")
        assert cf.add_template("", "x") and cf.add_template("t", "")
        assert cf.add_template("ntp", "ntp server {{srv}}", "Cisco") == ""
        tid = cf.list_templates()[0]["id"]
        r = cf.push(["10.0.0.1", "10.0.0.2", "8.8.8.8"], tid, {"srv": "1.1.1.1"}, K, 0, dry_run=True)
        assert r[0]["commands"] == ["ntp server 1.1.1.1"] and "Cisco" in r[1]["error"] and "envanterde" in r[2]["error"]
        r = cf.push(["10.0.0.1"], tid, {"srv": "1.1.1.1"}, K, 0, dry_run=False)               # ayar kapalı
        assert not r[0]["ok"] and "kapalı" in r[0]["error"]
        monkeypatch.setattr(cf, "push_enabled", lambda: True)
        monkeypatch.setattr(cf, "ssh_available", lambda: True)
        assert cf.add_cred(K, "", "u", "p") and cf.add_cred(K, "n", "u", "p", port=99999)
        assert cf.add_cred(K, "lab", "admin", "pw", "en") == ""
        cid = cf.list_creds()[0]["id"]
        assert "secret" not in str(cf.list_creds()) and cf._cred(K, cid, 1)["password"] == "pw" and cf._cred(K, cid, 2) is None
        state = {"cfg": "hostname a", "sent": []}

        def fake(ip, cred, commands, timeout=20):
            if commands[-1].startswith("show running"):
                return state["cfg"]
            state["sent"].append(commands)
            state["cfg"] += "\nntp server 1.1.1.1"
            return "ok"
        monkeypatch.setattr(cf, "_ssh_run", fake)
        r = cf.push(["10.0.0.1"], tid, {"srv": "1.1.1.1"}, K, cid, "emre", dry_run=False)
        assert r[0]["ok"] and r[0]["backup"] == 1 and r[0]["after"] == 2 and state["sent"] == [["ntp server 1.1.1.1"]]
        assert [v["source"] for v in cf.list_versions("10.0.0.1")] == ["post-push", "pre-push"]
        monkeypatch.setattr(cf, "_ssh_run", lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
        r = cf.push(["10.0.0.1"], tid, {"srv": "x"}, K, cid, dry_run=False)
        assert not r[0]["ok"] and "Yedek alınamadı" in r[0]["error"]                            # yedek yoksa gönderilmez
        assert cf.delete_cred(cid) and not cf.delete_cred(cid, tenant_id=2) and cf.delete_template(tid)


def test_pages_rbac(app, client):
    with app.app_context():
        _dev()
        cf.manual_backup("10.0.0.1", "hostname a")
    login_as(client, "superadmin")
    assert client.get("/configs").status_code == 200 and client.get("/configs/data").get_json()["success"]
    assert client.get("/configs/10.0.0.1/versions").get_json()["versions"][0]["version"] == 1
    assert client.get("/configs/10.0.0.1/v/1").get_json()["content"] == "hostname a"
    assert client.get("/configs/10.0.0.1/v/9").status_code == 404 and client.get("/configs/10.0.0.1/diff?a=1&b=2").status_code == 404
    assert client.get("/configs/export.csv").status_code == 200 and client.get("/configs/export.json").status_code == 200
    assert client.get("/configs/export.xml").status_code == 404
    r = client.post("/configs/push", data={"_csrf_token": "tok", "ips": "10.0.0.1", "template_id": "1", "confirm": "GONDER"})
    assert r.status_code in (200, 302, 400)
    login_as(client, "network_admin")                       # yalnızca süper yönetici
    assert client.get("/configs").status_code in (302, 403)
    assert client.get("/configs/10.0.0.1/v/1").status_code in (302, 403)


def test_scheduled_backup_all(app, client, monkeypatch):
    with app.app_context():
        _dev(); _dev("10.0.0.2")
        c = inv._db()
        c.execute("UPDATE inv_devices SET ssh_ok=1 WHERE ip IN ('10.0.0.1','10.0.0.2')"); c.commit(); c.close()
        calls = []

        def fake_collect(ip, key, cred, user="", source="ssh", tenant_id=1):
            calls.append((ip, source))
            return (None, "boom") if ip.endswith("2") else (1, "")
        monkeypatch.setattr(cf, "collect", fake_collect)
        assert cf.backup_all(K, 5) == (1, 1) and calls == [("10.0.0.1", "scheduled"), ("10.0.0.2", "scheduled")]
        assert "1 başarılı" in cf.schedule_settings()["result"] and not cf.schedule_settings()["enabled"]   # varsayılan kapalı
    login_as(client, "superadmin")
    assert client.post("/configs/schedule", data={"_csrf_token": "tok", "enabled": "1", "cred_id": "1", "hours": "6"}).status_code in (200, 302, 400)
