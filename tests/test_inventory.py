# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import inventory as inv, llm


def test_range_validation_and_tenant(app):
    with app.app_context():
        assert inv.add_range("abc")
        assert inv.add_range("10.1.1.0/24", "A", "public,x", 5) is None
        assert inv.add_range("10.1.1.0/24") == "Bu aralık zaten kayıtlı."
        assert inv.add_range("10.2.0.0/24", tenant_id=2) is None
        assert [r["cidr"] for r in inv.list_ranges()] == ["10.1.1.0/24"]
        assert len(inv.list_ranges(tenant_id=2)) == 1
        rid = inv.list_ranges()[0]["id"]
        assert not inv.delete_range(rid, tenant_id=2)  # başka kiracı silemez
        assert inv.delete_range(rid)


def test_parse_and_classify():
    m, v = inv.parse_model_version("Cisco IOS Software, C2960X Software, Version 15.2(7)E3, RELEASE")
    assert m == "C2960X" and v.startswith("15.2")
    assert inv.ssh_vendor("SSH-2.0-ROSSSH") == "MikroTik"
    assert inv.classify("Cisco", "Catalyst switch", 1, 1) == "Switch"
    assert inv.classify("", "", 0, 0) == "Bilinmiyor"


def test_save_list_filter_csv(app):
    with app.app_context():
        conn = inv._db()
        base = {"mac": "", "hostname": "", "mac_vendor": "", "vendor": "Cisco", "model": "C2960", "os_version": "15",
                "sys_name": "=sw1", "sys_descr": "", "sys_object_id": "", "device_type": "Switch", "snmp_ok": 1,
                "ssh_ok": 0, "ssh_banner": "", "snmp_community": "public"}
        inv.save_device(conn, dict(base, ip="10.1.1.2"))
        inv.save_device(conn, dict(base, ip="10.1.1.1", vendor="", model=""))
        inv.save_device(conn, dict(base, ip="10.1.1.1", vendor="", model=""), tenant_id=2)
        conn.commit(); conn.close()
        devs = inv.list_devices()
        assert [d["ip"] for d in devs] == ["10.1.1.1", "10.1.1.2"]
        assert len(inv.list_devices(q="C2960")) == 1 and not inv.list_devices(vendor="Nokia")
        inv.save_device(inv._db(), dict(base, ip="10.1.1.2", model="", vendor=""))  # boş sonuç eskiyi silmez
        assert inv.list_devices(q="10.1.1.2")[0]["vendor"] == "Cisco"
        assert "'=sw1" not in inv.devices_csv(devs)  # sys_name CSV'de yok; hostname kaçışı aşağıda
        d = dict(devs[0], ip="=1+1")
        assert "'=1+1" in inv.devices_csv([d])


def test_pages_and_api(client):
    login_as(client, "superadmin")
    assert client.get("/inventory").status_code == 200
    tok = "tok"
    r = client.post("/inventory/range/add", data={"cidr": "10.9.0.0/24", "_csrf_token": tok})
    assert r.status_code == 302
    assert b"10.9.0.0/24" in client.get("/inventory").data
    assert client.get("/inventory/data").get_json()["success"]
    assert client.get("/inventory/export.csv").status_code == 200
    assert client.get("/inventory/export.json").status_code == 200
    assert client.get("/inventory/export.xml").status_code == 404


def test_inventory_rbac(client):
    login_as(client, "helpdesk")
    assert client.get("/inventory").status_code in (302, 403)


def test_llm_silent_when_off(monkeypatch):
    monkeypatch.setattr(llm, "get_setting", lambda k, d="": d)
    assert llm.generate("x") is None and llm.explain_alarm({"message": "m"}) is None
    monkeypatch.setattr(llm, "get_setting", lambda k, d="": {"llm_enabled": "1", "llm_model": "m", "llm_url": "http://evil.example"}.get(k, d))
    assert llm.generate("x") is None  # loopback dışı URL reddedilir
