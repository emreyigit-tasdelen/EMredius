# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import inventory as inv, ipam


def _dev(ip, status="ONLINE", mac=""):
    c = inv._db()
    c.execute("INSERT INTO inv_devices (tenant_id,ip,sys_name,mac,status) VALUES (1,?,?,?,?)", (ip, "d" + ip.split(".")[-1], mac, status))
    c.commit(); c.close()


def test_subnets_validation_and_usage(app):
    with app.app_context():
        for bad in ("", "10.0.0.0/4", "::1/64", "abc"):
            assert ipam.add_subnet(bad)
        assert ipam.add_subnet("10.0.0.0/24", gateway="10.1.1.1") and ipam.add_subnet("10.0.0.0/24", vlan=5000) and ipam.add_subnet("10.0.0.0/24", vlan="x")
        assert ipam.add_subnet("10.0.0.0/24", "LAN", 10, "10.0.0.1", "merkez") == ""
        assert ipam.add_subnet("10.0.0.5/24") == "Bu alt ağ zaten tanımlı."
        assert ipam.add_subnet("10.0.0.0/16", "tüm") == ""                       # farklı uzunluk: üst ağ olabilir
        assert ipam.add_addr("bad") and ipam.add_addr("10.0.0.2", kind="zzz") and ipam.add_addr("::1")
        assert ipam.add_addr("10.0.0.1", "gw", "ağ", "gateway") == "" and ipam.add_addr("10.0.0.1") == "Bu adres zaten kayıtlı."
        assert ipam.add_addr("10.0.0.50", "rezerve", kind="reserved") == ""
        _dev("10.0.0.1"); _dev("10.0.0.7"); _dev("10.0.0.8", "OFFLINE"); _dev("10.9.9.9")
        subs = {s["cidr"]: s for s in ipam.list_subnets()}
        s = subs["10.0.0.0/24"]
        assert (s["total"], s["planned"], s["discovered"], s["used"], s["free"]) == (254, 2, 2, 3, 251)
        assert (s["unplanned"], s["missing"], s["parent"]) == (1, 1, "10.0.0.0/16") and subs["10.0.0.0/16"]["parent"] == ""
        rows = {r["ip"]: r["state"] for r in ipam.compare("10.0.0.0/24")}
        assert rows == {"10.0.0.1": "ok", "10.0.0.7": "unplanned", "10.0.0.8": "offline", "10.0.0.50": "planned_only"}
        assert ipam.free_addresses("10.0.0.0/24", count=3) == ["10.0.0.2", "10.0.0.3", "10.0.0.4"]
        assert ipam.free_addresses("10.0.0.0/30") == ["10.0.0.2"] or ipam.free_addresses("10.0.0.0/30")[0] == "10.0.0.2"
        assert ipam.compare("bad") is None and ipam.free_addresses("bad") == []
        assert len(ipam.list_subnets(q="merkez")) == 1 and ipam.list_subnets(tenant_id=2) == []
        o = ipam.overview()
        assert o["subnets"] == 2 and o["unplanned"] >= 1
        assert "10.0.0.0/24" in ipam.subnets_csv(ipam.list_subnets())
        sid = subs["10.0.0.0/24"]["id"]
        assert not ipam.delete_subnet(sid, tenant_id=2) and ipam.delete_subnet(sid)


def test_pages_rbac(app, client):
    with app.app_context():
        ipam.add_subnet("192.168.1.0/24", "x")
    login_as(client, "superadmin")
    assert client.get("/ipam").status_code == 200 and client.get("/ipam?q=x").status_code == 200
    assert client.get("/ipam/data").get_json()["success"]
    j = client.get("/ipam/detail?cidr=192.168.1.0/24").get_json()
    assert j["success"] and j["free"][0] == "192.168.1.1"
    assert client.get("/ipam/detail?cidr=zzz").status_code == 400
    assert client.get("/ipam/export.csv").status_code == 200 and client.get("/ipam/export.json").status_code == 200
    assert client.get("/ipam/export.xml").status_code == 404
    login_as(client, "helpdesk")
    assert client.get("/ipam").status_code in (302, 403)
