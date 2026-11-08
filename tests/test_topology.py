# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import inventory as inv, topology as topo

TABLES = {
    "ifname": {"1": "Gi0/1", "2": "Gi0/2"}, "lldp_loc": {"1": "Gi0/1"},
    "lldp": {5: {"0.1.1": b"\xaa\xbb\xcc\xdd\xee\xff"}, 7: {"0.1.1": b"Gi1/0/24"}, 8: {"0.1.1": b"uplink"},
             9: {"0.1.1": b"core-sw"}},
    "lldp_man": {"0.1.1": "10.0.0.1"},
    "cdp": {4: {"2.1": b"\x0a\x00\x00\x09"}, 6: {"2.1": b"edge.lab.local"}, 7: {"2.1": b"Fa0/1"}},
}


def test_parse_neighbors():
    n = topo.parse_neighbors(TABLES)
    l = [x for x in n if x["protocol"] == "LLDP"][0]
    assert (l["local_port"], l["remote_name"], l["remote_port"], l["remote_ip"], l["remote_mac"]) == \
        ("Gi0/1", "core-sw", "uplink", "10.0.0.1", "aa:bb:cc:dd:ee:ff")
    c = [x for x in n if x["protocol"] == "CDP"][0]
    assert (c["local_port"], c["remote_name"], c["remote_ip"]) == ("Gi0/2", "edge", "10.0.0.9")
    assert topo.parse_neighbors({}) == []


def test_graph_merges_and_tenant(app):
    with app.app_context():
        conn = inv._db()
        base = {"mac": "", "hostname": "", "mac_vendor": "", "vendor": "Cisco", "model": "", "os_version": "",
                "sys_name": "", "sys_descr": "", "sys_object_id": "", "device_type": "Switch", "snmp_ok": 1,
                "ssh_ok": 0, "ssh_banner": "", "snmp_community": "public"}
        inv.save_device(conn, dict(base, ip="10.0.0.1", sys_name="core-sw"))
        inv.save_device(conn, dict(base, ip="10.0.0.2", sys_name="acc1"))
        conn.commit(); conn.close()
        c = topo._db()
        topo.save_links(c, "10.0.0.2", [{"local_port": "Gi0/1", "remote_name": "core-sw", "remote_port": "Gi1/0/24",
                                         "remote_ip": "", "remote_mac": "", "protocol": "LLDP"},
                                        {"local_port": "Gi0/9", "remote_name": "ap-x", "remote_port": "eth0",
                                         "remote_ip": "", "remote_mac": "", "protocol": "CDP"}])
        topo.save_links(c, "10.0.0.1", [{"local_port": "Gi1/0/24", "remote_name": "acc1", "remote_port": "Gi0/1",
                                         "remote_ip": "10.0.0.2", "remote_mac": "", "protocol": "CDP"}])
        topo.save_links(c, "10.0.0.2", [{"local_port": "x", "remote_name": "t2", "remote_port": "", "remote_ip": "",
                                         "remote_mac": "", "protocol": "LLDP"}], tenant_id=2)
        c.commit(); c.close()
        g = topo.graph(q="core")
        assert len(g["nodes"]) == 3 and g["stats"]["unknown"] == 1
        assert len(g["edges"]) == 2  # iki yönlü bağlantı tek kenar, protokoller birleşir
        both = [e for e in g["edges"] if len(e["protocols"]) == 2]
        assert both and [n["match"] for n in g["nodes"] if n["id"] == "10.0.0.1"] == [True]
        assert len(topo.list_links()) == 3 and len(topo.list_links(tenant_id=2)) == 1
        assert "'=x" in topo.links_csv([dict(topo.list_links()[0], local_port="=x")])


def test_pages_api_rbac(client):
    login_as(client, "superadmin")
    assert client.get("/topology").status_code == 200
    assert client.get("/topology/data").get_json()["success"]
    assert client.get("/topology/export.csv").status_code == 200
    assert client.get("/topology/export.json").status_code == 200
    assert client.get("/topology/export.xml").status_code == 404
    assert client.post("/topology/discover", data={"_csrf_token": "tok"}).status_code in (200, 302, 400)
    login_as(client, "helpdesk")
    assert client.get("/topology").status_code in (302, 403)


def test_manual_type_override(app, client):
    with app.app_context():
        devs = [{"ip": "10.1.0.1", "sys_name": "x1", "hostname": "", "device_type": "Switch", "vendor": "", "model": "",
                 "status": "ONLINE", "mac": ""}]
        links = [{"local_ip": "10.1.0.1", "local_port": "1", "remote_name": "ph1", "remote_port": "", "remote_ip": "",
                  "remote_mac": "", "protocol": "LLDP", "last_seen": ""}]
        assert topo.set_override("10.1.0.1", "Router", "t") == (True, "")
        assert topo.set_override("ph1", "IP Telefon", "t")[0]
        assert not topo.set_override("ph1", "Uzay Gemisi", "t")[0] and not topo.set_override("", "Router")[0]
        g = topo.build_graph(devs, links, overrides=topo.list_overrides())
        n = {x["id"]: x for x in g["nodes"]}
        assert (n["10.1.0.1"]["type"], n["10.1.0.1"]["auto_type"], n["10.1.0.1"]["manual"]) == ("Router", "Switch", True)
        assert n["ph1"]["type"] == "IP Telefon"
        assert topo.list_overrides(tenant_id=2) == {}
        topo.set_override("10.1.0.1", "auto")
        assert "10.1.0.1" not in topo.list_overrides()
    login_as(client, "superadmin")
    r = client.post("/topology/type", json={"node": "n9", "type": "Firewall"}, headers={"X-CSRF-Token": "tok"})
    assert r.status_code in (200, 400)
