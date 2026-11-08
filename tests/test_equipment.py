# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import equipment as eq, inventory as inv

T = {
    "ifname": {"1": "Gi0/1", "2": "Gi0/2", "9": "Vlan10"}, "ifdescr": {"1": "Gi0/1", "2": "Gi0/2", "9": "Vlan10"},
    "iftype": {"1": 6, "2": 6, "9": 53}, "ifadmin": {"1": 1, "2": 2}, "ifoper": {"1": 1, "2": 2},
    "ifspeed": {"1": 1000}, "ifalias": {"1": b"uplink"}, "ifphys": {"1": b"\xaa\xbb\xcc\xdd\xee\x01"},
    "qfdb": {"10.1.2.3.4.5.6": 3, "20.1.2.3.4.5.7": 3, "10.1.2.3.4.5": 3, "10.1.2.3.4.5.6.7": 3},
    "bport": {"3": "1"},
    "ent": {2: {"1": b"Chassis X"}, 5: {"1": 3, "2": 9}, 4: {"2": 1}, 7: {"1": b"Chassis", "2": b"Slot 1"},
            11: {"1": b"SN123"}, 13: {"1": b"C9300-48P"}},
}


def test_parse_device():
    ports, macs, chassis = eq.parse_device(T)
    assert [p["name"] for p in ports] == ["Gi0/1", "Gi0/2"]  # sanal arayüz elendi
    assert (ports[0]["oper_status"], ports[0]["speed_mbps"], ports[0]["mac"], ports[0]["alias"]) == \
        ("up", 1000, "aa:bb:cc:dd:ee:01", "uplink")
    assert ports[1]["admin_status"] == "down"
    assert len(macs) == 2 and macs[0]["port"] == "Gi0/1" and {m["vlan"] for m in macs} == {10, 20}
    assert chassis[0]["ent_class"] == "chassis" and chassis[0]["serial"] == "SN123" and chassis[0]["model"] == "C9300-48P"
    assert eq.parse_device({}) == ([], [], [])
    # eski BRIDGE-MIB (VLAN yok)
    _, m2, _ = eq.parse_device({"ifname": {"1": "e1"}, "dfdb": {"1.2.3.4.5.6": 1}})
    assert m2[0]["mac"] == "01:02:03:04:05:06" and m2[0]["vlan"] == 0 and m2[0]["port"] == "e1"
    assert eq.norm_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff" and eq.norm_mac("zz") == ""


def test_store_enrich_tenant(app):
    with app.app_context():
        conn = inv._db()
        base = {"mac": "", "hostname": "", "mac_vendor": "", "vendor": "Cisco", "model": "", "os_version": "", "sys_name": "",
                "sys_descr": "", "sys_object_id": "", "device_type": "Switch", "snmp_ok": 1, "ssh_ok": 0, "ssh_banner": "",
                "snmp_community": "public"}
        inv.save_device(conn, dict(base, ip="10.0.0.1", sys_name="sw1"))
        inv.save_device(conn, dict(base, ip="10.0.0.7", sys_name="host7", mac="01:02:03:04:05:06", snmp_ok=0))
        conn.commit(); conn.close()
        ports, macs, chassis = eq.parse_device(T)
        c = eq._db()
        eq.save_device_data(c, "10.0.0.1", ports, macs, chassis)
        eq.save_device_data(c, "10.0.0.1", ports, macs, chassis)  # tekrar: çoğalmaz
        eq.save_device_data(c, "10.0.0.1", ports, macs, chassis, tenant_id=2)
        c.commit(); c.close()
        assert len(eq.list_ports()) == 2 and len(eq.list_macs(enrich=False)) == 2 and len(eq.list_chassis()) == 2
        assert len(eq.list_ports(tenant_id=2)) == 2
        r = eq.list_macs(q="01:02:03:04:05:06")
        assert len(r) == 1 and r[0]["inv_ip"] == "10.0.0.7" and r[0]["radius_user"] == ""
        assert len(eq.list_macs(vlan="20")) == 1 and len(eq.list_ports(state="up")) == 1
        s = eq.device_summary()
        assert s[0]["ip"] == "10.0.0.1" and (s[0]["ports"], s[0]["ports_up"], s[0]["macs"], s[0]["modules"]) == (2, 1, 2, 2)
        assert eq.panel("10.0.0.1")[0]["mac_count"] == 2
        assert "'=x" in eq.to_csv("ports", [dict(eq.list_ports()[0], name="=x", device_ip="=x")])
        assert eq.overview()["macs"] == 2


def test_pages_api_rbac(client):
    login_as(client, "superadmin")
    assert client.get("/equipment").status_code == 200
    for k in ("summary", "panel", "macs", "ports", "chassis"):
        assert client.get(f"/equipment/data/{k}").get_json()["success"]
    assert client.get("/equipment/data/zzz").status_code == 404
    for k in ("ports", "macs", "chassis"):
        for fmt in ("csv", "json"):
            assert client.get(f"/equipment/export/{k}.{fmt}").status_code == 200
    assert client.get("/equipment/export/macs.xml").status_code == 404
    assert client.post("/equipment/discover", data={"_csrf_token": "tok"}).status_code in (200, 302, 400)
    login_as(client, "helpdesk")
    assert client.get("/equipment").status_code in (302, 403)
