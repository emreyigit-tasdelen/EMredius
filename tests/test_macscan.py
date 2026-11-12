# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import equipment as eq, inventory as inv, macscan as ms

PORTS = [{"if_index": 1, "name": "Gi1/0/1", "if_type": 6}, {"if_index": 2, "name": "Gi1/0/2", "if_type": 6},
         {"if_index": 9, "name": "Vlan10", "if_type": 53}]


def test_parse_poe():
    t = {"port": {3: {"1.1": 1, "1.2": 2}, 6: {"1.1": 3, "1.2": 2}, 10: {"1.1": 3}},
         "main": {2: {"1": 370}, 3: {"1": 1}, 4: {"1": 42}}, "cpe": {"1": 7500}}
    poe, main = ms.parse_poe(t, PORTS)
    assert [(r["port"], r["admin"], r["detection"], r["power_class"], r["power_mw"]) for r in poe] == \
        [("Gi1/0/1", "on", "delivering", "2", 7500), ("Gi1/0/2", "off", "searching", "", 0)]
    assert main == [{"grp": 1, "budget_w": 370, "used_w": 42, "oper": "on"}]
    assert ms.parse_poe({}, PORTS) == ([], [])  # PoE yok: sessiz


def test_parse_arp():
    mac = b"\xaa\xbb\xcc\xdd\xee\x01"
    out = ms.parse_arp({"arp": {"5.10.0.0.7": mac, "5.300.0.0.7": mac, "5.10.0.7": mac},
                        "arp6": {"5.1.4.10.0.0.8": mac}})
    assert out == [{"ip": "10.0.0.7", "mac": "aa:bb:cc:dd:ee:01", "if_index": 5},
                   {"ip": "10.0.0.8", "mac": "aa:bb:cc:dd:ee:01", "if_index": 5}]


def test_guess_kind():
    assert ms.guess_kind("Yealink Network Technology") == "IP Telefon"
    assert ms.guess_kind("Hikvision Digital") == "Kamera"
    assert ms.guess_kind("Dell Inc.") == ""
    assert inv.classify("", "Yealink SIP-T46U IP Phone", 1, 0) == "IP Telefon"


def test_list_rows_join(app):
    with app.app_context():
        c = eq._db()
        eq.save_device_data(c, "10.0.0.1", [{"if_index": 1, "name": "Gi1/0/1", "descr": "", "alias": "", "if_type": 6, "speed_mbps": 1000,
                                             "admin_status": "up", "oper_status": "up", "mac": ""}],
                            [{"mac": "aa:bb:cc:dd:ee:01", "vlan": 10, "if_index": 1, "port": "Gi1/0/1"}], [])
        c.commit(); c.close()
        c = ms._db()
        ms.save_device(c, "10.0.0.1", [{"grp": 1, "pport": 1, "if_index": 1, "port": "Gi1/0/1", "admin": "on", "detection": "delivering",
                                        "power_class": "2", "power_mw": 6500}], [],
                       [{"ip": "10.0.0.50", "mac": "aa:bb:cc:dd:ee:01", "if_index": 5}])
        c.commit(); c.close()
        rows = ms.list_rows()
        assert len(rows) == 1 and rows[0]["ip"] == "10.0.0.50" and rows[0]["poe_state"] == "delivering" and rows[0]["poe_w"] == 6.5
        assert ms.list_rows(poe_only=True) and not ms.list_rows(q="zz:zz")
        assert "aa:bb:cc:dd:ee:01" in ms.to_csv(rows)


def test_macscan_page_and_export(client):
    login_as(client, "superadmin")
    assert client.get("/macscan").status_code == 200
    assert client.get("/macscan/data").get_json()["success"] is True
    assert client.get("/macscan/export.csv").status_code == 200
    assert client.get("/macscan/export.json").status_code == 200
    assert client.get("/macscan/export.xml").status_code == 404


def test_parse_poe_robust():
    # Cisco tüketimi grp.port dizinli; bozuk/eksik veri çökertmez; aynı ifIndex'e düşen çift eşleme boş kalır
    t = {"port": {3: {"1.1": 1, "1.2": "x"}, 6: {"1.1": 3}}, "main": {3: {"1": 1}},
         "cpe": {"1.1": 6400, "1.2": -5}}
    poe, main = ms.parse_poe(t, PORTS)
    assert poe[0]["power_mw"] == 6400 and poe[1]["power_mw"] == 0 and poe[1]["admin"] == ""
    assert main and main[0]["oper"] == "on"
    for bad in (None, {"port": None}, {"port": {3: None}}, {"port": {3: {"a.b": 1}}, "cpe": []}):
        ms.parse_poe(bad, PORTS)
    ms.parse_poe(t, None)
    ms.parse_poe(t, [{"if_index": 1}, "x"])
