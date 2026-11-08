# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import equipment as eq, loops as lp


def E(a, b):
    return {"source": a, "target": b}


def test_find_rings():
    assert lp.find_rings([E("a", "b"), E("b", "c")]) == []          # ağaç
    r = lp.find_rings([E("a", "b"), E("b", "c"), E("c", "a")])
    assert len(r) == 1 and sorted(r[0]) == ["a", "b", "c"]
    assert len(lp.find_rings([E("a", "b"), E("a", "b")])) == 1       # paralel bağlantı
    sq = lp.find_rings([E("a", "b"), E("b", "c"), E("c", "d"), E("d", "a"), E("a", "c")])
    assert len(sq) == 2                                              # iki temel halka
    assert lp.find_rings([]) == [] and lp.find_rings([E("x", "x")]) == []


def test_mac_moves_and_pages(app, client):
    with app.app_context():
        c = eq._db()
        for v, (dev, port) in enumerate((("10.0.0.1", "Gi0/5"), ("10.0.0.2", "Gi0/7"), ("10.0.0.2", "Gi0/9"))):
            c.execute("INSERT INTO eq_macs (tenant_id,device_ip,mac,vlan,if_index,port) VALUES (1,?,'aa:bb:cc:00:00:01',?,1,?)", (dev, v, port))
        c.execute("INSERT INTO eq_macs (tenant_id,device_ip,mac,vlan,if_index,port) VALUES (1,'10.0.0.1','aa:bb:cc:00:00:02',10,1,'Gi0/1')")
        c.commit(); c.close()
        m = lp.mac_rows()
        assert len(m) == 1 and m[0]["count"] == 3 and m[0]["severity"] == "high"
        assert "10.0.0.1:Gi0/5" in lp.to_csv("macs", m) and lp.overview()["macs"] == 1
    login_as(client, "superadmin")
    assert client.get("/loops").status_code == 200 and client.get("/loops/data").get_json()["success"]
    for k in ("rings", "macs"):
        for f in ("csv", "json"):
            assert client.get(f"/loops/export/{k}.{f}").status_code == 200
    assert client.get("/loops/export/x.csv").status_code == 404
    login_as(client, "helpdesk")
    assert client.get("/loops").status_code in (302, 403)
