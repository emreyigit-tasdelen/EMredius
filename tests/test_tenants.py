# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.core import tenant as tn
from emredius.services import alarms, boards, configs, equipment, flows, inventory as inv, ipam, topology, watch


def _dev(ip, tenant):
    c = inv._db()
    c.execute("INSERT INTO inv_devices (tenant_id,ip,sys_name,status) VALUES (?,?,?,'ONLINE')", (tenant, ip, "d" + ip[-1]))
    c.commit(); c.close()


def test_tenant_crud_and_delete_guards(app):
    with app.app_context():
        assert [t["id"] for t in tn.list_tenants()] == [1] and tn.all_tenant_ids() == [1]
        assert tn.add_tenant("") and tn.add_tenant("Varsayılan") == "Bu ad zaten kullanılıyor."
        assert tn.add_tenant("Müşteri A") == ""
        tid = [t for t in tn.list_tenants() if t["name"] == "Müşteri A"][0]["id"]
        assert tn.rename_tenant(tid, "Müşteri B") == "" and tn.rename_tenant(tid, "Varsayılan") and tn.rename_tenant(999, "x")
        assert tn.assign_admin("ali", tid) == "" and tn.admin_tenant("ali") == tid and tn.admin_tenant("veli") == 1
        assert tn.assign_admin("", tid) and tn.assign_admin("ali", 999)
        _dev("10.0.0.1", tid)
        assert "veri var" in tn.delete_tenant(tid) and "silinemez" in tn.delete_tenant(1) and tn.delete_tenant(999)
        c = inv._db(); c.execute("DELETE FROM inv_devices"); c.commit(); c.close()
        assert tn.delete_tenant(tid) == "" and tn.admin_tenant("ali") == 1 and tn.all_tenant_ids() == [1]
        assert tn.resolve_tenant(5) == 5 and tn.resolve_tenant(None) == 1 and tn.current_tenant_name() == "Varsayılan"


def test_data_isolation_across_modules(app):
    with app.app_context():
        tn.add_tenant("B")
        tb = [t["id"] for t in tn.list_tenants() if t["name"] == "B"][0]
        _dev("10.0.0.1", 1); _dev("10.0.0.2", tb)
        assert [d["ip"] for d in inv.list_devices()] == ["10.0.0.1"] and [d["ip"] for d in inv.list_devices(tenant_id=tb)] == ["10.0.0.2"]
        assert ipam.add_subnet("10.0.0.0/24", tenant_id=tb) == "" and ipam.list_subnets() == [] and len(ipam.list_subnets(tenant_id=tb)) == 1
        assert watch.add_target("1.1.1.1", tenant_id=tb) == "" and watch.list_targets() == []
        assert boards.create_board("x", tenant_id=tb)[0] and boards.list_boards() == []
        assert alarms.add_rule("r", "cpu", 90, tenant_id=tb) == "" and alarms.list_rules() == []
        assert configs.manual_backup("10.0.0.2", "hostname a", tenant_id=tb)[0] == 1 and configs.manual_backup("10.0.0.2", "hostname a")[0] is None
        c = equipment._db(); c.execute("INSERT INTO eq_ports (tenant_id,device_ip,if_index) VALUES (?,?,1)", (tb, "10.0.0.2")); c.commit(); c.close()
        assert equipment.list_ports() == [] and len(equipment.list_ports(tenant_id=tb)) == 1
        assert topology.list_links() == [] and flows.top("src") == []


def test_pages_switch_and_rbac(app, client):
    with app.app_context():
        tn.add_tenant("B")
    login_as(client, "superadmin")
    assert client.get("/tenants").status_code == 200
    r = client.post("/tenants/switch", data={"_csrf_token": "tok", "tenant_id": "1"})
    assert r.status_code in (200, 302, 400)
    assert client.post("/tenants/add", data={"_csrf_token": "tok", "name": "C"}).status_code in (200, 302, 400)
    assert client.get("/inventory").status_code == 200 and client.get("/api/v1/inventory/devices?tenant=999").status_code in (200, 401, 403)
    login_as(client, "network_admin")
    assert client.get("/tenants").status_code in (302, 403)


def test_topbar_label(app, client):
    login_as(client, "superadmin")
    assert "Çalışılan kiracı".encode() not in client.get("/tenants").data           # tek kiracıda gösterge yok
    with app.app_context():
        tn.add_tenant("Etiket Test")
    assert "Çalışılan kiracı".encode() in client.get("/tenants").data


def test_radius_tacacs_owner_mapping(app):
    from emredius.services import tacacs as tsvc
    with app.app_context():
        tn.add_tenant("B")
        tb = [t["id"] for t in tn.list_tenants() if t["name"] == "B"][0]
        rows = [{"username": "Ali"}, {"username": "veli"}]
        assert len(tn.filter_owned("radius_user", rows, lambda r: r["username"])) == 2  # eşlemesiz = varsayılan
        assert tn.set_owner("radius_user", "ali", tb) == "" and tn.set_owner("bad", "x", tb) and tn.set_owner("nas", "x", 999)
        assert [r["username"] for r in tn.filter_owned("radius_user", rows, lambda r: r["username"])] == ["veli"]
        assert [r["username"] for r in tn.filter_owned("radius_user", rows, lambda r: r["username"], tb)] == ["Ali"]
        assert tn.set_owner("radius_user", "ali", 1) == "" and len(tn.filter_owned("radius_user", rows, lambda r: r["username"])) == 2
        data, _ = tsvc.page_data()
        assert data["clients"] == []
