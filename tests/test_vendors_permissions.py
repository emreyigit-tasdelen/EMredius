# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import vendors


def test_sixteen_families_and_resolve():
    assert len(vendors.FAMILIES) == 16 and len({f["key"] for f in vendors.FAMILIES}) == 16
    assert all(f["cmds"] and f["aliases"] for f in vendors.FAMILIES)
    assert vendors.resolve("Cisco Systems")["key"] == "cisco" and vendors.resolve("Juniper Networks, Inc.")["key"] == "juniper"
    assert vendors.resolve("MikroTik")["key"] == "mikrotik" and vendors.resolve("Huawei Technologies")["key"] == "huawei"
    assert vendors.resolve("Hewlett Packard Enterprise")["key"] == "aruba" and vendors.resolve("Palo Alto Networks")["key"] == "paloalto"
    assert vendors.resolve("") is None and vendors.resolve("Bilinmeyen") is None
    assert vendors.backup_commands("Cisco")[-1] == "show running-config" and vendors.backup_commands("xyz") == vendors.DEFAULT_CMDS
    assert vendors.same_family("Cisco Systems", "cisco") and not vendors.same_family("Cisco", "Juniper") and vendors.same_family("Foo", "foo")


def test_permissions_page_and_rbac(client):
    login_as(client, "superadmin")
    r = client.get("/permissions")
    assert r.status_code == 200 and b"Rol x men" in r.data
    assert client.get("/permissions/export.json").status_code == 200
    s = client.post("/permissions/save", data={"_csrf_token": "tok", "role_key": "superadmin"})
    assert s.status_code in (200, 302, 400)
    login_as(client, "network_admin")
    assert client.get("/permissions").status_code in (302, 403) and client.get("/permissions/export.json").status_code in (302, 403)
