# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import pytest

from conftest import login_as
from emredius.services import apn as svc
from emredius.services.radius_users import ServiceError


def test_page_and_rbac(client):
    assert client.get("/apn").status_code in (302, 401)
    login_as(client, "superadmin")
    assert client.get("/apn").status_code == 200


def test_crud_tenant_and_links(app):
    with app.test_request_context():
        svc.save("providers", {"name": "Turkcell"}, tenant_id=1)
        svc.save("locations", {"name": "Merkez"}, tenant_id=1)
        pid = svc.overview(1)["providers"][0]["id"]
        lid = svc.overview(1)["locations"][0]["id"]
        svc.save("lines", {"name": "L1", "provider_id": str(pid), "location_id": str(lid), "nas_ip": "10.0.0.1", "status": "active"}, tenant_id=1)
        line = svc.overview(1)["lines"][0]
        assert line["provider"] == "Turkcell" and line["location"] == "Merkez"
        assert svc.overview(2) == {"providers": [], "locations": [], "lines": []}
        with pytest.raises(ServiceError):
            svc.delete("providers", pid, tenant_id=1)  # hat bağlı
        with pytest.raises(ServiceError):
            svc.delete("providers", pid, tenant_id=2)  # başka kiracı
        with pytest.raises(ServiceError):
            svc.save("providers", {"name": "Turkcell"}, tenant_id=1)  # tekrar
        svc.save("lines", {"name": "L1b", "status": "retired"}, line["id"], tenant_id=1)
        svc.delete("lines", line["id"], tenant_id=1)
        svc.delete("providers", pid, tenant_id=1)


@pytest.mark.parametrize("form", [{"name": ""}, {"name": "x", "nas_ip": "bad"}, {"name": "x", "status": "zz"},
                                  {"name": "x", "provider_id": "999"}, {"name": "x" * 70}])
def test_validation(app, form):
    with app.test_request_context():
        with pytest.raises(ServiceError):
            svc.save("lines", form, tenant_id=1)
