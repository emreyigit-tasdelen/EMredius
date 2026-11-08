# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import pytest

from conftest import login_as
from emredius.services import approvals as svc
from emredius.services import vouchers
from emredius.services.radius_users import ServiceError


def test_page_and_rbac(client):
    assert client.get("/approvals").status_code in (302, 401)
    login_as(client, "superadmin")
    assert client.get("/approvals").status_code == 200
    assert client.get("/approvals?status=pending").status_code == 200


def test_flow_approve_reject_tenant(app, monkeypatch):
    calls = []
    monkeypatch.setattr(vouchers, "generate_vouchers", lambda p: calls.append(p) or {"codes": ["GUEST-AAAAA"]})
    monkeypatch.setattr(svc, "credentials", lambda code: "123456")
    with app.test_request_context():
        svc.add_request("Ali", "a@x", "Veli", "toplantı", "4h", tenant_id=1)
        svc.add_request("Ayşe", tenant_id=1)
        a, b = [r["id"] for r in sorted(svc.list_requests(1), key=lambda r: r["id"])]
        assert svc.list_requests(2) == []
        with pytest.raises(ServiceError):
            svc.approve(a, "u", tenant_id=2)  # başka kiracı
        assert svc.approve(a, "u", tenant_id=1) == ("GUEST-AAAAA", "123456")
        assert calls[0]["duration"] == "4h" and calls[0]["count"] == 1
        with pytest.raises(ServiceError):
            svc.approve(a, "u", tenant_id=1)  # tekrar onay yok
        with pytest.raises(ServiceError):
            svc.delete_request(b, tenant_id=1)  # bekleyen silinemez
        svc.reject(b, "u", tenant_id=1)
        svc.delete_request(b, tenant_id=1)
        assert [r["status"] for r in svc.list_requests(1)] == ["approved"]


@pytest.mark.parametrize("args", [("",), ("x", "", "", "", "9y"), ("x" * 81,)])
def test_validation(app, args):
    with app.test_request_context():
        with pytest.raises(ServiceError):
            svc.add_request(*args, tenant_id=1)
