# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import pytest

from conftest import login_as
from emredius.services import groups as svc
from emredius.services.radius_users import ServiceError


def test_groups_page(client, monkeypatch):
    monkeypatch.setattr(svc, "list_groups", lambda: [
        {"groupname": "a'b", "vlan_id": "30", "rate_limit": None, "member_count": 2}])
    login_as(client, "superadmin")
    body = client.get("/profiles").get_data(as_text=True)
    assert "/group/delete/a%27b" in body and "a\\u0027b grubunu silmek" in body
    assert "2 kullanıcının grup üyeliği" in body and "VLAN 30" in body


def test_group_validation():
    assert svc.validate_group(" Staff ", "030", "") == ("Staff", "30", "")
    for args in (("bad name", "", ""), ("ok", "4095", ""), ("ok", "", "fast!")):
        with pytest.raises(ServiceError):
            svc.validate_group(*args)


def test_group_delete_not_found(client, monkeypatch):
    monkeypatch.setattr(svc, "delete_group", lambda g: (0, 0))
    tok = login_as(client, "superadmin")
    r = client.post("/group/delete/x", data={"_csrf_token": tok})
    assert r.status_code == 302 and r.headers["Location"].endswith("/groups")
