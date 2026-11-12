# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
import pytest

from conftest import login_as
from emredius.services import macs as svc
from emredius.services.radius_users import ServiceError


def test_macs_page_escapes(client, monkeypatch):
    monkeypatch.setattr(svc, "list_macs", lambda: (
        [{"mac": "aa:bb:cc:dd:ee:ff", "vlan_id": "50", "description": "<b>x</b>", "vendor": "HP", "created_at": None}],
        [{"username": "11:22:33:44:55:66');alert(1);//", "authdate": "now", "vendor": "?"}]))
    login_as(client, "network_admin")
    body = client.get("/macs").get_data(as_text=True)
    assert "<b>x</b>" not in body and "&lt;b&gt;x&lt;/b&gt;" in body
    assert "quickApproveMac('11" not in body and "data-mac=" in body
    assert "/mac/delete/aa%3Abb%3Acc%3Add%3Aee%3Aff" in body


def test_mac_rbac_and_post_only(client):
    login_as(client, "helpdesk")
    assert client.get("/macs").status_code == 302
    login_as(client, "superadmin")
    assert client.get("/mac/delete/aa:bb:cc:dd:ee:ff").status_code == 405


def test_add_mac_validation():
    with pytest.raises(ServiceError):
        svc.add_mac("zz", "d", "")
    with pytest.raises(ServiceError):
        svc.add_mac("aa:bb:cc:dd:ee:ff", "", "")
    with pytest.raises(ServiceError):
        svc.add_mac("aa:bb:cc:dd:ee:ff", "d", "5000")
