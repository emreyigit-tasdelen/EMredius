# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
import pytest

from conftest import login_as
from emredius.services import ippools as svc
from emredius.services.radius_users import ServiceError


def test_page_and_api_route(client):
    login_as(client, "superadmin")
    assert client.get("/ippools").status_code == 200


def test_requires_login(client):
    assert client.get("/ippools").status_code in (302, 401)


def test_parse_range_cidr_and_bounds():
    a, b = svc.parse_range("", "", "10.1.0.0/24")
    assert (str(a), str(b)) == ("10.1.0.1", "10.1.0.254")
    a, b = svc.parse_range("10.0.0.5", "10.0.0.9")
    assert int(b) - int(a) == 4
    for bad in (("10.0.0.9", "10.0.0.5", ""), ("x", "y", ""), ("", "", "10.0.0.0/8"), ("", "", "::1/128")):
        with pytest.raises(ServiceError):
            svc.parse_range(*bad)


def test_add_pool_rejects_bad_name(app):
    with app.test_request_context():
        with pytest.raises(ServiceError):
            svc.add_pool("bad name!", "10.0.0.1", "10.0.0.5")


def test_assign_rejects_bad_kind(app):
    with app.test_request_context():
        with pytest.raises(ServiceError):
            svc.assign("x", "bogus", "u")
