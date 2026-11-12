# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from conftest import login_as
from emredius.services import radtest as svc


def test_radtest_masks_password(client, monkeypatch):
    monkeypatch.setattr(svc, "run_cmd", lambda cmd, timeout: (
        0, 'Sent Access-Request\n\tUser-Password = "s3cret<b>"\nReceived Access-Accept', ""))
    tok = login_as(client, "superadmin")
    body = client.post("/test", data={"_csrf_token": tok, "username": "u<x>", "password": "s3cret<b>",
                                      "secret": "testing123"}).get_data(as_text=True)
    assert "s3cret" not in body and "Access-Accept" in body and "u&lt;x&gt;" in body


def test_radtest_validation():
    assert svc.validate("-x", "p", "s") and svc.validate("u", "", "s") and svc.validate("u", "p", "a\x01")
    assert svc.validate("u", "p", "s") is None


def test_radtest_get(client):
    login_as(client, "superadmin")
    assert "Doğrula (radtest)" in client.get("/test").get_data(as_text=True)
