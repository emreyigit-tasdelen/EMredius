# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import erasures as svc


def test_page_ok_without_db(client):
    login_as(client, "superadmin")
    assert client.get("/erasures").status_code == 200


def test_requires_login(client):
    assert client.get("/erasures").status_code in (302, 401)
    assert client.post("/erasures/run").status_code in (302, 400, 401, 403)


def test_pending_only_expired(monkeypatch):
    monkeypatch.setattr(svc, "list_batch_accounts", lambda: {"accounts": [
        {"code": "GUEST-1", "status": "expired"}, {"code": "GUEST-2", "status": "active"}, {"code": "U", "status": "online"}]})
    d = svc.pending()
    assert d["total"] == 1 and d["rows"][0]["code"] == "GUEST-1"
