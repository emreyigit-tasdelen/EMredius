# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from conftest import login_as
from emredius.services import boards as bd


def test_board_crud_and_render(app):
    with app.app_context():
        assert bd.create_board("")[0] is None
        bid, err = bd.create_board("Ana pano", "emre")
        assert bid and not err
        b = bd.get_board(bid)
        assert b["widgets"] == ["inventory", "alarms", "health", "watch"]
        assert bd.set_widgets(bid, ["loops", "zzz", "loops", "flows_src", "equipment", "flows_app", "alarm_list", "health_list"])
        b = bd.get_board(bid)
        assert b["widgets"] == ["loops", "flows_src", "equipment", "flows_app", "alarm_list", "health_list"]
        ws = bd.render(b)
        assert [w["key"] for w in ws] == b["widgets"] and all(w["kind"] in ("stats", "list") for w in ws)
        full = bd.get_board(bid)
        full["widgets"] = list(bd.CATALOG)
        assert len(bd.render(full)) == len(bd.CATALOG)           # tüm bileşenler boş veride de çalışır
        assert bd.get_board(bid, tenant_id=2) is None and not bd.delete_board(bid, tenant_id=2)
        assert not bd.set_widgets(bid, [], tenant_id=2) and bd.rename_board(bid, "Yeni") and not bd.rename_board(bid, " ")
        assert bd.list_boards()[0]["name"] == "Yeni"
        assert bd.delete_board(bid) and bd.list_boards() == []


def test_pages_rbac(app, client):
    with app.app_context():
        bid, _ = bd.create_board("P")
    login_as(client, "superadmin")
    assert client.get("/boards").status_code == 200 and client.get(f"/boards?id={bid}").status_code == 200
    j = client.get(f"/boards/{bid}/data").get_json()
    assert j["success"] and len(j["widgets"]) == 4
    assert client.get("/boards/9999/data").status_code == 404
    assert client.get(f"/boards/{bid}/export.json").status_code == 200
    assert client.get("/boards/9999/export.json").status_code == 404
    login_as(client, "helpdesk")
    assert client.get("/boards").status_code in (302, 403)
