# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
import json

from conftest import login_as
from emredius.services import ipscan, portscan


def _log(monkeypatch, module):
    logged = []
    monkeypatch.setattr(module, "log_admin_action", lambda *a, **k: logged.append(a))
    return logged


def test_ipscan_history_delete_superadmin_only(app, client, monkeypatch):
    import emredius.blueprints.ipscan.routes as r
    logged = _log(monkeypatch, r)
    path = app.config["IPSCAN_HISTORY_PATH"]
    rec = {"id": "abc123", "user": "tester", "network": "10.0.0.0/24", "status": "done", "total": 254,
           "done": 254, "started_at": 1, "elapsed": 1.0, "alive_count": 0, "alive": []}
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"scans": [rec]}, f)
    tok = login_as(client, "admin")
    client.post("/ip-scan/history/abc123/delete", headers={"X-CSRF-Token": tok})
    assert ipscan.list_history("tester", path)
    tok = login_as(client, "superadmin")
    assert client.post("/ip-scan/history/abc123/delete").status_code in (302, 400, 403)  # no CSRF token
    assert ipscan.list_history("tester", path)
    assert client.post("/ip-scan/history/abc123/delete", headers={"X-CSRF-Token": tok}).get_json()["success"]
    assert ipscan.list_history("tester", path) == []
    assert logged and logged[0][1] == "IP_SCAN_DELETE"
    assert client.post("/ip-scan/history/abc123/delete", headers={"X-CSRF-Token": tok}).status_code == 404


def test_portscan_history_kept_viewed_and_deleted(app, client, monkeypatch):
    import emredius.blueprints.portscan.routes as r
    logged = _log(monkeypatch, r)
    path = app.config["PORTSCAN_HISTORY_PATH"]
    for i in range(25):
        portscan._save_history(path, {"id": f"s{i}", "user": "u1", "target": "10.0.0.1", "label": "h", "range": "1-2",
                                      "status": "done", "total": 2, "done": 2, "open": [{"port": 22, "service": "ssh"}],
                                      "closed": 1, "filtered": 0, "timeout": 1, "elapsed": 1, "started": "x",
                                      "started_wall": i})
    recent = portscan.recent_jobs("u1", False, path)
    assert len(recent) == 20 and recent[0]["id"] == "s24"  # last 20 per administrator, newest first
    assert portscan.get_job("s24", "u1", history_path=path)["open"][0]["port"] == 22
    assert portscan.get_job("s24", "other", history_path=path) is None
    assert portscan.get_job("s24", "other", True, history_path=path)
    tok = login_as(client, "admin")
    client.post("/portscan/job/s24/delete", headers={"X-CSRF-Token": tok})
    assert portscan.get_job("s24", "u1", history_path=path)
    tok = login_as(client, "superadmin")
    assert client.post("/portscan/job/s24/delete", headers={"X-CSRF-Token": tok}).get_json()["success"]
    assert portscan.get_job("s24", "u1", history_path=path) is None
    assert len(logged) == 1 and logged[0][1] == "PORT_SCAN_DELETE"
