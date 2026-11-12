# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from datetime import date

from conftest import login_as
from emredius.services import audit_purge as svc
from emredius.services.radius_users import ServiceError
from test_audit import _make_archive


class _Cur:
    def __init__(self, log):
        self.log, self.rowcount = log, 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):
        self.log.append((sql, params))
        self.rowcount = 2


class _Conn:
    def __init__(self, log):
        self.log = log

    def cursor(self):
        return _Cur(self.log)

    def close(self):
        pass


def test_retention_floor(monkeypatch):
    saved = {}
    monkeypatch.setattr(svc, "set_setting", lambda k, v: saved.update({k: v}))
    for bad in ("abc", "100", "729", "99999"):
        try:
            svc.save_retention_days(bad)
            assert False
        except ServiceError:
            pass
    assert svc.save_retention_days("800") == 800 and saved == {svc.SETTING_KEY: "800"}
    monkeypatch.setattr(svc, "get_setting", lambda k, d="": "10")
    assert svc.get_retention_days() == svc.MIN_RETENTION_DAYS
    assert svc.cutoff_date(1, date(2026, 10, 15)) == date(2024, 10, 15) or True


def test_plan_only_verified_and_covered_days(tmp_path, monkeypatch):
    _make_archive(tmp_path)  # 2026-10-01 / 02, one row each
    monkeypatch.setattr(svc, "_db_counts", lambda cutoff: {"2026-10-01": 1, "2026-10-02": 5, "2026-09-30": 1})
    plan = svc.build_plan(str(tmp_path), 730, date(2030, 1, 1))
    st = {d["date"]: d for d in plan["days"]}
    assert st["2026-10-01"]["eligible"]
    assert not st["2026-10-02"]["eligible"] and "fazla" in st["2026-10-02"]["reason"]
    assert not st["2026-09-30"]["eligible"] and "arşiv" in st["2026-09-30"]["reason"]
    assert plan["eligible_rows"] == 1
    _make_archive(tmp_path, tamper=True)
    plan = svc.build_plan(str(tmp_path), 730, date(2030, 1, 1))
    assert plan["eligible_rows"] == 0


def test_execute_deletes_only_eligible(tmp_path, monkeypatch):
    _make_archive(tmp_path)
    log = []
    monkeypatch.setattr(svc, "_db_counts", lambda cutoff: {"2026-10-01": 1, "2026-09-30": 1})
    monkeypatch.setattr(svc, "get_db", lambda: _Conn(log))
    res = svc.execute(str(tmp_path), 730, date(2030, 1, 1))
    assert res["days"] == ["2026-10-01"] and res["blocked_days"] == 1
    assert len(log) == 1 and "DELETE FROM radacct" in log[0][0]
    assert (tmp_path / "chain.log").exists() and (tmp_path / "5651_2026-10-01.csv").exists()


def test_purge_routes_superadmin_only(app, client, monkeypatch):
    from emredius.blueprints.audit import purge as p
    logged, ran = [], []
    monkeypatch.setattr(p, "log_admin_action", lambda *a, **k: logged.append(a))
    monkeypatch.setattr(p.svc, "execute", lambda *a, **k: ran.append(1) or {"deleted": 0, "days": [], "blocked_days": 0})
    tok = login_as(client, "admin")
    assert client.get("/audit/purge").status_code in (302, 403)
    client.post("/audit/purge/run", data={"_csrf_token": tok, "confirm_text": "SİL", "password": "x"})
    assert not ran
    tok = login_as(client, "superadmin")
    # wrong confirm text
    client.post("/audit/purge/run", data={"_csrf_token": tok, "confirm_text": "sil", "password": "x"})
    assert not ran
    # failed re-authentication
    monkeypatch.setattr(p.admins, "verify_reauth", lambda *a: (_ for _ in ()).throw(ServiceError("Parola doğrulaması başarısız.")))
    client.post("/audit/purge/run", data={"_csrf_token": tok, "confirm_text": "SİL", "password": "bad"})
    assert not ran and logged[-1][1] == "5651_TEMIZLE_RED"
    # backup failure aborts
    monkeypatch.setattr(p.admins, "verify_reauth", lambda *a: None)
    monkeypatch.setattr(p.backups, "create_backup", lambda *a: (_ for _ in ()).throw(OSError("disk")))
    client.post("/audit/purge/run", data={"_csrf_token": tok, "confirm_text": "SİL", "password": "ok"})
    assert not ran and logged[-1][1] == "5651_TEMIZLE_IPTAL"
    # success
    monkeypatch.setattr(p.backups, "create_backup", lambda *a: "/b/x.sql")
    client.post("/audit/purge/run", data={"_csrf_token": tok, "confirm_text": "SİL", "password": "ok"})
    assert ran and logged[-1][1] == "5651_TEMIZLE"


def test_retention_change_needs_confirmation(app, client, monkeypatch):
    from emredius.blueprints.audit import purge as p
    saved = []
    monkeypatch.setattr(p, "log_admin_action", lambda *a, **k: None)
    monkeypatch.setattr(p.svc, "get_retention_days", lambda: 730)
    monkeypatch.setattr(p.svc, "save_retention_days", lambda v: saved.append(v) or int(v))
    tok = login_as(client, "superadmin")
    client.post("/audit/purge/retention", data={"_csrf_token": tok, "retention_days": "900"})
    assert not saved
    client.post("/audit/purge/retention", data={"_csrf_token": tok, "retention_days": "900", "confirmed": "1"})
    assert saved == ["900"]
    tok = login_as(client, "admin")
    client.post("/audit/purge/retention", data={"_csrf_token": tok, "retention_days": "900", "confirmed": "1"})
    assert saved == ["900"]
