# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
import gzip
import os

from conftest import login_as
from emredius.services import backups as svc


def _cfg(tmp_path):
    return {"BACKUP_DIR": str(tmp_path / "bk"), "RADDB_DIR": str(tmp_path / "raddb"), "DB_NAME": "radius_staging",
            "MYSQL_DEFAULTS_FILE": "/nonexistent", "BACKUP_POLICY_CONF": str(tmp_path / "conf"),
            "BACKUP_TIMER_UNIT": str(tmp_path / "timer"), "SOURCE_BUNDLE_PATH": str(tmp_path / "bundle.tar.gz")}


def _touch(d, name, data=b"x", mtime=None):
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    with open(p, "wb") as f:
        f.write(data)
    if mtime:
        os.utime(p, (mtime, mtime))
    return p


def test_backup_path_rejects_traversal(tmp_path):
    d = str(tmp_path)
    _touch(d, "radius_backup_1.sql.gz")
    assert svc.backup_path(d, "radius_backup_1.sql.gz")
    for bad in ("../radius_backup_1.sql.gz", "x/radius_backup_1.sql.gz", "secret.sql.gz", "radius_backup_2.sql.gz"):
        assert svc.backup_path(d, bad) is None


def test_prune_keeps_per_type(tmp_path):
    d = str(tmp_path)
    for i in range(4):
        _touch(d, f"radius_backup_{i}.sql.gz", mtime=1000 + i)
        _touch(d, f"radius_backup_{i}.sql.gz.sha256", b"a" * 64)
        _touch(d, f"radius_full_system_{i}.tar.gz", mtime=1000 + i)
    _touch(d, "radius_full_system_9.tar.gz.sha256", b"")  # orphan left by a failed full backup
    assert svc.prune(d, 2) == 4
    assert sorted(os.listdir(d)) == ["radius_backup_2.sql.gz", "radius_backup_2.sql.gz.sha256", "radius_backup_3.sql.gz",
                                     "radius_backup_3.sql.gz.sha256", "radius_full_system_2.tar.gz",
                                     "radius_full_system_3.tar.gz"]


def test_timer_unit_text():
    assert "OnCalendar=*-*-* 00/6:00:00" in svc.timer_unit_text(6)
    assert "OnCalendar=*-*-* 00:00:00" in svc.timer_unit_text(24)
    assert "OnUnitActiveSec=48h" in svc.timer_unit_text(48) and "00/48" not in svc.timer_unit_text(48)
    assert "OnUnitActiveSec=5h" in svc.timer_unit_text(5)


def test_parse_policy_form():
    assert svc.parse_policy_form({"interval_hours": "custom", "custom_interval": "9999", "max_count": "0"}) == (720, 1)
    assert svc.parse_policy_form({"interval_hours": "x", "max_count": "y"}) == (12, 2)


def test_create_and_restore_sql(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    monkeypatch.setattr(svc, "dump_database", lambda c, out: out.write(b"CREATE TABLE t (a int);\n"))
    path = svc.create_backup(cfg, "sql")
    assert os.path.basename(path).startswith("radius_backup_") and os.path.isfile(path + ".sha256")
    with gzip.open(path) as f:
        assert f.read().startswith(b"CREATE TABLE")
    imported = []
    monkeypatch.setattr(svc, "_import_sql", lambda c, src: imported.append(src.read()))
    assert svc.restore_backup(cfg, os.path.basename(path)) == os.path.basename(path)
    assert imported == [b"CREATE TABLE t (a int);\n"]
    with open(path, "ab") as f:  # tampered archive
        f.write(b"junk")
    try:
        svc.restore_backup(cfg, os.path.basename(path))
        assert False, "tampered archive restored"
    except svc.ServiceError as e:
        assert "SHA256" in str(e)


def test_full_backup_and_dry_run_restore_refused(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    _touch(cfg["RADDB_DIR"], "clients.conf", b"client x {}")
    monkeypatch.setattr(svc, "dump_database", lambda c, out: out.write(b"-- dump\n"))
    path = svc.create_backup(cfg, "full")
    import tarfile
    with tarfile.open(path) as t:
        assert {"radius_database.sql", "raddb_config/clients.conf"} <= set(t.getnames())
    monkeypatch.setattr(svc, "is_dry_run", lambda: True)
    try:
        svc.restore_backup(cfg, os.path.basename(path))
        assert False, "full restore allowed in dry run"
    except svc.ServiceError as e:
        assert "SYSTEM_DRY_RUN" in str(e)


def test_apply_policy_dry_run_writes_no_files(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    saved = {}
    monkeypatch.setattr(svc, "set_setting", lambda k, v: saved.__setitem__(k, v))
    monkeypatch.setattr(svc, "is_dry_run", lambda: True)
    assert svc.apply_policy(cfg, 6, 3) is False
    assert saved == {"backup_interval_hours": "6", "backup_max_count": "3"}
    assert not os.path.exists(cfg["BACKUP_POLICY_CONF"]) and not os.path.exists(cfg["BACKUP_TIMER_UNIT"])


def test_source_bundle_excludes_venv(tmp_path):
    cfg = _cfg(tmp_path)
    proj = tmp_path / "proj"
    _touch(str(proj / "emredius"), "app.py")
    _touch(str(proj / "venv"), "big.bin")
    _touch(str(proj / ".git"), "HEAD")
    path = svc.create_source_bundle(cfg, str(proj))
    import tarfile
    with tarfile.open(path) as t:
        names = t.getnames()
    assert "emredius/emredius/app.py" in names and not any("venv" in n or ".git" in n for n in names)


def test_backups_page_superadmin_only(app, client, tmp_path, monkeypatch):
    app.config["BACKUP_DIR"] = str(tmp_path / "bk")
    _touch(app.config["BACKUP_DIR"], "radius_backup_<x>.sql.gz")  # not a valid name: ignored
    _touch(app.config["BACKUP_DIR"], "radius_backup_20261010_010101.sql.gz")
    monkeypatch.setattr(svc, "get_policy", lambda: (12, 2))
    login_as(client, "network_admin")
    assert client.get("/backups").status_code == 302
    login_as(client, "superadmin")
    body = client.get("/backups").get_data(as_text=True)
    assert "radius_backup_20261010_010101.sql.gz" in body and "&lt;x&gt;" not in body and "1 Arşiv" in body


def test_backup_actions_post_only(app, client, tmp_path):
    app.config["BACKUP_DIR"] = str(tmp_path / "bk")
    login_as(client, "superadmin")
    for url in ("/backup/create?type=sql", "/backup/restore/radius_backup_1.sql.gz", "/backup/delete/radius_backup_1.sql.gz",
                "/backup/create-source-bundle"):
        assert client.get(url).status_code == 405


def test_backup_delete(app, client, tmp_path, monkeypatch):
    app.config["BACKUP_DIR"] = d = str(tmp_path / "bk")
    _touch(d, "radius_backup_1.sql.gz")
    _touch(d, "radius_backup_1.sql.gz.sha256", b"a" * 64)
    tok = login_as(client, "superadmin")
    assert client.post("/backup/delete/radius_backup_1.sql.gz", data={"_csrf_token": tok}).status_code == 302
    assert os.listdir(d) == []
