# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Backups: SQL dump / full system image (DB + raddb), SHA256 sidecars, per-type rotation, restore,
automatic backup policy (systemd timer) and the single-file source bundle.

All paths come from the config mapping `cfg` (BACKUP_DIR, RADDB_DIR, ...), so staging works on its own directory.
Archives are written with Python's gzip/tarfile (the server has no `tar` binary). The DB password is never on a
command line: mysqldump/mysql read `--defaults-extra-file=MYSQL_DEFAULTS_FILE`."""
import gzip
import hashlib
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime

from ..core import format_bytes, get_setting, is_dry_run, run_cmd, set_setting
from .radius_users import ServiceError

log = logging.getLogger(__name__)

SQL_PREFIX, FULL_PREFIX = "radius_backup_", "radius_full_system_"
BACKUP_NAME_RE = re.compile(r"^radius_(backup|full_system)_[A-Za-z0-9_.-]+\.(sql|tar)\.gz$")
INTERVAL_CHOICES = [
    (1, "Her 1 Saatte Bir (Günde 24 Defa)"),
    (2, "Her 2 Saatte Bir (Günde 12 Defa)"),
    (4, "Her 4 Saatte Bir (Günde 6 Defa)"),
    (6, "Her 6 Saatte Bir (Günde 4 Defa)"),
    (8, "Her 8 Saatte Bir (Günde 3 Defa)"),
    (12, "Her 12 Saatte Bir (Günde 2 Defa - Varsayılan)"),
    (24, "Her 24 Saatte Bir (Günde 1 Defa - Gece 00:00)"),
    (48, "Her 48 Saatte Bir (2 Günde Bir)"),
    (72, "Her 72 Saatte Bir (3 Günde Bir)"),
    (168, "Her 168 Saatte Bir (Haftada Bir)"),
]
MAX_INTERVAL_HOURS, MAX_KEEP = 720, 50
_DUMP_TIMEOUT = 600
_BUNDLE_EXCLUDE_DIRS = {".git", "venv", ".venv", "__pycache__", ".pytest_cache", "legacy"}
_BUNDLE_SYSTEM_FILES = [
    ("/etc/systemd/system/emredius-panel.service", "emredius-panel.service"),
    ("/etc/systemd/system/emredius-nms.service", "emredius-nms.service"),
]


def _is_full(name):
    return name.startswith(FULL_PREFIX)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _read_sha(path):
    try:
        with open(path + ".sha256", "r", encoding="utf-8") as f:
            parts = f.read().split()
        return parts[0].lower() if parts and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]) else ""
    except OSError:
        return ""


# ---------- policy ----------

def get_policy():
    """(interval_hours, max_count) from settings; defaults 12 / 2."""
    def _int(key, default, hi):
        v = str(get_setting(key, str(default)) or "").strip()
        return max(1, min(hi, int(v))) if v.isdigit() else default
    try:
        return _int("backup_interval_hours", 12, MAX_INTERVAL_HOURS), _int("backup_max_count", 2, MAX_KEEP)
    except Exception:
        return 12, 2


def parse_policy_form(form):
    sel = (form.get("interval_hours") or "12").strip()
    raw = (form.get("custom_interval") or "12").strip() if sel == "custom" else sel
    try:
        interval = max(1, min(MAX_INTERVAL_HOURS, int(raw)))
    except ValueError:
        interval = 12
    try:
        max_count = max(1, min(MAX_KEEP, int((form.get("max_count") or "2").strip())))
    except ValueError:
        max_count = 2
    return interval, max_count


def timer_unit_text(interval_hours):
    """systemd timer for the given interval. Divisors of 24 run at fixed wall-clock hours; longer or uneven
    intervals use a monotonic timer (`00/48` is not a valid OnCalendar hour)."""
    if interval_hours == 24:
        schedule = "OnCalendar=*-*-* 00:00:00\nPersistent=true"
    elif interval_hours < 24 and 24 % interval_hours == 0:
        schedule = f"OnCalendar=*-*-* 00/{interval_hours}:00:00\nPersistent=true"
    else:
        schedule = f"OnBootSec=15min\nOnUnitActiveSec={interval_hours}h"
    return (
        "[Unit]\n"
        f"Description=FreeRADIUS Enterprise Automated Backup Timer ({interval_hours} Hours)\n"
        "After=mariadb.service radiusd.service\n\n"
        "[Timer]\n"
        f"{schedule}\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )


def apply_policy(cfg, interval_hours, max_count):
    """Stores the policy, rewrites the backup conf + timer and reloads systemd, then rotates.
    Returns False when SYSTEM_DRY_RUN skipped the host changes (settings and rotation still applied)."""
    set_setting("backup_interval_hours", str(interval_hours))
    set_setting("backup_max_count", str(max_count))
    host_changed = not is_dry_run()
    if host_changed:
        try:
            with open(cfg["BACKUP_POLICY_CONF"], "w", encoding="utf-8") as f:
                f.write(f"# FreeRADIUS Enterprise Backup Policy\nINTERVAL_HOURS={interval_hours}\nMAX_COUNT={max_count}\n")
            with open(cfg["BACKUP_TIMER_UNIT"], "w", encoding="utf-8") as f:
                f.write(timer_unit_text(interval_hours))
        except OSError as e:
            raise ServiceError(f"Zamanlayıcı dosyaları yazılamadı: {e}")
        run_cmd(["systemctl", "daemon-reload"])
        rc, _, err = run_cmd(["systemctl", "restart", "radius-backup.timer"])
        if rc != 0:
            log.warning("radius-backup.timer restart failed: %s", err)
    else:
        log.warning("SYSTEM_DRY_RUN: backup policy files / timer not changed")
    prune(cfg["BACKUP_DIR"], max_count)
    return host_changed


def next_run_text(interval_hours):
    text = f"Her {interval_hours} Saatte Bir"
    rc, out, _ = run_cmd(["systemctl", "list-timers", "radius-backup.timer", "--no-legend"])
    if rc == 0 and out.strip():
        p = out.strip().split()
        if len(p) >= 6:
            text = f"{p[0]} {p[1]} {p[2]} ({p[3]} {p[4]} kaldı)"
    return text


# ---------- listing / rotation ----------

def list_backups(backup_dir):
    out = []
    try:
        names = os.listdir(backup_dir)
    except OSError:
        return out
    for name in names:
        if not BACKUP_NAME_RE.match(name):
            continue
        path = os.path.join(backup_dir, name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        sha = _read_sha(path)
        out.append({
            "filename": name,
            "is_full": _is_full(name),
            "size": format_bytes(st.st_size),
            "empty": st.st_size == 0,
            "checksum": (sha[:16] + "...") if sha else "",
            "mtime": st.st_mtime,
            "created_at": datetime.fromtimestamp(st.st_mtime).strftime("%d.%m.%Y %H:%M:%S"),
        })
    out.sort(key=lambda b: b["mtime"], reverse=True)
    return out


def _remove_with_sidecar(path):
    for p in (path, path + ".sha256"):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass


def prune(backup_dir, max_count):
    """Keeps the newest `max_count` archives PER TYPE (sql / full); removes older ones and their .sha256.
    Orphan .sha256 files (left behind by failed full backups) are removed too."""
    removed = 0
    backups = list_backups(backup_dir)
    for full in (False, True):
        for b in [x for x in backups if x["is_full"] == full][max_count:]:
            _remove_with_sidecar(os.path.join(backup_dir, b["filename"]))
            removed += 1
    try:
        for name in os.listdir(backup_dir):
            if name.endswith(".sha256") and BACKUP_NAME_RE.match(name[:-7]) \
                    and not os.path.exists(os.path.join(backup_dir, name[:-7])):
                os.remove(os.path.join(backup_dir, name))
    except OSError:
        pass
    return removed


def backup_path(backup_dir, filename):
    """Absolute path of an existing archive in backup_dir, or None (no traversal, only our own file names)."""
    name = os.path.basename(filename or "")
    if name != filename or not BACKUP_NAME_RE.match(name):
        return None
    path = os.path.join(backup_dir, name)
    return path if os.path.isfile(path) else None


def delete_backup(backup_dir, filename):
    path = backup_path(backup_dir, filename)
    if not path:
        raise ServiceError("Yedek dosyası bulunamadı!")
    _remove_with_sidecar(path)
    return os.path.basename(path)


# ---------- create ----------

def _mysql_args(cfg, prog):
    return [prog, f"--defaults-extra-file={cfg['MYSQL_DEFAULTS_FILE']}"]


def dump_database(cfg, out):
    """Streams `mysqldump` of DB_NAME into the binary file object `out`."""
    cmd = _mysql_args(cfg, "mysqldump") + ["--single-transaction", "--routines", "--triggers", "--events",
                                            cfg["DB_NAME"]]
    with tempfile.TemporaryFile() as errf:
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errf, stdin=subprocess.DEVNULL)
        except OSError as e:
            raise ServiceError(f"mysqldump çalıştırılamadı: {e}")
        try:
            shutil.copyfileobj(p.stdout, out, 1024 * 1024)
            p.stdout.close()
            rc = p.wait(timeout=_DUMP_TIMEOUT)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            raise ServiceError("mysqldump zaman aşımına uğradı.")
        if rc != 0:
            errf.seek(0)
            raise ServiceError("mysqldump hatası: " + errf.read().decode("utf-8", "replace").strip()[:300])


def _finalize(tmp_path, final_path):
    if os.path.getsize(tmp_path) == 0:
        os.remove(tmp_path)
        raise ServiceError("Yedek dosyası boş oluştu.")
    os.replace(tmp_path, final_path)
    digest = sha256_file(final_path)
    with open(final_path + ".sha256", "w", encoding="utf-8") as f:
        f.write(digest + "\n")
    return final_path


def create_backup(cfg, kind):
    """kind 'sql' -> radius_backup_<ts>.sql.gz; 'full' -> radius_full_system_<ts>.tar.gz
    (radius_database.sql + raddb_config/). Returns the archive path."""
    backup_dir = cfg["BACKUP_DIR"]
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if kind == "full":
        final = os.path.join(backup_dir, f"{FULL_PREFIX}{ts}.tar.gz")
    else:
        final = os.path.join(backup_dir, f"{SQL_PREFIX}{ts}.sql.gz")
    tmp = final + ".part"
    old_umask = os.umask(0o077)
    try:
        if kind == "full":
            with tempfile.TemporaryDirectory(prefix="emredius_backup_") as work:
                sql_path = os.path.join(work, "radius_database.sql")
                with open(sql_path, "wb") as f:
                    dump_database(cfg, f)
                with tarfile.open(tmp, "w:gz") as tar:
                    tar.add(sql_path, arcname="radius_database.sql")
                    if os.path.isdir(cfg["RADDB_DIR"]):
                        tar.add(cfg["RADDB_DIR"], arcname="raddb_config")
        else:
            with gzip.open(tmp, "wb") as gz:
                dump_database(cfg, gz)
        return _finalize(tmp, final)
    except ServiceError:
        _remove_with_sidecar(tmp)
        raise
    except (OSError, tarfile.TarError) as e:
        _remove_with_sidecar(tmp)
        raise ServiceError(f"Yedek yazılamadı: {e}")
    finally:
        os.umask(old_umask)


# ---------- restore ----------

def _verify(path):
    sha = _read_sha(path)
    if sha and sha != sha256_file(path):
        raise ServiceError("SHA256 doğrulaması başarısız: yedek dosyası bozulmuş veya değiştirilmiş.")


def _import_sql(cfg, src):
    """Pipes the binary file object `src` into `mysql DB_NAME`."""
    cmd = _mysql_args(cfg, "mysql") + [cfg["DB_NAME"]]
    with tempfile.TemporaryFile() as errf:
        try:
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=errf)
        except OSError as e:
            raise ServiceError(f"mysql çalıştırılamadı: {e}")
        try:
            shutil.copyfileobj(src, p.stdin, 1024 * 1024)
        except BrokenPipeError:
            pass
        finally:
            p.stdin.close()
        try:
            rc = p.wait(timeout=_DUMP_TIMEOUT)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            raise ServiceError("Veritabanı geri yükleme zaman aşımına uğradı.")
        if rc != 0:
            errf.seek(0)
            raise ServiceError("mysql hatası: " + errf.read().decode("utf-8", "replace").strip()[:300])


def restore_backup(cfg, filename):
    """Restores an archive into DB_NAME (and, for a full image, raddb_config/ into RADDB_DIR + radiusd restart).
    A full restore changes host configuration and is refused in SYSTEM_DRY_RUN."""
    path = backup_path(cfg["BACKUP_DIR"], filename)
    if not path:
        raise ServiceError("Yedek dosyası bulunamadı!")
    name = os.path.basename(path)
    if _is_full(name) and is_dry_run():
        raise ServiceError("[staging] Tam sistem geri yüklemesi SYSTEM_DRY_RUN modunda engellendi.")
    _verify(path)
    if not _is_full(name):
        with gzip.open(path, "rb") as src:
            _import_sql(cfg, src)
        return name
    with tempfile.TemporaryDirectory(prefix="emredius_restore_") as work:
        try:
            with tarfile.open(path, "r:gz") as tar:
                tar.extractall(work, filter="data")
        except (OSError, tarfile.TarError) as e:
            raise ServiceError(f"Arşiv açılamadı: {e}")
        sql_path = os.path.join(work, "radius_database.sql")
        if os.path.isfile(sql_path):
            with open(sql_path, "rb") as src:
                _import_sql(cfg, src)
        raddb = os.path.join(work, "raddb_config")
        if os.path.isdir(raddb):
            shutil.copytree(raddb, cfg["RADDB_DIR"], dirs_exist_ok=True)
            run_cmd(["systemctl", "restart", "radiusd"], timeout=30)
    return name


# ---------- single-file source bundle ----------

def create_source_bundle(cfg, project_dir):
    """project code (without venv/.git/legacy) + NMS data + /etc/raddb + systemd units -> SOURCE_BUNDLE_PATH."""
    bundle = cfg["SOURCE_BUNDLE_PATH"]
    tmp = bundle + ".part"

    def _filter(ti):
        parts = ti.name.split("/")
        if any(p in _BUNDLE_EXCLUDE_DIRS for p in parts) or ti.name.endswith((".pyc", ".part")) \
                or os.path.basename(ti.name) == os.path.basename(bundle):
            return None
        return ti
    old_umask = os.umask(0o077)
    try:
        with tarfile.open(tmp, "w:gz") as tar:
            tar.add(project_dir, arcname="emredius", filter=_filter)
            if os.path.isdir(cfg["RADDB_DIR"]):
                tar.add(cfg["RADDB_DIR"], arcname="etc_raddb")
            for src, arc in _BUNDLE_SYSTEM_FILES:
                if os.path.isfile(src):
                    tar.add(src, arcname=arc)
        os.replace(tmp, bundle)
    except (OSError, tarfile.TarError) as e:
        _remove_with_sidecar(tmp)
        raise ServiceError(f"Arşiv oluşturma hatası: {e}")
    finally:
        os.umask(old_umask)
    return bundle
