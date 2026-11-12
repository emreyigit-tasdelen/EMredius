# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Runtime configuration. Values come from the environment, which is pre-filled from
/etc/emredius/emredius.env (KEY=VALUE lines; variables already set are not overridden)."""
import os
import re
import secrets
import logging
from datetime import timedelta

log = logging.getLogger(__name__)


def load_env_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass


load_env_file(os.environ.get("EMREDIUS_ENV_FILE", "/etc/emredius/emredius.env"))


def env(key, default=""):
    return (os.environ.get(key) or default).strip()


def env_bool(key, default=False):
    v = os.environ.get(key)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _load_or_create_secret_key(path):
    """SECRET_KEY from env, else from the key file; created (0600) with a random value on first start."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    try:
        with open(path, "r", encoding="utf-8") as f:
            val = f.read().strip()
            if len(val) >= 32:
                return val
    except OSError:
        pass
    val = secrets.token_hex(32)
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(val + "\n")
    except OSError as e:
        log.warning("could not persist SECRET_KEY (%s); sessions reset on restart", e)
    return val


def _db_password():
    """DB password from env DB_PASSWORD, else read from FreeRADIUS' own SQL module config (single source of truth)."""
    if os.environ.get("DB_PASSWORD"):
        return os.environ["DB_PASSWORD"]
    try:
        with open(env("RADDB_SQL_CONF", "/etc/raddb/mods-enabled/sql"), "r", encoding="utf-8") as f:
            for line in f:
                m = re.match(r'^\s*password\s*=\s*"(.*)"\s*$', line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return ""


_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_PKG_DIR)


class Config:
    """Flask config (upper-case attributes are loaded with app.config.from_object)."""

    SECRET_KEY_FILE = env("SECRET_KEY_FILE", "/etc/emredius/secret_key")
    SESSION_COOKIE_NAME = env("SESSION_COOKIE_NAME", "session")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", True)
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    # Background polling must not keep an idle session alive; /api/session/heartbeat extends it explicitly.
    SESSION_REFRESH_EACH_REQUEST = False
    MAX_CONTENT_LENGTH = 20 * 1024 * 1024
    SEND_FILE_MAX_AGE_DEFAULT = 86400  # static files are cache-busted with ?v=<asset_version>
    JSON_AS_ASCII = False

    DB_HOST = env("DB_HOST", "127.0.0.1")
    DB_PORT = int(env("DB_PORT", "3306"))
    DB_USER = env("DB_USER", "radius")
    DB_NAME = env("DB_NAME", "radius")
    DB_POOL_SIZE = int(env("DB_POOL_SIZE", "8"))

    # MySQL client defaults file for mysqldump / mysql (contains NO password; unix-socket auth as root).
    MYSQL_DEFAULTS_FILE = env("MYSQL_DEFAULTS_FILE", "/etc/emredius/my.cnf")

    NMS_DB_PATH = env("NMS_DB_PATH", os.path.join(_PROJECT_DIR, "nms", "data", "enterprise_nms.db"))
    # last 20 IP scans per administrator (JSON); next to the NMS DB so staging and live never share it
    IPSCAN_HISTORY_PATH = env("IPSCAN_HISTORY_PATH",
                              os.path.join(os.path.dirname(NMS_DB_PATH), "ipscan_history.json"))
    # last 20 port scans per administrator (JSON); same rule as the IP scan history
    PORTSCAN_HISTORY_PATH = env("PORTSCAN_HISTORY_PATH",
                                os.path.join(os.path.dirname(NMS_DB_PATH), "portscan_history.json"))
    NMS_SETTINGS_SYNC_ON_START = env_bool("NMS_SETTINGS_SYNC_ON_START", True)
    START_BACKGROUND_JOBS = env_bool("START_BACKGROUND_JOBS", True)
    # Staging on the production host: refuse host-changing commands (see core.system.run_cmd)
    SYSTEM_DRY_RUN = env_bool("SYSTEM_DRY_RUN", False)

    # 5651 daily signed archive (written by scripts/maintenance.py)
    ARCHIVE_5651_DIR = env("ARCHIVE_5651_DIR", "/var/lib/emredius/5651")

    # Backups (staging MUST set its own BACKUP_DIR; policy files are not written in SYSTEM_DRY_RUN)
    BACKUP_DIR = env("BACKUP_DIR", "/var/backups/radius")
    RADDB_DIR = env("RADDB_DIR", "/etc/raddb")
    BACKUP_POLICY_CONF = env("BACKUP_POLICY_CONF", "/etc/radius-backup.conf")
    BACKUP_TIMER_UNIT = env("BACKUP_TIMER_UNIT", "/etc/systemd/system/radius-backup.timer")
    RESOLV_CONF = env("RESOLV_CONF", "/etc/resolv.conf")
    SOURCE_BUNDLE_PATH = env("SOURCE_BUNDLE_PATH",
                             os.path.join(_PROJECT_DIR, "freeradius_enterprise_complete_bundle.tar.gz"))

    # Root CA offered at /download/ca.crt (browser trust for the panel's HTTPS certificate)
    CA_CERT_PATH = env("CA_CERT_PATH", os.path.join(_PKG_DIR, "static", "radius-root-ca.crt"))

    # systemd unit of this panel (services page restart button)
    PANEL_UNIT = env("PANEL_UNIT", "emredius-panel.service")

    LOG_LEVEL = env("LOG_LEVEL", "INFO")
    ASSET_VERSION = env("ASSET_VERSION", "20261018b")


def build_config(overrides=None):
    cfg = {k: getattr(Config, k) for k in dir(Config) if k.isupper()}
    if overrides:
        cfg.update(overrides)
    if not cfg.get("SECRET_KEY"):
        cfg["SECRET_KEY"] = _load_or_create_secret_key(cfg["SECRET_KEY_FILE"])
    if "DB_PASSWORD" not in cfg:
        cfg["DB_PASSWORD"] = _db_password()
    return cfg
