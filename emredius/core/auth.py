# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Administrator authentication: web accounts (werkzeug hash) and Linux system accounts (/etc/shadow),
per-IP brute-force lock, role labels."""
import hmac
import html
import logging
import threading
import time
import warnings
from datetime import datetime, timedelta

from werkzeug.security import check_password_hash

from .audit import log_admin_action
from .db import get_db
from .notify import send_alert
from .settings import get_setting

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    try:
        import spwd
    except ImportError:
        spwd = None
    try:
        import crypt
    except ImportError:
        crypt = None
try:
    import pwd
    import grp
except ImportError:  # non-Linux development machines
    pwd = None
    grp = None

log = logging.getLogger(__name__)

ROLE_LABELS = {
    "superadmin": "Süper Yönetici",
    "network_admin": "Ağ Yöneticisi",
    "helpdesk": "Kupon Operatörü",
    "auditor": "Denetçi (Salt Okunur)",
}


# ==================== PER-IP BRUTE-FORCE LOCK ====================

LOGIN_ATTEMPTS = {}
_login_attempts_lock = threading.Lock()
LOCK_THRESHOLD = 5
LOCK_SECONDS = 900


def lock_policy():
    """(deneme sınırı, kilit süresi sn): ayarlardan (Sertleştirme menüsü), sınırlara kırpılı; ayar yoksa 5 / 15 dk."""
    def _int(key, default, lo, hi):
        try:
            return min(hi, max(lo, int(get_setting(key, str(default)))))
        except (TypeError, ValueError):
            return default
    return _int("login_lock_threshold", LOCK_THRESHOLD, 3, 20), _int("login_lock_minutes", LOCK_SECONDS // 60, 1, 1440) * 60

def is_ip_locked(ip):
    with _login_attempts_lock:
        rec = LOGIN_ATTEMPTS.get(ip)
        if not rec or not rec.get("locked_until"):
            return False
        if time.time() < rec["locked_until"]:
            return True
        LOGIN_ATTEMPTS.pop(ip, None)
        return False


def record_failed_login(ip):
    alert = False
    threshold, lock_secs = lock_policy()
    with _login_attempts_lock:
        now = time.time()
        # drop stale records so the dict cannot grow without bound
        if len(LOGIN_ATTEMPTS) > 5000:
            for k in [k for k, v in LOGIN_ATTEMPTS.items() if now - v.get("last", 0) > 3600]:
                LOGIN_ATTEMPTS.pop(k, None)
        rec = LOGIN_ATTEMPTS.setdefault(ip, {"count": 0, "locked_until": None, "last": now})
        rec["count"] += 1
        rec["last"] = now
        if rec["count"] >= threshold and not rec.get("locked_until"):
            rec["locked_until"] = now + lock_secs
            alert = True
    if alert:
        send_alert(f"⚠️ [GÜVENLİK ALARMI] {ip} adresinden {threshold} kez hatalı yönetici girişi denendi. "
                   f"IP {lock_secs // 60} dakika engellendi!")


def record_successful_login(ip):
    with _login_attempts_lock:
        LOGIN_ATTEMPTS.pop(ip, None)


# ==================== LINUX (/etc/shadow) PASSWORD VERIFICATION ====================
# spwd/crypt are removed in Python 3.13 -> fall back to reading /etc/shadow + libcrypt via ctypes.

_libcrypt = None
_crypt_lock = threading.Lock()


def _shadow_hash(username):
    if spwd is not None:
        try:
            return spwd.getspnam(username).sp_pwdp
        except KeyError:
            return None
        except Exception as e:
            log.warning("shadow lookup failed for %r: %s", username, e)
    try:
        with open("/etc/shadow", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split(":")
                if parts and parts[0] == username:
                    return parts[1] if len(parts) > 1 else None
    except OSError:
        return None
    return None


def _crypt_hash(password, salt):
    if crypt is not None:
        return crypt.crypt(password, salt)
    import ctypes
    import ctypes.util
    global _libcrypt
    with _crypt_lock:
        if _libcrypt is None:
            _libcrypt = ctypes.CDLL(ctypes.util.find_library("crypt") or "libcrypt.so.1")
            _libcrypt.crypt.restype = ctypes.c_char_p
            _libcrypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        res = _libcrypt.crypt(password.encode("utf-8"), salt.encode("utf-8"))
        return res.decode("utf-8") if res else None


def verify_system_password(username, password):
    stored = _shadow_hash(username)
    if not stored or stored.startswith(("!", "*")):
        return False
    try:
        computed = _crypt_hash(password, stored) or ""
    except Exception as e:
        log.error("System auth error: %s", e)
        return False
    return hmac.compare_digest(computed, stored)


def _is_wheel_member(username):
    if grp is None or pwd is None:
        return False
    try:
        wheel = grp.getgrnam("wheel")
        return username in wheel.gr_mem or pwd.getpwnam(username).pw_gid == wheel.gr_gid
    except Exception:
        return False


def get_system_linux_users():
    if pwd is None:
        return ["root"]
    try:
        users = set()
        for u in pwd.getpwall():
            if u.pw_uid == 0 or (1000 <= u.pw_uid < 60000):
                shell = u.pw_shell.lower()
                if "nologin" not in shell and "false" not in shell:
                    users.add(u.pw_name)
        return sorted(users)
    except Exception:
        return ["root", "admin"]


# ==================== PANEL LOGIN ====================

def authenticate_admin(username, password, client_ip):
    """Panel login. Returns (success, message, user_data).
    - web accounts: werkzeug hash only.
    - system accounts: /etc/shadow, ONLY if the account is registered in admin_users as auth_type='system',
      or it is root / a wheel member (auto-provisioned as superadmin). Other Linux accounts are rejected."""
    now = datetime.now()
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM admin_users WHERE username = %s", (username,))
            user_record = cur.fetchone()

        if user_record:
            if user_record.get("status") == "disabled":
                return False, "Hesabınız yönetici tarafından devre dışı bırakılmıştır.", None
            if user_record.get("locked_until") and user_record["locked_until"] > now:
                diff = int((user_record["locked_until"] - now).total_seconds() / 60) + 1
                return False, f"Çok fazla hatalı deneme nedeniyle hesabınız {diff} dakika kilitlendi.", None

        auth_success = False
        auth_source = None
        role = "network_admin"
        full_name = username
        auth_type = user_record.get("auth_type") if user_record else None

        if auth_type == "web":
            auth_source = "web"
            stored_hash = user_record.get("password_hash") or ""
            if stored_hash and check_password_hash(stored_hash, password):
                auth_success = True
                role = user_record.get("role") or "network_admin"
                full_name = user_record.get("full_name") or username
        elif auth_type == "system":
            auth_source = "system"
            if verify_system_password(username, password):
                auth_success = True
                role = user_record.get("role") or "network_admin"
                full_name = user_record.get("full_name") or f"Linux ({username})"
        elif not user_record and (username == "root" or _is_wheel_member(username)):
            auth_source = "system"
            if verify_system_password(username, password):
                auth_success = True
                role = "superadmin"
                full_name = f"Linux ({username})"
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO admin_users (username, full_name, auth_type, role, status, last_login, last_login_ip)
                        VALUES (%s, %s, 'system', %s, 'active', %s, %s)
                        ON DUPLICATE KEY UPDATE last_login = %s, last_login_ip = %s
                    """, (username, full_name, role, now, client_ip, now, client_ip))

        with conn.cursor() as cur:
            if auth_success:
                cur.execute("""
                    UPDATE admin_users
                    SET failed_attempts = 0, locked_until = NULL, last_login = %s, last_login_ip = %s
                    WHERE username = %s
                """, (now, client_ip, username))
            elif user_record:
                fails = (user_record.get("failed_attempts") or 0) + 1
                threshold, lock_secs = lock_policy()
                locked_time = now + timedelta(seconds=lock_secs) if fails >= threshold else None
                cur.execute("UPDATE admin_users SET failed_attempts = %s, locked_until = %s WHERE username = %s",
                            (fails, locked_time, username))
    finally:
        conn.close()

    role_label = ROLE_LABELS.get(role, role)
    if auth_success:
        log_admin_action(username, "GİRİŞ", "Web Paneli", f"Başarılı oturum ({auth_source}, Rol: {role_label})", client_ip)
        send_alert(f"🛡️ <b>[Yönetici Girişi]</b> <code>{html.escape(username)}</code> panele giriş yaptı.\n"
                   f"Rol: {html.escape(role_label)}\nIP: {client_ip}")
        return True, "Giriş Başarılı", {
            "username": username,
            "role": role,
            "role_label": role_label,
            "auth_type": auth_source,
            "full_name": full_name,
        }
    log_admin_action((username or "Bilinmeyen")[:64], "HATALI_GİRİŞ", "Web Paneli", "Hatalı şifre denemesi", client_ip)
    return False, "Geçersiz kullanıcı adı veya şifre!", None


def get_role_display(role_key, role_dict=None):
    if role_dict and role_key in role_dict:
        r = role_dict[role_key]
        return f"{r.get('icon', '🛡️')} {r.get('role_name', role_key)}"
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT role_name, icon FROM admin_roles WHERE role_key = %s", (role_key,))
                row = cur.fetchone()
        finally:
            conn.close()
        if row:
            return f"{row.get('icon') or '🛡️'} {row.get('role_name')}"
    except Exception:
        pass
    return ROLE_LABELS.get(role_key, role_key)
