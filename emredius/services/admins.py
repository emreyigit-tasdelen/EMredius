# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Panel administrators, custom roles (RBAC), own profile / password / 2FA, admin audit CSV."""
import csv
import io
import logging
import re

import pymysql
from werkzeug.security import check_password_hash, generate_password_hash

from ..core import (PAGE_DEFINITIONS, ROLE_LABELS, SUPERADMIN_ONLY_PAGES, VALID_PAGE_KEYS, get_db,
                    get_system_linux_users, verify_system_password, verify_totp_token)
from .radius_users import ServiceError

try:
    import pwd
except ImportError:  # pragma: no cover (Windows dev machines)
    pwd = None

log = logging.getLogger(__name__)

USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")
ROLE_KEY_RE = re.compile(r"^[a-z0-9_]{2,50}$")
EMAIL_RE = re.compile(r"^[^@\s<>\"'`]+@[^@\s<>\"'`]+\.[^@\s<>\"'`]+$")
MIN_PASSWORD_LEN = 8
# Only these admin_users columns may ever reach the browser (never password_hash / totp_secret / lockout data)
PUBLIC_FIELDS = ("username", "full_name", "email", "auth_type", "role", "status", "totp_enabled", "last_login",
                 "last_login_ip")
ROLE_PUBLIC_FIELDS = ("role_key", "role_name", "description", "allowed_pages", "icon", "is_system")
ROLE_BADGE_STYLES = {
    "superadmin": "background:#f3e8ff; color:#7e22ce; border:1px solid #d8b4fe; font-weight:700;",
    "network_admin": "background:#eff6ff; color:#1d4ed8; border:1px solid #bfdbfe; font-weight:700;",
    "helpdesk": "background:#fef3c7; color:#92400e; border:1px solid #fde68a; font-weight:700;",
    "auditor": "background:#f1f5f9; color:#475569; border:1px solid #cbd5e1; font-weight:700;",
}
DEFAULT_BADGE_STYLE = "background:#e0f2fe; color:#0369a1; border:1px solid #bae6fd; font-weight:700;"
LANGS = ("tr", "en", "zh", "ru", "es", "fr")
_DB_ERROR = "veritabanı hatası"


def _db():
    return get_db()


# ---------- validation helpers ----------

def validate_contact(full_name, email):
    if full_name and len(full_name) > 128:
        return "Ad Soyad en fazla 128 karakter olabilir."
    if email and (len(email) > 128 or not EMAIL_RE.match(email)):
        return "Geçerli bir e-posta adresi giriniz."
    return None


def role_exists(cur, role_key):
    if not role_key or len(role_key) > 64:
        return False
    cur.execute("SELECT 1 AS x FROM admin_roles WHERE role_key = %s", (role_key,))
    return bool(cur.fetchone()) or role_key in ROLE_LABELS


def sanitize_pages(selected):
    """Allowed pages = submitted keys ∩ VALID_PAGE_KEYS (superadmin-only pages never apply to custom roles)."""
    chosen = {str(p).strip() for p in (selected or []) if p}
    pages = [k for k, _ in PAGE_DEFINITIONS if k in chosen and k in VALID_PAGE_KEYS and k not in SUPERADMIN_ONLY_PAGES]
    return ",".join(pages) if pages else "dashboard"


def is_last_active_superadmin(cur, admin_row):
    if not admin_row or (admin_row.get("role") or "") != "superadmin" or (admin_row.get("status") or "") != "active":
        return False
    cur.execute("SELECT COUNT(*) AS c FROM admin_users WHERE role = 'superadmin' AND status = 'active' AND username <> %s",
                (admin_row.get("username") or "",))
    return int((cur.fetchone() or {}).get("c") or 0) == 0


def linux_user_exists(username):
    if pwd is None or not username:
        return False
    try:
        pwd.getpwnam(username)
        return True
    except (KeyError, OSError):
        return False


def is_protected_target(username, current_user):
    """root and the logged-in admin can never be disabled or deleted from the list actions."""
    u = (username or "").lower()
    return u == "root" or u == (current_user or "").lower()


def role_label(role_key, roles_by_key=None):
    r = (roles_by_key or {}).get(role_key)
    if r:
        return r.get("icon") or "🛡️", r.get("role_name") or role_key
    return "🛡️", ROLE_LABELS.get(role_key, role_key)


# ---------- page data ----------

def page_data():
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM admin_users ORDER BY id ASC")
            admins = cur.fetchall()
            cur.execute("SELECT * FROM admin_audit_log ORDER BY id DESC LIMIT 20")
            audit_logs = cur.fetchall()
            cur.execute("SELECT * FROM admin_roles ORDER BY id ASC")
            roles = cur.fetchall()
    finally:
        conn.close()
    roles_by_key = {r["role_key"]: r for r in roles if r.get("role_key")}
    for a in admins:
        a["role"] = a.get("role") or "network_admin"
        a["status"] = a.get("status") or "active"
        a["role_icon"], a["role_name"] = role_label(a["role"], roles_by_key)
        a["role_style"] = ROLE_BADGE_STYLES.get(a["role"], DEFAULT_BADGE_STYLE)
    for r in roles:
        perms = (r.get("allowed_pages") or "").strip()
        r["all_pages"] = perms == "*"
        r["pages"] = [p.strip() for p in perms.split(",") if p.strip()]
        r["deletable"] = not r.get("is_system") and r["role_key"] != "superadmin" and r["role_key"] not in ROLE_LABELS
    for e in audit_logs:
        act = e.get("action") or ""
        e["badge"] = ("badge-disabled" if ("HATALI" in act or "SİL" in act or "DONDUR" in act)
                      else "badge-active" if ("GİRİŞ" in act or "AKTİF" in act) else "badge-vlan")
    role_options = [(r["role_key"], f"{r.get('icon') or '🛡️'} {r.get('role_name') or r['role_key']} ({r['role_key']})")
                    for r in roles if r.get("role_key")]
    if not role_options:
        role_options = [(k, f"{v} ({k})") for k, v in ROLE_LABELS.items()]
    return {
        "admins": admins,
        "audit_logs": audit_logs,
        "roles": roles,
        "role_options": role_options,
        "admins_public": {a["username"]: {k: a.get(k) for k in PUBLIC_FIELDS} for a in admins if a.get("username")},
        "roles_public": {k: {f: r.get(f) for f in ROLE_PUBLIC_FIELDS} for k, r in roles_by_key.items()},
        "linux_users": get_system_linux_users(),
        "total_admins": len(admins),
        "web_admins": sum(1 for a in admins if a.get("auth_type") == "web"),
        "sys_admins": sum(1 for a in admins if a.get("auth_type") == "system"),
        "active_admins": sum(1 for a in admins if a.get("status") == "active"),
    }


# ---------- roles ----------

def add_role(form):
    role_key = (form.get("role_key") or "").strip().lower()
    role_name = (form.get("role_name") or "").strip()
    icon = (form.get("icon") or "").strip() or "🛡️"
    description = (form.get("description") or "").strip()
    if not role_key or not role_name:
        raise ServiceError("Rol kodu ve rol adı zorunludur.")
    if not ROLE_KEY_RE.match(role_key):
        raise ServiceError("Rol anahtarı 2-50 karakter olmalı ve yalnızca küçük harf, rakam ve alt çizgi (_) içermelidir.")
    if role_key == "superadmin" or role_key in ROLE_LABELS:
        raise ServiceError(f"'{role_key}' rol anahtarı sistem tarafından ayrılmıştır.")
    if len(role_name) > 64:
        raise ServiceError("Rol adı en fazla 64 karakter olabilir.")
    if len(icon) > 16:
        raise ServiceError("Rol emojisi çok uzun.")
    if len(description) > 255:
        raise ServiceError("Açıklama en fazla 255 karakter olabilir.")
    pages = sanitize_pages(form.getlist("pages"))
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 AS x FROM admin_roles WHERE role_key = %s", (role_key,))
            if cur.fetchone():
                raise ServiceError(f"'{role_key}' rol anahtarı zaten mevcut.")
            cur.execute("INSERT INTO admin_roles (role_key, role_name, description, allowed_pages, is_system, icon) "
                        "VALUES (%s, %s, %s, %s, 0, %s)", (role_key, role_name, description, pages, icon))
    except pymysql.MySQLError as e:
        log.error("add_role: %s", e)
        raise ServiceError("Rol oluşturulurken bir veritabanı hatası oluştu.") from e
    finally:
        conn.close()
    return {"role_key": role_key, "role_name": role_name, "icon": icon, "pages": pages}


def update_role(form):
    role_key = (form.get("role_key") or "").strip()
    icon = (form.get("icon") or "").strip()
    pages = sanitize_pages(form.getlist("pages"))
    if role_key == "superadmin":
        raise ServiceError("Süper Yönetici rolünün yetkileri kısıtlanamaz.")
    if not role_key or len(role_key) > 64:
        raise ServiceError("Geçersiz rol anahtarı.")
    if len(icon) > 16:
        raise ServiceError("Rol emojisi çok uzun.")
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT role_key FROM admin_roles WHERE role_key = %s", (role_key,))
            if not cur.fetchone():
                raise ServiceError(f"'{role_key}' rolü bulunamadı.")
            if icon:
                cur.execute("UPDATE admin_roles SET allowed_pages = %s, icon = %s WHERE role_key = %s", (pages, icon, role_key))
            else:
                cur.execute("UPDATE admin_roles SET allowed_pages = %s WHERE role_key = %s", (pages, role_key))
    except pymysql.MySQLError as e:
        log.error("update_role: %s", e)
        raise ServiceError("Yetkiler güncellenirken bir veritabanı hatası oluştu.") from e
    finally:
        conn.close()
    try:  # yetki verilen sayfalar için bildirim "yetki anı" başlar
        from . import notifications
        notifications.sync_all()
    except Exception:  # noqa: BLE001
        log.debug("notification sync after role update failed", exc_info=True)
    return {"role_key": role_key, "icon": icon, "pages": pages}


def delete_role(role_key):
    role_key = (role_key or "").strip()
    if not role_key or len(role_key) > 64:
        raise ServiceError("Geçersiz rol anahtarı.")
    if role_key == "superadmin" or role_key in ROLE_LABELS:
        raise ServiceError("Sistem yerleşik rolleri silinemez.")
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT is_system FROM admin_roles WHERE role_key = %s", (role_key,))
            r = cur.fetchone()
            if not r:
                raise ServiceError(f"'{role_key}' rolü bulunamadı.")
            if r.get("is_system"):
                raise ServiceError("Sistem yerleşik rolleri silinemez.")
            cur.execute("SELECT COUNT(*) AS c FROM admin_users WHERE role = %s", (role_key,))
            in_use = int((cur.fetchone() or {}).get("c") or 0)
            if in_use:
                raise ServiceError(f"'{role_key}' rolü hâlâ {in_use} yöneticiye atanmış. "
                                   "Önce bu yöneticilerin rolünü değiştirin.")
            cur.execute("DELETE FROM admin_roles WHERE role_key = %s", (role_key,))
    except pymysql.MySQLError as e:
        log.error("delete_role: %s", e)
        raise ServiceError("Rol silinirken bir veritabanı hatası oluştu.") from e
    finally:
        conn.close()
    return role_key


# ---------- admins ----------

def create_admin(username, full_name, email, role, auth_type, password):
    """Validates and inserts a new admin (never overwrites). Returns the username."""
    if auth_type not in ("web", "system"):
        raise ServiceError("Geçersiz hesap türü.")
    if not username:
        raise ServiceError("Kullanıcı adı zorunludur.")
    if not USERNAME_RE.match(username):
        raise ServiceError("Kullanıcı adı 1-64 karakter olmalı ve sadece harf, rakam, nokta, alt çizgi ve tire içerebilir!")
    err = validate_contact(full_name, email)
    if err:
        raise ServiceError(err)
    password_hash = None
    if auth_type == "web":
        if len(password or "") < MIN_PASSWORD_LEN:
            raise ServiceError(f"Web kullanıcıları için en az {MIN_PASSWORD_LEN} karakterli şifre zorunludur.")
        password_hash = generate_password_hash(password)
        full_name = full_name or username
    else:
        if not linux_user_exists(username):
            raise ServiceError(f"'{username}' kullanıcısı AlmaLinux işletim sisteminde bulunamadı! "
                               f"Önce 'useradd {username}' ile sunucuda oluşturabilirsiniz.")
        full_name = full_name or f"Linux ({username})"
    conn = _db()
    try:
        with conn.cursor() as cur:
            if not role_exists(cur, role):
                raise ServiceError(f"'{role}' rolü tanımlı değil.")
            cur.execute("SELECT username, auth_type, role FROM admin_users WHERE username = %s", (username,))
            existing = cur.fetchone()
            if existing:
                raise ServiceError(f"'{existing.get('username') or username}' kullanıcı adı zaten kayıtlı "
                                   f"(Tür: {existing.get('auth_type')}, Rol: {existing.get('role')}). "
                                   "Değişiklik için 'Düzenle' işlemini kullanın.")
            cur.execute("INSERT INTO admin_users (username, full_name, email, password_hash, auth_type, role, status) "
                        "VALUES (%s, %s, %s, %s, %s, %s, 'active')",
                        (username, full_name, email, password_hash, auth_type, role))
    except pymysql.err.IntegrityError as e:
        raise ServiceError(f"'{username}' kullanıcı adı zaten kayıtlı!") from e
    except pymysql.MySQLError as e:
        log.error("create_admin: %s", e)
        raise ServiceError("Yönetici eklenirken bir veritabanı hatası oluştu.") from e
    finally:
        conn.close()
    return username


def edit_admin(form, current_user):
    """Returns (username, role, status, password_reset, notes)."""
    username = (form.get("username") or "").strip()
    full_name = (form.get("full_name") or "").strip()
    email = (form.get("email") or "").strip()
    role = (form.get("role") or "network_admin").strip()
    status = (form.get("status") or "active").strip()
    new_pw = (form.get("new_password") or "").strip()
    if not username or len(username) > 64:
        raise ServiceError("Geçersiz yönetici kullanıcı adı.")
    if status not in ("active", "disabled"):
        raise ServiceError("Geçersiz hesap durumu.")
    if username.lower() == "root":
        role, status = "superadmin", "active"
    if username.lower() == (current_user or "").lower() and status == "disabled":
        raise ServiceError("Kendi hesabınızı devre dışı bırakamazsınız!")
    err = validate_contact(full_name, email)
    if err:
        raise ServiceError(err)
    notes, pw_reset = [], False
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username, full_name, auth_type, role, status FROM admin_users WHERE username = %s",
                        (username,))
            admin = cur.fetchone()
            if not admin:
                raise ServiceError(f"'{username}' yöneticisi bulunamadı!")
            if not role_exists(cur, role):
                raise ServiceError(f"'{role}' rolü tanımlı değil.")
            if is_last_active_superadmin(cur, admin) and (role != "superadmin" or status != "active"):
                raise ServiceError("Sistemdeki son aktif Süper Yönetici hesabının rolü düşürülemez veya devre dışı "
                                   "bırakılamaz!")
            sql = "UPDATE admin_users SET full_name = %s, email = %s, role = %s, status = %s"
            params = [full_name or admin.get("full_name") or username, email, role, status]
            if new_pw:
                if admin.get("auth_type") != "web":
                    notes.append("Linux OS hesabının şifresi panelden değiştirilemez; şifre alanı yok sayıldı.")
                elif len(new_pw) < MIN_PASSWORD_LEN:
                    raise ServiceError(f"Yeni şifre en az {MIN_PASSWORD_LEN} karakter olmalıdır!")
                else:
                    sql += ", password_hash = %s, failed_attempts = 0, locked_until = NULL"
                    params.append(generate_password_hash(new_pw))
                    pw_reset = True
            params.append(admin["username"])
            cur.execute(sql + " WHERE username = %s", tuple(params))
    except pymysql.MySQLError as e:
        log.error("edit_admin: %s", e)
        raise ServiceError("Yönetici güncellenirken bir veritabanı hatası oluştu.") from e
    finally:
        conn.close()
    return username, role, status, pw_reset, notes


def toggle_admin(username, current_user):
    """Returns the new status."""
    username = (username or "").strip()
    if is_protected_target(username, current_user):
        raise ServiceError("Root kullanıcısı veya kendi hesabınız dondurulamaz!")
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username, role, status FROM admin_users WHERE username = %s", (username,))
            row = cur.fetchone()
            if not row:
                raise ServiceError("Kullanıcı bulunamadı!")
            new_status = "disabled" if row.get("status") == "active" else "active"
            if new_status == "disabled" and is_last_active_superadmin(cur, row):
                raise ServiceError("Sistemdeki son aktif Süper Yönetici devre dışı bırakılamaz!")
            if new_status == "active":
                cur.execute("UPDATE admin_users SET status = %s, failed_attempts = 0, locked_until = NULL "
                            "WHERE username = %s", (new_status, row["username"]))
            else:
                cur.execute("UPDATE admin_users SET status = %s WHERE username = %s", (new_status, row["username"]))
    except pymysql.MySQLError as e:
        log.error("toggle_admin: %s", e)
        raise ServiceError("Durum güncellenirken bir veritabanı hatası oluştu.") from e
    finally:
        conn.close()
    return new_status


def delete_admin(username, current_user):
    """Returns the deleted admin's role."""
    username = (username or "").strip()
    if is_protected_target(username, current_user):
        raise ServiceError("Root kullanıcısı veya kendi hesabınız silinemez!")
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username, role, status FROM admin_users WHERE username = %s", (username,))
            row = cur.fetchone()
            if not row:
                raise ServiceError("Kullanıcı bulunamadı!")
            if is_last_active_superadmin(cur, row):
                raise ServiceError("Sistemdeki son aktif Süper Yönetici silinemez!")
            cur.execute("DELETE FROM admin_users WHERE username = %s", (row["username"],))
    except pymysql.MySQLError as e:
        log.error("delete_admin: %s", e)
        raise ServiceError("Yönetici silinirken bir veritabanı hatası oluştu.") from e
    finally:
        conn.close()
    return row.get("role")


def csv_cell(value):
    """Neutralises spreadsheet formula injection (audit rows contain attacker-controlled login names)."""
    if value is None:
        return ""
    s = str(value)
    return "'" + s if s and s[0] in ("=", "+", "-", "@", "\t", "\r") else s


def audit_csv():
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, admin_username, action, target, details, ip_address, created_at "
                        "FROM admin_audit_log ORDER BY id DESC")
            rows = cur.fetchall()
    finally:
        conn.close()
    out = io.StringIO()
    out.write("﻿")
    w = csv.writer(out)
    w.writerow(["ID", "Yonetici", "Eylem", "Hedef", "Detaylar", "IP Adresi", "Tarih"])
    for r in rows:
        w.writerow([r["id"]] + [csv_cell(r[k]) for k in ("admin_username", "action", "target", "details", "ip_address",
                                                          "created_at")])
    return out.getvalue()


# ---------- own profile ----------

def get_profile(username):
    try:
        conn = _db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT username, full_name, email, auth_type, role, status, last_login, last_login_ip, "
                            "totp_enabled FROM admin_users WHERE username = %s", (username,))
                return cur.fetchone() or {}
        finally:
            conn.close()
    except Exception as e:
        log.error("get_profile: %s", e)
        return {}


def change_own_password(username, current_pw, new_pw, confirm_pw):
    """Raises ServiceError; the message 'Mevcut şifrenizi hatalı girdiniz!' marks a wrong current password."""
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username, auth_type, password_hash FROM admin_users WHERE username = %s", (username,))
            admin = cur.fetchone()
            if not admin or admin.get("auth_type") != "web":
                raise ServiceError("Sadece bağımsız web hesaplarının şifresi buradan değiştirilebilir!")
            stored = admin.get("password_hash") or ""
            if not current_pw or not stored or not check_password_hash(stored, current_pw):
                raise ServiceError("Mevcut şifrenizi hatalı girdiniz!")
            if len(new_pw) < MIN_PASSWORD_LEN:
                raise ServiceError(f"Yeni şifre en az {MIN_PASSWORD_LEN} karakter olmalıdır!")
            if new_pw != confirm_pw:
                raise ServiceError("Yeni şifreler birbiriyle uyuşmuyor!")
            cur.execute("UPDATE admin_users SET password_hash = %s WHERE username = %s",
                        (generate_password_hash(new_pw), username))
    except pymysql.MySQLError as e:
        log.error("change_own_password: %s", e)
        raise ServiceError("Şifre güncellenirken bir veritabanı hatası oluştu.") from e
    finally:
        conn.close()


def _totp_row(cur, username):
    cur.execute("SELECT totp_secret, totp_enabled FROM admin_users WHERE username = %s", (username,))
    return cur.fetchone() or {}


def totp_enabled(username):
    conn = _db()
    try:
        with conn.cursor() as cur:
            return bool(_totp_row(cur, username).get("totp_enabled"))
    finally:
        conn.close()


def enable_totp(username, secret, token):
    if not secret or not verify_totp_token(secret, token):
        raise ServiceError("Girilen 2FA doğrulama kodu hatalı veya zaman aşımına uğramış. Lütfen tekrar deneyiniz.")
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE admin_users SET totp_secret = %s, totp_enabled = 1 WHERE username = %s", (secret, username))
    finally:
        conn.close()


def disable_totp(username, token):
    """Requires a valid code from the CURRENT secret (a stolen session alone cannot remove 2FA)."""
    conn = _db()
    try:
        with conn.cursor() as cur:
            row = _totp_row(cur, username)
            if not row.get("totp_enabled"):
                raise ServiceError("İki aşamalı doğrulama zaten devre dışı.")
            if not verify_totp_token(row.get("totp_secret") or "", token):
                raise ServiceError("2FA kodu hatalı. İki aşamalı doğrulama kapatılmadı.")
            cur.execute("UPDATE admin_users SET totp_secret = NULL, totp_enabled = 0 WHERE username = %s", (username,))
    finally:
        conn.close()


# ---------- superadmin security centre (/security) ----------

def security_overview():
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, full_name, role, auth_type, status, last_login, last_login_ip, totp_enabled "
                        "FROM admin_users ORDER BY id ASC")
            admins = cur.fetchall()
    finally:
        conn.close()
    for a in admins:
        a["role_label"] = ROLE_LABELS.get(a.get("role"), a.get("role"))
        a["auth_type"] = a.get("auth_type") or "system"
    enabled = sum(1 for a in admins if a.get("totp_enabled"))
    return {"admins": admins, "total_admins": len(admins), "totp_enabled_count": enabled,
            "totp_disabled_count": len(admins) - enabled}


def reset_totp(username):
    conn = _db()
    try:
        with conn.cursor() as cur:
            n = cur.execute("UPDATE admin_users SET totp_secret = NULL, totp_enabled = 0 WHERE username = %s", (username,))
    finally:
        conn.close()
    if not n:
        raise ServiceError("Kullanıcı bulunamadı veya 2FA zaten kapalı.")


def reset_password(username, new_pw):
    if not username or len(username) > 64:
        raise ServiceError("Lütfen geçerli bir kullanıcı adı belirtiniz.")
    if len(new_pw or "") < MIN_PASSWORD_LEN:
        raise ServiceError(f"Yeni şifre en az {MIN_PASSWORD_LEN} karakter olmalıdır.")
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT auth_type FROM admin_users WHERE username = %s", (username,))
            row = cur.fetchone()
            if not row or row.get("auth_type") != "web":
                raise ServiceError("İşletim sistemi hesaplarının şifresi terminal üzerinden (passwd) değiştirilmelidir.")
            cur.execute("UPDATE admin_users SET password_hash = %s, failed_attempts = 0, locked_until = NULL "
                        "WHERE username = %s", (generate_password_hash(new_pw), username))
    finally:
        conn.close()


def verify_reauth(username, password, token=""):
    """Re-authentication for dangerous actions: current password (web or system account) and, when the
    account has 2FA enabled, a valid TOTP code. Raises ServiceError."""
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT auth_type, password_hash, totp_secret, totp_enabled FROM admin_users "
                        "WHERE username = %s AND status = 'active'", (username,))
            row = cur.fetchone()
    except pymysql.MySQLError as e:
        log.error("verify_reauth: %s", e)
        raise ServiceError("Kimlik doğrulaması yapılamadı (veritabanı hatası).") from e
    finally:
        conn.close()
    if not row or not password:
        raise ServiceError("Parola doğrulaması başarısız.")
    if row.get("auth_type") == "web":
        ok = bool(row.get("password_hash")) and check_password_hash(row["password_hash"], password)
    else:
        ok = verify_system_password(username, password)
    if not ok:
        raise ServiceError("Parola doğrulaması başarısız.")
    if row.get("totp_enabled") and not verify_totp_token(row.get("totp_secret") or "", (token or "").strip()):
        raise ServiceError("2FA kodu hatalı.")
