# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Role based page access. Every route declares the page key(s) it belongs to with @require_page(...).
Page access implies the actions on that page, except for READ_ONLY_ROLES which can never mutate state
(enforced globally in core.security)."""
import hmac
from functools import wraps

from flask import flash, g, jsonify, redirect, request, session

from .db import get_db
from .settings import get_api_token
from .web import url_for

PAGE_DEFINITIONS = [
    ("dashboard", "Genel Bakış Paneli"),
    ("tacacs", "TACACS+ Yönetimi"),
    ("snmp", "SNMP NMS / Ağ İzleme"),
    ("ntp", "NTP Zaman Sunucusu"),
    ("users", "FreeRADIUS Kullanıcıları"),
    ("batch_users", "Toplu & Misafir Kullanıcılar"),
    ("groups", "Gruplar & Profiller"),
    ("nas", "Ağ Donanımı (NAS)"),
    ("macs", "MAC Whitelist / IoT"),
    ("sessions", "Canlı Oturumlar & CoA"),
    ("audit", "5651 Yasal Denetim"),
    ("admins", "Yöneticiler & Yetkiler (Süper Yönetici)"),
    ("backups", "Yedekleme & Kurtarma (Süper Yönetici)"),
    ("settings", "Sistem Ayarları & Entegrasyon (Süper Yönetici)"),
    ("logs", "Canlı Loglar & Teşhis"),
    ("services", "Servis & Sistem Yeniden Başlat"),
    ("cli", "Web Terminal & CLI (Süper Yönetici)"),
    ("test", "Sistem Doğrulama Testi"),
    ("ipscan", "IP Tarama / Ağ Keşfi"),
    ("portscan", "Port Tarama"),
    ("syslog", "Syslog"),
    ("inventory", "Aktif Cihazlar"),
    ("topology", "Ağ Topolojisi"),
    ("equipment", "Ekipman & MAC Tabloları"),
    ("macscan", "MAC Tarama"),
    ("machist", "MAC Geçmişi"),
    ("macalarm", "MAC Alarmları"),
    ("reports", "Raporlar"),
    ("health", "Ekipman Sağlığı & Trafik"),
    ("watch", "İzlenen IP'ler"),
    ("loops", "Döngü Tespiti"),
    ("flows", "Akış Analizi"),
    ("alarms", "Alarmlar"),
    ("boards", "Özel Panolar"),
    ("configs", "Konfig Yönetimi (Süper Yönetici)"),
    ("ipam", "IPAM"),
    ("permissions", "Yetki Matrisi (Süper Yönetici)"),
    ("tenants", "Kiracılar (Süper Yönetici)"),
    ("svchealth", "Servis Sağlığı"),
    ("ippools", "IP Havuzları"),
    ("erasures", "Misafir Silme"),
    ("apn", "APN Envanteri"),
    ("approvals", "Misafir Onayları"),
    ("hardening", "Sertleştirme (Süper Yönetici)"),
    ("authlog", "Kimlik Doğrulama Günlüğü"),
    ("anomalies", "Anomaliler"),
    ("correlation", "Korelasyon"),
    ("blacklist", "Kara Liste"),
    ("quarantine", "Karantina"),
    ("enforcement", "Uygulama Kayıtları"),
    ("certs", "Sertifikalar (Süper Yönetici)"),
    ("siem", "SIEM Yönlendirme (Süper Yönetici)"),
    ("integrations", "Entegrasyonlar (Süper Yönetici)"),
    ("availability", "Erişilebilirlik"),
]
VALID_PAGE_KEYS = {k for k, _ in PAGE_DEFINITIONS}

# Pages that only the superadmin role may ever open (root-equivalent or security-critical)
SUPERADMIN_ONLY_PAGES = {"backups", "settings", "admins", "security", "cli", "configs", "permissions", "tenants", "hardening", "certs", "siem", "integrations"}
# Roles that may view but never change anything
READ_ONLY_ROLES = {"auditor"}

DEFAULT_ROLE_PAGES = {
    "network_admin": {"dashboard", "tacacs", "snmp", "users", "batch_users", "groups", "nas", "macs",
                      "sessions", "audit", "test", "portscan", "syslog", "ipscan", "inventory", "topology", "equipment", "macscan", "machist", "macalarm", "reports", "health", "watch", "loops", "flows", "alarms", "boards", "ipam", "svchealth", "authlog", "anomalies", "correlation", "blacklist", "quarantine", "enforcement", "ippools", "erasures", "apn", "approvals", "availability"},
    "helpdesk": {"dashboard", "batch_users"},
    "auditor": {"dashboard", "sessions", "audit", "authlog", "anomalies", "correlation", "enforcement"},
}


def get_role_permissions(role_key):
    """Set of allowed page keys for a role (cached per request)."""
    if role_key == "superadmin":
        return {"*"}
    if not role_key:
        return set()
    try:
        cache = g.setdefault("_role_perm_cache", {})
    except RuntimeError:  # outside an app context
        cache = None
    if cache is not None and role_key in cache:
        return cache[role_key]

    perms = None
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT allowed_pages FROM admin_roles WHERE role_key = %s", (role_key,))
                row = cur.fetchone()
        finally:
            conn.close()
        if row and row.get("allowed_pages"):
            raw = row["allowed_pages"].strip()
            perms = {"*"} if raw == "*" else {p.strip() for p in raw.split(",") if p.strip()}
    except Exception:
        perms = None
    if perms is None:
        perms = set(DEFAULT_ROLE_PAGES.get(role_key, {"dashboard"}))
    if cache is not None:
        cache[role_key] = perms
    return perms


def can_access_page(page_name):
    """True if the logged-in user may open page_name."""
    if not session.get("logged_in") or "user" not in session:
        return False
    role = session.get("role") or ""
    if role == "superadmin":
        return True
    if page_name in SUPERADMIN_ONLY_PAGES:
        return False
    perms = get_role_permissions(role)
    return "*" in perms or page_name in perms


def is_read_only_role():
    return (session.get("role") or "") in READ_ONLY_ROLES


def wants_json():
    return (request.path.startswith("/api/") or request.is_json
            or "application/json" in (request.headers.get("Accept") or ""))


def _deny_unauthenticated():
    if wants_json():
        return jsonify({"success": False, "error": "Oturum gerekli."}), 401
    return redirect(url_for("login"))


def require_page(*page_names, superadmin=False):
    """Route decorator: requires a logged-in session and access to ANY of the given page keys
    (or the superadmin role when superadmin=True)."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("logged_in"):
                return _deny_unauthenticated()
            if superadmin:
                allowed = session.get("role") == "superadmin"
            else:
                allowed = any(can_access_page(p) for p in page_names)
            if not allowed:
                if wants_json():
                    return jsonify({"success": False, "error": "Bu işlem için yetkiniz bulunmamaktadır."}), 403
                flash("Bu sayfaya erişim yetkiniz bulunmamaktadır.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return _deny_unauthenticated()
        return f(*args, **kwargs)
    return decorated


def api_auth_required(f):
    """REST API (/api/v1/*): X-API-Key header or `Authorization: Bearer <token>`."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-API-Key")
        if not token:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1].strip()
        expected = get_api_token()
        if not token or not expected or not hmac.compare_digest(str(token), str(expected)):
            return jsonify({"status": "error", "message": "Yetkisiz erişim. Geçerli X-API-Key gereklidir."}), 401
        return f(*args, **kwargs)
    return decorated
