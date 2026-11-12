# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Administrators & RBAC (/admins, /admin/*, /role/*), own profile + password + 2FA (/profile*), language switch."""
from datetime import datetime

from flask import Response, current_app, flash, make_response, redirect, render_template, request, session

from ...core import (ROLE_LABELS, generate_totp_secret, get_client_ip, get_role_display, get_totp_uri, local_referrer,
                     log_admin_action, login_required, require_page, url_for)
from ...services import admins as svc
from . import bp


def _back():
    return redirect(url_for("admins_page"))


def _fail(e, category="danger"):
    flash(str(e), category)
    return _back()


def _me():
    return session.get("user") or ""


# ---------- profile ----------

@bp.route("/profile")
@login_required
def user_profile():
    username = _me()
    admin = svc.get_profile(username)
    role = admin.get("role") or session.get("role") or "network_admin"
    return render_template(
        "admins/profile.html",
        title="Yönetici Profili",
        page_title="Profil & Hesap Ayarları",
        active_tab="profile",
        admin=admin,
        username=username,
        auth_type=admin.get("auth_type") or session.get("auth_type") or "system",
        role_label=get_role_display(role),
        min_pw=svc.MIN_PASSWORD_LEN,
    )


@bp.route("/profile/change-password", methods=["POST"])
@login_required
def change_profile_password():
    username = _me()
    try:
        svc.change_own_password(username, (request.form.get("current_password") or "").strip(),
                                (request.form.get("new_password") or "").strip(),
                                (request.form.get("confirm_password") or "").strip())
    except svc.ServiceError as e:
        if "hatalı" in str(e):
            log_admin_action(username, "ŞİFRE_GÜNCELLE_HATALI", "Profil", "Mevcut şifre hatalı girildi", get_client_ip())
        flash(str(e), "danger")
        return redirect(url_for("user_profile"))
    log_admin_action(username, "ŞİFRE_GÜNCELLE", "Profil", "Yönetici kendi web şifresini güncelledi", get_client_ip())
    flash("Şifreniz başarıyla güncellendi.", "success")
    return redirect(url_for("user_profile"))


@bp.route("/profile/2fa/setup", methods=["GET", "POST"])
@login_required
def profile_2fa_setup():
    username = _me()
    try:
        enabled = svc.totp_enabled(username)
    except Exception:
        flash("Veritabanına ulaşılamadı.", "danger")
        return redirect(url_for("user_profile"))
    if enabled:
        flash("İki aşamalı doğrulama hesabınızda zaten aktif.", "info")
        return redirect(url_for("user_profile"))
    if "setup_2fa_secret" not in session:
        session["setup_2fa_secret"] = generate_totp_secret()
    secret = session["setup_2fa_secret"]
    return render_template(
        "admins/twofa_setup.html",
        title="2FA Kurulumu",
        page_title="2FA Güvenlik Kurulumu",
        active_tab="profile",
        secret=secret,
        formatted_secret=" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)),
        otp_uri=get_totp_uri(username, secret, "EMredius"),
    )


@bp.route("/profile/2fa/verify", methods=["POST"])
@login_required
def profile_2fa_verify():
    # The secret only ever comes from this session (never from the form).
    secret = session.get("setup_2fa_secret") or ""
    token = (request.form.get("token") or "").replace(" ", "").strip()
    if not secret or not token:
        flash("Geçersiz istek parametreleri.", "danger")
        return redirect(url_for("profile_2fa_setup"))
    try:
        svc.enable_totp(_me(), secret, token)
    except svc.ServiceError as e:
        flash(str(e), "danger")
        return redirect(url_for("profile_2fa_setup"))
    session.pop("setup_2fa_secret", None)
    log_admin_action(_me(), "2FA_ETKİN", "Profil", "İki aşamalı doğrulama etkinleştirildi", get_client_ip())
    flash("İki aşamalı doğrulama (2FA) başarıyla etkinleştirildi! Hesabınız artık TOTP ile tam koruma altında.", "success")
    return redirect(url_for("user_profile"))


@bp.route("/profile/2fa/disable", methods=["POST"])
@login_required
def profile_2fa_disable():
    try:
        svc.disable_totp(_me(), (request.form.get("token") or "").replace(" ", "").strip())
    except svc.ServiceError as e:
        flash(str(e), "danger")
        return redirect(url_for("user_profile"))
    log_admin_action(_me(), "2FA_KAPAT", "Profil", "İki aşamalı doğrulama kapatıldı", get_client_ip())
    flash("İki aşamalı doğrulama (2FA) hesabınızdan kaldırıldı ve devre dışı bırakıldı.", "warning")
    return redirect(url_for("user_profile"))


# ---------- roles ----------

@bp.route("/role/add", methods=["POST"])
@require_page("admins")
def add_custom_role():
    try:
        r = svc.add_role(request.form)
    except svc.ServiceError as e:
        return _fail(e)
    log_admin_action(_me(), "ROL EKLE", r["role_key"], f"Yeni rol: {r['icon']} {r['role_name']} | Sayfalar: {r['pages']}",
                     get_client_ip())
    flash(f"'{r['icon']} {r['role_name']}' ({r['role_key']}) rolü başarıyla oluşturuldu.", "success")
    return _back()


@bp.route("/role/update", methods=["POST"])
@require_page("admins")
def update_role_permissions():
    try:
        r = svc.update_role(request.form)
    except svc.ServiceError as e:
        return _fail(e, "warning" if "kısıtlanamaz" in str(e) else "danger")
    log_admin_action(_me(), "ROL GÜNCELLE", r["role_key"], f"Yetkiler güncellendi: {r['pages']} (İkon: {r['icon'] or '-'})",
                     get_client_ip())
    flash(f"'{r['role_key']}' rolünün yetkileri ve ikonu güncellendi.", "success")
    return _back()


@bp.route("/role/delete/<path:role_key>", methods=["POST"])
@require_page("admins")
def delete_custom_role(role_key):
    try:
        rk = svc.delete_role(role_key)
    except svc.ServiceError as e:
        return _fail(e, "warning" if "atanmış" in str(e) else "danger")
    log_admin_action(_me(), "ROL SİL", rk, "Özel rol silindi", get_client_ip())
    flash(f"'{rk}' rolü silindi.", "success")
    return _back()


# ---------- admins ----------

@bp.route("/rbac")
@bp.route("/admins")
@require_page("admins")
def admins_page():
    try:
        data = svc.page_data()
    except Exception as e:
        current_app.logger.error("admins page: %s", e)
        flash("Yönetici listesi okunamadı (veritabanı hatası).", "danger")
        data = {"admins": [], "audit_logs": [], "roles": [], "role_options": [(k, f"{v} ({k})") for k, v in ROLE_LABELS.items()],
                "admins_public": {}, "roles_public": {}, "linux_users": [], "total_admins": 0, "web_admins": 0,
                "sys_admins": 0, "active_admins": 0}
    me = _me()
    return render_template(
        "admins/index.html",
        title="Yöneticiler & Roller",
        page_title="Yönetici Kullanıcılar & RBAC Yetkilendirme",
        active_tab="admins",
        min_pw=svc.MIN_PASSWORD_LEN,
        is_protected=lambda u: svc.is_protected_target(u, me),
        **data,
    )


def _create(auth_type, audit_action, lower=False):
    username = (request.form.get("username") or "").strip()
    username = username.lower() if lower else username
    role = (request.form.get("role") or "network_admin").strip()
    try:
        svc.create_admin(username, (request.form.get("full_name") or "").strip(), (request.form.get("email") or "").strip(),
                         role, auth_type, (request.form.get("password") or "").strip() if auth_type == "web" else "")
    except svc.ServiceError as e:
        return _fail(e)
    log_admin_action(_me(), audit_action, username, f"Tür: {auth_type}, Rol: {ROLE_LABELS.get(role, role)}", get_client_ip())
    flash(f"'{username}' yöneticisi başarıyla eklendi ({'Linux PAM' if auth_type == 'system' else 'Web Hesabı'}).",
          "success")
    return _back()


@bp.route("/admin/add-unified", methods=["POST"])
@require_page("admins")
def add_unified_admin():
    return _create((request.form.get("auth_type") or "web").strip(), "YÖNETİCİ EKLE")


@bp.route("/admin/add-web", methods=["POST"])
@require_page("admins")
def add_web_admin():
    return _create("web", "YÖNETİCİ_EKLE", lower=True)


@bp.route("/admin/add-system", methods=["POST"])
@require_page("admins")
def add_system_admin():
    return _create("system", "SİSTEM_YÖNETİCİSİ_YETKİLENDİR")


@bp.route("/admin/edit", methods=["POST"])
@require_page("admins")
def edit_admin():
    try:
        username, role, status, pw_reset, notes = svc.edit_admin(request.form, _me())
    except svc.ServiceError as e:
        return _fail(e)
    details = f"Bilgiler güncellendi (Rol: {ROLE_LABELS.get(role, role)}, Durum: {status}"
    details += ", Şifre sıfırlandı)" if pw_reset else ")"
    log_admin_action(_me(), "YÖNETİCİ_DÜZENLE", username, details, get_client_ip())
    for n in notes:
        flash(n, "warning")
    flash(f"'{username}' bilgileri başarıyla güncellendi.", "success")
    return _back()


@bp.route("/admin/toggle-status/<path:username>", methods=["POST"])
@require_page("admins")
def toggle_admin_status(username):
    try:
        new_status = svc.toggle_admin(username, _me())
    except svc.ServiceError as e:
        return _fail(e)
    log_admin_action(_me(), "DURUM_DEĞİŞTİR", username, f"Durum '{new_status}' yapıldı", get_client_ip())
    flash(f"'{username}' durumu '{new_status}' olarak güncellendi.", "success")
    return _back()


@bp.route("/admin/delete/<path:username>", methods=["POST"])
@require_page("admins")
def delete_admin(username):
    try:
        role = svc.delete_admin(username, _me())
    except svc.ServiceError as e:
        return _fail(e)
    log_admin_action(_me(), "YÖNETİCİ_SİL", username, f"Yönetici hesabı tablodan kaldırıldı (Rol: {role})", get_client_ip())
    flash(f"'{username}' yöneticisi başarıyla silindi.", "success")
    return _back()


@bp.route("/admin/audit/export.csv")
@require_page("admins")
def export_admin_audit():
    text = svc.audit_csv()
    log_admin_action(_me(), "DENETİM_CSV_DIŞA_AKTAR", "admin_audit_log", "", get_client_ip())
    filename = f"admin_audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(text.encode("utf-8"), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}", "Cache-Control": "no-store"})


# ---------- language ----------

@bp.route("/set-lang/<lang>")
def set_lang(lang):
    resp = make_response(redirect(local_referrer()))
    if lang in svc.LANGS:
        session["lang"] = lang
        resp.set_cookie("app_lang", lang, max_age=31536000, samesite="Lax")
    return resp
