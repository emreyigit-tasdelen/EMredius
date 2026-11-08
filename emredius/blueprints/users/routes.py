# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""RADIUS users: list, add/edit, disable/enable/delete, password reveal, CSV export/import."""
from flask import Response, flash, jsonify, redirect, render_template, request, session

from ...core import can_access_page, get_client_ip, log_admin_action, require_page, url_for
from ...services import radius_users as svc
from . import bp


def _back():
    return redirect(url_for("users_page"))


def _form_fields():
    return {
        "username": request.form.get("username"),
        "password": request.form.get("password"),
        "vlan": request.form.get("vlan_id"),
        "static_ip": request.form.get("static_ip"),
        "rate": request.form.get("rate_limit"),
        "group": request.form.get("groupname"),
        "desc": request.form.get("description"),
    }


def _yes_no(flag):
    return "Evet" if flag else "Hayır"


@bp.route("/users")
@require_page("users")
def users_page():
    users, groups = svc.list_users()
    return render_template(
        "users/index.html",
        title="Kullanıcılar",
        page_title="Kullanıcı & Dinamik Yetkilendirme",
        active_tab="users",
        users=users,
        groups=groups,
        edit_payload=svc.edit_payload,
        password_max_len=svc.USER_PASSWORD_MAX_LEN,
        desc_max_len=svc.USER_DESC_MAX_LEN,
        import_max_rows=svc.USER_IMPORT_MAX_ROWS,
    )


@bp.route("/user/password/<path:username>", methods=["POST"])
@require_page("users")
def reveal_user_password(username):
    """Returns one user's Cleartext-Password on explicit request (the users table never embeds passwords).
    Every reveal is written to the admin audit log."""
    canon, pw = svc.get_password(username)
    if pw is None:
        return jsonify({"success": False, "error": "Kullanıcı bulunamadı."}), 404
    log_admin_action(session.get("user"), "KULLANICI_ŞİFRE_GÖRÜNTÜLE", canon, "Kullanıcı şifresi panelde görüntülendi",
                     get_client_ip())
    resp = jsonify({"success": True, "password": pw})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.route("/user/add", methods=["POST"])
@require_page("users")
def add_user_action():
    work_hours = request.form.get("work_hours_only") == "1"
    single_device = request.form.get("single_device") == "1"
    try:
        d = svc.add_user(_form_fields(), work_hours, single_device)
    except svc.ServiceError as e:
        flash(str(e), "danger")
        return _back()
    u = d["username"]
    log_admin_action(
        session.get("user"), "KULLANICI_EKLE", u,
        f"Grup: {d['group'] or '-'}, VLAN: {d['vlan'] or '-'}, Limit: {d['rate'] or '-'}, Statik IP: {d['static_ip'] or '-'}, "
        f"Mesai: {_yes_no(work_hours)}, Tek Cihaz: {_yes_no(single_device)}",
        get_client_ip(),
    )
    flash(f"'{u}' kullanıcısı başarıyla oluşturuldu.", "success")
    return _back()


@bp.route("/user/edit", methods=["POST"])
@require_page("users")
def edit_user_action():
    work_hours = request.form.get("work_hours_only") == "1"
    single_device = request.form.get("single_device") == "1"
    try:
        u, d = svc.edit_user(_form_fields(), work_hours, single_device)
    except svc.ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(
        session.get("user"), "KULLANICI_GÜNCELLE", u,
        f"Şifre: {'değiştirildi' if d['password'] else 'korundu'}, Grup: {d['group'] or '-'}, VLAN: {d['vlan'] or '-'}, "
        f"Limit: {d['rate'] or '-'}, Statik IP: {d['static_ip'] or '-'}, Mesai: {_yes_no(work_hours)}, "
        f"Tek Cihaz: {_yes_no(single_device)}",
        get_client_ip(),
    )
    flash(f"'{u}' kullanıcısının ayarları başarıyla güncellendi.", "success")
    return _back()


_STATE_ACTIONS = {
    "disable": ("KULLANICI_ASKIYA_AL", "Auth-Type := Reject (girişler engellendi)",
                "'{}' hesabı askıya alındı (Girişler engellendi).", "warning"),
    "enable": ("KULLANICI_AKTİF", "Erişim kısıtı kaldırıldı", "'{}' hesabı tekrar aktif edildi.", "success"),
    "delete": ("KULLANICI_SİL", "radcheck/radreply/radusergroup/radius_meta kayıtları silindi", "'{}' silindi.", "success"),
}


def _change_state(username, action):
    audit_action, details, message, category = _STATE_ACTIONS[action]
    try:
        u = svc.change_user_state(username, action)
    except svc.ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), audit_action, u, details, get_client_ip())
    flash(message.format(u), category)
    return _back()


@bp.route("/user/disable/<path:username>", methods=["POST"])
@require_page("users")
def disable_user_action(username):
    return _change_state(username, "disable")


@bp.route("/user/enable/<path:username>", methods=["POST"])
@require_page("users")
def enable_user_action(username):
    return _change_state(username, "enable")


@bp.route("/user/delete/<path:username>", methods=["POST"])
@require_page("users")
def delete_user_action(username):
    return _change_state(username, "delete")


@bp.route("/users/export.csv")
@require_page("users")
def export_users_csv():
    text, count = svc.export_users_csv()
    log_admin_action(session.get("user"), "KULLANICI_CSV_DIŞA_AKTAR", "radius_users_export.csv",
                     f"{count} kullanıcı (şifreler dahil) dışa aktarıldı", get_client_ip())
    return Response(text, mimetype="text/csv", headers={
        "Content-Disposition": "attachment; filename=radius_users_export.csv",
        "Cache-Control": "no-store",
    })


def _import_redirect():
    if request.path == "/users/import-csv" and can_access_page("batch_users"):
        return redirect(url_for("batch_users_page"))
    if can_access_page("users"):
        return _back()
    return redirect(url_for("batch_users_page"))


@bp.route("/users/import-csv", methods=["POST"], endpoint="users_import_csv")
@bp.route("/users/import.csv", methods=["POST"])
@require_page("users", "batch_users")
def import_users_csv():
    # Imports started from the batch-users page (or by a role without the users page) become batch accounts,
    # which is where those operators can see and manage them.
    is_batch = (request.path == "/users/import-csv" and can_access_page("batch_users")) or not can_access_page("users")
    account_type = "batch" if is_batch else "user"

    file = request.files.get("csv_file")
    fname = (file.filename or "") if file else ""
    if not file or not fname.lower().endswith((".csv", ".txt")):
        flash("Geçerli bir CSV dosyası seçilmedi!", "danger")
        return _import_redirect()
    try:
        colmap, rows = svc.parse_import_csv(file.read(svc.USER_IMPORT_MAX_BYTES + 1))
        res = svc.import_users(colmap, rows, account_type)
    except svc.ServiceError as e:
        flash(str(e), "warning" if "satır bulunamadı" in str(e) else "danger")
        return _import_redirect()

    imported, skipped, invalid, errors = res["imported"], res["skipped"], res["invalid"], res["errors"]
    log_admin_action(
        session.get("user"), "KULLANICI_CSV_İÇE_AKTAR", fname[:128],
        f"Eklenen: {imported}, Atlanan: {skipped}, Geçersiz: {invalid}, Hesap türü: {account_type}",
        get_client_ip(),
    )
    flash(
        f"CSV içe aktarma tamamlandı: {imported} kullanıcı eklendi, {skipped} atlandı (zaten mevcut / tekrarlı), "
        f"{invalid} geçersiz satır.",
        "success" if imported and not invalid else "warning",
    )
    if errors:
        flash("Geçersiz satırlar: " + " | ".join(errors) + (" ..." if invalid > len(errors) else ""), "danger")
    return _import_redirect()
