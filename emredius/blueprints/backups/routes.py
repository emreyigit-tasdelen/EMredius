# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Backups & disaster recovery: archive list, create / download / restore / delete, automatic policy,
single-file source bundle. Superadmin-only page ("backups")."""
import os

from flask import current_app, flash, redirect, render_template, request, send_file, session

from ...core import get_client_ip, get_server_ip, is_dry_run, log_admin_action, require_page, url_for
from ...services import backups as svc
from . import bp

_PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _cfg():
    return current_app.config


def _back():
    return redirect(url_for("backups_page"))


@bp.route("/backup")
@bp.route("/backups")
@require_page("backups")
def backups_page():
    interval, max_count = svc.get_policy()
    bundle = _cfg()["SOURCE_BUNDLE_PATH"]
    return render_template(
        "backups/index.html",
        title="Yedekleme",
        page_title="Yedekleme & Felaket Kurtarma",
        active_tab="backups",
        backups=svc.list_backups(_cfg()["BACKUP_DIR"]),
        interval=interval,
        max_count=max_count,
        next_run=svc.next_run_text(interval),
        interval_choices=svc.INTERVAL_CHOICES,
        preset_intervals=[h for h, _ in svc.INTERVAL_CHOICES],
        scp_command=f"scp admin@{get_server_ip()}:{bundle} ./",
        dry_run=is_dry_run(),
    )


@bp.route("/backup/policy/update", methods=["POST"])
@require_page("backups")
def update_backup_policy_route():
    interval, max_count = svc.parse_policy_form(request.form)
    try:
        host_changed = svc.apply_policy(_cfg(), interval, max_count)
    except svc.ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), "YEDEK_POLİTİKA", "radius-backup.timer",
                     f"Aralık: {interval} saat, Saklanan: {max_count} (tür başına)", get_client_ip())
    flash(f"Otomatik yedekleme politikası güncellendi: Sistem her {interval} saatte bir otomatik yedek alacak ve "
          f"en fazla {max_count} adet güncel yedek saklayacaktır.", "success")
    if not host_changed:
        flash("[staging] SYSTEM_DRY_RUN: zamanlayıcı dosyaları değiştirilmedi.", "warning")
    return _back()


@bp.route("/backup/create-source-bundle", methods=["POST"])
@require_page("backups")
def create_source_bundle():
    try:
        path = svc.create_source_bundle(_cfg(), _PROJECT_DIR)
    except svc.ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), "KAYNAK_PAKET_OLUŞTUR", os.path.basename(path), "", get_client_ip())
    flash(f"Tüm sistem kaynak kodları ve yapılandırma tek dosya altında arşivlendi: {os.path.basename(path)}", "success")
    return _back()


@bp.route("/backup/download-source-bundle")
@require_page("backups")
def download_source_bundle():
    path = _cfg()["SOURCE_BUNDLE_PATH"]
    if not os.path.isfile(path):
        flash("Arşiv paketi henüz oluşturulmadı. Lütfen önce 'Paketi Güncelle / Oluştur' butonuna basınız.", "warning")
        return _back()
    log_admin_action(session.get("user"), "KAYNAK_PAKET_İNDİR", os.path.basename(path), "", get_client_ip())
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@bp.route("/backup/create", methods=["POST"])
@require_page("backups")
def create_backup():
    kind = "full" if request.args.get("type") == "full" else "sql"
    try:
        path = svc.create_backup(_cfg(), kind)
    except svc.ServiceError as e:
        flash(f"Yedek alınırken hata oluştu: {e}", "danger")
        return _back()
    _, max_count = svc.get_policy()
    svc.prune(_cfg()["BACKUP_DIR"], max_count)
    log_admin_action(session.get("user"), "YEDEK_AL", os.path.basename(path),
                     "Tam sistem (DB + raddb)" if kind == "full" else "SQL", get_client_ip())
    flash("Yedekleme başarıyla tamamlandı ve SHA256 özeti kaydedildi.", "success")
    return _back()


@bp.route("/backup/download/<path:filename>")
@require_page("backups")
def download_backup(filename):
    path = svc.backup_path(_cfg()["BACKUP_DIR"], filename)
    if not path:
        flash("Dosya bulunamadı!", "danger")
        return _back()
    log_admin_action(session.get("user"), "YEDEK_İNDİR", os.path.basename(path), "", get_client_ip())
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@bp.route("/backup/restore/<path:filename>", methods=["POST"])
@require_page("backups")
def restore_backup(filename):
    try:
        name = svc.restore_backup(_cfg(), filename)
    except svc.ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), "YEDEK_GERİ_YÜKLE", name, "", get_client_ip())
    flash(f"'{name}' başarıyla geri yüklendi.", "success")
    return _back()


@bp.route("/backup/delete/<path:filename>", methods=["POST"])
@require_page("backups")
def delete_backup(filename):
    try:
        name = svc.delete_backup(_cfg()["BACKUP_DIR"], filename)
    except svc.ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), "YEDEK_SİL", name, "", get_client_ip())
    flash(f"'{name}' silindi.", "success")
    return _back()
