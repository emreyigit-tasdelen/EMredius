# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Batch / guest accounts and Wi-Fi vouchers: list, generate, delete, purge expired, print (QR cards)."""
from flask import flash, redirect, render_template, request, session

from ...core import get_client_ip, get_setting, log_admin_action, login_required, require_page, safe_int, url_for
from ...services import vouchers as svc
from ...services.radius_users import ServiceError
from . import bp


def _back():
    return redirect(url_for("batch_users_page"))


@bp.route("/vouchers", endpoint="vouchers_page")
@login_required
def vouchers_redirect():
    return _back()


@bp.route("/batch-users")
@require_page("batch_users")
def batch_users_page():
    data = svc.list_batch_accounts()
    return render_template(
        "batch/index.html",
        title="Toplu & Misafir Kullanıcılar",
        page_title="Toplu & Misafir Kullanıcılar",
        active_tab="batch_users",
        duration_options=svc.VOUCHER_DURATION_LABELS,
        rate_options=svc.VOUCHER_RATE_OPTIONS,
        **data,
    )


@bp.route("/voucher/generate", methods=["POST"])
@bp.route("/vouchers/generate", methods=["POST"])
@require_page("batch_users")
def generate_vouchers_action():
    f = request.form
    try:
        p = svc.validate_generate(f.get("count"), f.get("duration"), f.get("timing_mode"), f.get("vlan_id"),
                                  f.get("rate_limit"), f.get("description"))
        res = svc.generate_vouchers(p)
    except ServiceError as e:
        flash(str(e), "danger")
        return _back()
    codes = res["codes"]
    mode_label = "İlk girişte başlar" if p["timing_mode"] == "first_login" else f"Sabit bitiş ({res['exp_str']})"
    log_admin_action(
        session.get("user"), "KUPON_ÜRET", f"{p['count']} kupon ({codes[0]} .. {codes[-1]})",
        f"Süre: {p['duration']}, Mod: {mode_label}, VLAN: {p['vlan'] or '-'}, Hız: {p['rate'] or 'Limitsiz'}, "
        f"Açıklama: {p['desc']}",
        get_client_ip(),
    )
    flash(f"{p['count']} adet kupon başarıyla üretildi ({svc.quota_label(res['total_seconds'])}, {mode_label}).", "success")
    return _back()


@bp.route("/voucher/delete/<code>", methods=["POST"])
@require_page("batch_users")
def delete_voucher_action(code):
    try:
        code = svc.delete_voucher(code)
    except ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), "KUPON_SİL", code,
                     "Kupon / toplu hesap silindi (radcheck, radreply, radusergroup, radius_meta)", get_client_ip())
    flash(f"'{code}' silindi.", "success")
    return _back()


@bp.route("/vouchers/purge-expired", methods=["POST"])
@require_page("batch_users")
def purge_expired_vouchers():
    try:
        expired_fixed, expired_quota = svc.purge_expired_vouchers()
    except ServiceError as e:
        flash(str(e), "danger")
        return _back()
    total = len(expired_fixed) + len(expired_quota)
    if total:
        sample = ", ".join((expired_fixed + expired_quota)[:20])
        log_admin_action(session.get("user"), "KUPON_TEMİZLE", f"{total} kupon",
                         f"Sabit bitişi geçen: {len(expired_fixed)}, Kullanım kotası dolan: {len(expired_quota)}. "
                         f"Örnek: {sample}{' ...' if total > 20 else ''}", get_client_ip())
        flash(f"{total} adet kupon temizlendi: {len(expired_fixed)} süresi dolmuş (sabit bitiş), "
              f"{len(expired_quota)} kullanım kotası tükenmiş (ilk girişte başlayan).", "success")
    else:
        flash("Temizlenecek süresi dolmuş veya kotası tükenmiş kupon bulunamadı.", "info")
    return _back()


@bp.route("/vouchers/print")
@require_page("batch_users")
def print_vouchers():
    ssid = get_setting("company_ssid_name", "Sirket-WiFi-Secure") or "Sirket-WiFi-Secure"
    brand = get_setting("company_brand_name", "Kurumsal Ağ Güvenliği") or "Kurumsal Ağ Güvenliği"
    only_code = (request.args.get("code") or "").strip()[:64]
    limit = safe_int(request.args.get("limit"), 1000, 1, 5000)
    cards = svc.printable_vouchers(only_code, limit, ssid)
    return render_template(
        "batch/print.html", cards=cards, ssid=ssid, brand=brand,
        truncated=not only_code and len(cards) >= limit, limit=limit,
        qr_items=[{"id": c["qr_id"], "payload": c["qr_payload"]} for c in cards],
    )
