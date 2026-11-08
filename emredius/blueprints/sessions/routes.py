# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Live sessions: list, CoA Disconnect-Request, ghost session cleanup."""
from flask import flash, redirect, render_template, session

from ...core import get_client_ip, log_admin_action, require_page, url_for
from ...services import sessions as svc
from ...services.radius_users import ServiceError
from . import bp


def _back():
    return redirect(url_for("sessions_page"))


@bp.route("/sessions")
@require_page("sessions")
def sessions_page():
    return render_template("sessions/index.html", title="Canlı Oturumlar", page_title="Canlı Oturumlar & CoA / Disconnect",
                           active_tab="sessions", **svc.list_sessions())


@bp.route("/session/disconnect/<int:radacctid>", methods=["POST"])
@require_page("sessions")
def disconnect_session(radacctid):
    admin, client_ip = session.get("user"), get_client_ip()
    try:
        res = svc.disconnect(radacctid)
    except ServiceError as e:
        flash(str(e), "warning" if "zaten sonlanmış" in str(e) else "danger")
        return _back()
    username, target, detail = res["username"], res["target"], res["detail"]
    result = res["result"]
    if result == "no_nas":
        flash(f"{target} adresi için tanımlı bir NAS cihazı (shared secret) bulunamadı. Önce cihazı 'Ağ Donanımı (NAS)' "
              f"sayfasından ekleyin.", "danger")
        log_admin_action(admin, "OTURUM_KES_HATA", username, f"NAS {target} tanımlı değil (radacctid={radacctid})", client_ip)
    elif result == "ack":
        log_admin_action(admin, "OTURUM_KES", username, f"Disconnect-ACK ({target}, radacctid={radacctid})", client_ip)
        flash(f"'{username}' kullanıcısının oturumu NAS ({target}) tarafından sonlandırıldı (Disconnect-ACK).", "success")
    elif result == "nak":
        log_admin_action(admin, "OTURUM_KES_HATA", username,
                         f"Disconnect-NAK ({target}, Error-Cause={detail}, radacctid={radacctid})", client_ip)
        flash(f"NAS ({target}) bağlantı kesme isteğini reddetti (Disconnect-NAK, sebep: {detail}). Oturum kaydı açık "
              f"bırakıldı; NAS oturumu zaten kapattıysa 'Hayalet Oturumları Temizle' kullanılabilir.", "warning")
    elif result == "timeout":
        log_admin_action(admin, "OTURUM_KES_HATA", username, f"NAS yanıt vermedi ({target}, radacctid={radacctid})", client_ip)
        flash(f"NAS ({target}) Disconnect-Request paketine yanıt vermedi (zaman aşımı). CoA portunu ve shared secret'ı "
              f"kontrol edin; oturum kaydı açık bırakıldı.", "danger")
    else:
        log_admin_action(admin, "OTURUM_KES_HATA", username, f"radclient hatası ({target}): {detail}", client_ip)
        flash(f"Disconnect-Request gönderilemedi: {detail}", "danger")
    return _back()


@bp.route("/sessions/clean-ghosts", methods=["POST"])
@require_page("sessions")
def clean_ghost_sessions():
    try:
        cleaned = svc.clean_ghost_sessions()
    except ServiceError as e:
        flash(str(e), "danger")
        return _back()
    log_admin_action(session.get("user"), "HAYALET_OTURUM_TEMIZLE", "radacct", f"{cleaned} askıda kalan oturum kapatıldı",
                     get_client_ip())
    flash(f"{cleaned} adet askıda kalan hayalet oturum temizlendi.", "success")
    return _back()
