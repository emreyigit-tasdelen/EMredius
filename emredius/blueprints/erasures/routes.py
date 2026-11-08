# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Misafir Silme (/erasures): süresi dolanların önizlemesi + elle silme."""
from flask import flash, redirect, render_template, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import erasures as svc
from ...services.radius_users import ServiceError
from . import bp


@bp.route("/erasures")
@require_page("erasures")
def erasures_page():
    try:
        data = svc.pending()
    except Exception:  # noqa: BLE001
        data = {"total": 0, "rows": []}
    return render_template("erasures/index.html", title="Misafir Silme", page_title="Misafir Silme (Erasures)",
                           active_tab="erasures", data=data)


@bp.route("/erasures/run", methods=["POST"])
@require_page("erasures")
def erasures_run():
    try:
        fixed, quota = svc.erase()
    except ServiceError as e:
        flash(str(e), "danger")
        return redirect("/erasures")
    total = len(fixed) + len(quota)
    if total:
        log_admin_action(session.get("user"), "MISAFIR_SİL", f"{total} hesap",
                         f"Sabit bitiş: {len(fixed)}, kota dolan: {len(quota)}. Örnek: {', '.join((fixed + quota)[:20])}", get_client_ip())
        flash(f"{total} süresi dolmuş hesap silindi.", "success")
    else:
        flash("Silinecek hesap bulunamadı.", "info")
    return redirect("/erasures")
