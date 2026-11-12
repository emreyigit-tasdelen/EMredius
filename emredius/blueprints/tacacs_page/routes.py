# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""TACACS+ management page (data from the NMS SQLite DB; CRUD goes through the NMS /api/tacacs/* blueprint)."""
from flask import flash, render_template

from ...core import require_page
from ...services import tacacs as svc
from . import bp


@bp.route("/tacacs")
@require_page("tacacs")
def tacacs_page():
    data, error = svc.page_data()
    if error:
        flash(error, "danger")
    return render_template("tacacs/index.html", title="TACACS+ Yönetimi",
                           page_title="TACACS+ AAA & Komut Yetkilendirme Motoru", active_tab="tacacs", **data)
