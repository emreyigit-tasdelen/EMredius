# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Erişilebilirlik (/availability): servis başına 24 saat / 7 / 30 gün erişilebilirlik ve son kesintiler."""
from flask import jsonify, render_template

from ...core import require_page
from ...services import availability as svc
from . import bp

svc.register()


def _report():
    try:
        return svc.report(), None
    except Exception:  # noqa: BLE001
        return [], "Erişilebilirlik verisi okunamadı."


@bp.route("/availability")
@require_page("availability")
def availability_page():
    rows, error = _report()
    return render_template("availability/index.html", title="Erişilebilirlik", page_title="Erişilebilirlik", active_tab="availability",
                           rows=rows, error=error)


@bp.route("/availability/data")
@require_page("availability")
def availability_data():
    rows, error = _report()
    if error:
        return jsonify({"success": False, "error": error}), 503
    return jsonify({"success": True, "rows": rows})
