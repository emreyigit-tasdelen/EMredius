# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Korelasyon (/correlation): kullanıcı / MAC / IP için kimlik doğrulama + oturum + port + işaret birleşik görünümü."""
from flask import jsonify, render_template, request

from ...core import require_page
from ...services import correlation as svc
from . import bp


def _args():
    try:
        days = int(request.args.get("days", 30))
    except ValueError:
        days = 30
    return (request.args.get("q") or "")[:64], max(1, min(days, 365))


@bp.route("/correlation")
@require_page("correlation")
def correlation_page():
    q, days = _args()
    return render_template("correlation/index.html", title="Korelasyon", page_title="Korelasyon", active_tab="correlation",
                           q=q, days=days)


@bp.route("/correlation/data")
@require_page("correlation")
def correlation_data():
    q, days = _args()
    return jsonify({"success": True, **svc.lookup(q, days)})
