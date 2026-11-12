# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Özel Panolar (/boards): hazır bileşenlerden kişisel pano kurma, canlı yenileme, JSON dışa aktarma."""
import json

from flask import Response, flash, jsonify, redirect, render_template, request, session

from ...core import get_client_ip, log_admin_action, require_page
from ...services import boards as svc
from . import bp


def _user():
    return session.get("user") or ""


@bp.route("/boards")
@require_page("boards")
def boards_page():
    boards = svc.list_boards()
    bid = request.args.get("id", type=int) or (boards[0]["id"] if boards else 0)
    board = svc.get_board(bid) if bid else None
    return render_template("boards/index.html", title="Özel Panolar", page_title="Özel Panolar", active_tab="boards",
                           boards=boards, board=board, catalog={k: v[0] for k, v in svc.CATALOG.items()})


@bp.route("/boards/<int:board_id>/data")
@require_page("boards")
def boards_data(board_id):
    b = svc.get_board(board_id)
    if not b:
        return jsonify({"success": False, "error": "Pano yok."}), 404
    return jsonify({"success": True, "name": b["name"], "widgets": svc.render(b)})


@bp.route("/boards/add", methods=["POST"])
@require_page("boards")
def boards_add():
    bid, err = svc.create_board(request.form.get("name"), _user())
    if err:
        flash(err, "danger")
        return redirect("/boards")
    log_admin_action(_user(), "BOARD_ADD", str(bid), (request.form.get("name") or "")[:64], get_client_ip())
    return redirect(f"/boards?id={bid}")


@bp.route("/boards/<int:board_id>/widgets", methods=["POST"])
@require_page("boards")
def boards_widgets(board_id):
    if svc.set_widgets(board_id, request.form.getlist("widgets")):
        log_admin_action(_user(), "BOARD_EDIT", str(board_id), "bileşenler güncellendi", get_client_ip())
    return redirect(f"/boards?id={board_id}")


@bp.route("/boards/<int:board_id>/rename", methods=["POST"])
@require_page("boards")
def boards_rename(board_id):
    if svc.rename_board(board_id, request.form.get("name")):
        log_admin_action(_user(), "BOARD_RENAME", str(board_id), (request.form.get("name") or "")[:64], get_client_ip())
    return redirect(f"/boards?id={board_id}")


@bp.route("/boards/<int:board_id>/delete", methods=["POST"])
@require_page("boards")
def boards_delete(board_id):
    if svc.delete_board(board_id):
        log_admin_action(_user(), "BOARD_DELETE", str(board_id), "pano silindi", get_client_ip())
    return redirect("/boards")


@bp.route("/boards/<int:board_id>/export.json")
@require_page("boards")
def boards_export(board_id):
    b = svc.get_board(board_id)
    if not b:
        return jsonify({"success": False, "error": "Pano yok."}), 404
    log_admin_action(_user(), "BOARD_EXPORT", str(board_id), "json", get_client_ip())
    return Response(json.dumps({"name": b["name"], "widgets": svc.render(b)}, ensure_ascii=False, indent=1),
                    mimetype="application/json", headers={"Content-Disposition": "attachment; filename=board.json"})
