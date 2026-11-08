# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Law 5651 audit: accounting search, CSV export, signed daily archive (list / verify / download)."""
import os
import urllib.parse
from datetime import datetime

from flask import Response, current_app, flash, redirect, render_template, request, send_file, session

from ...core import get_client_ip, get_setting, log_admin_action, require_page, safe_int, url_for
from ...services import audit5651 as svc
from . import bp


def _archive_dir():
    return current_app.config["ARCHIVE_5651_DIR"]


def _back():
    return redirect(url_for("audit_page"))


@bp.route("/accounting")
@bp.route("/audit")
@require_page("audit")
def audit_page():
    f, errors = svc.parse_filters(request.args)
    for e in errors:
        flash(e, "danger")
    page = safe_int(request.args.get("page"), 1, 1, 10000000) or 1

    results, total, pages = [], 0, 1
    searched = f["active"] and not errors
    if searched:
        try:
            results, total, pages, page = svc.search(f, page)
        except Exception as ex:
            current_app.logger.error("5651 audit search: %s", ex)
            flash("Sorgu çalıştırılamadı (veritabanı hatası).", "danger")
            searched = False
        if searched and page == 1:
            log_admin_action(session.get("user"), "5651_SORGU", "radacct",
                             f"{svc.filter_summary(f)} -> {total} kayıt", get_client_ip())

    tsa_url = (get_setting("tsa_url", "") or "").strip()
    return render_template(
        "audit/index.html",
        title="5651 Yasal Denetim",
        page_title="5651 Yasal IP / MAC Adli Arama",
        active_tab="audit",
        f=f,
        searched=searched,
        results=results,
        total=total,
        pages=pages,
        page=page,
        offset=(page - 1) * svc.PAGE_SIZE,
        page_size=svc.PAGE_SIZE,
        qs=lambda **extra: svc.query_string(f, **extra),
        archive=svc.list_archive(_archive_dir()),
        archive_dir=_archive_dir(),
        tsa_url=tsa_url,
        tsa_host=urllib.parse.urlparse(tsa_url).hostname if tsa_url else "",
    )


@bp.route("/audit/export.csv")
@require_page("audit")
def audit_export_csv():
    f, errors = svc.parse_filters(request.args)
    if errors:
        for e in errors:
            flash(e, "danger")
        return _back()
    if not f["active"]:
        flash("Dışa aktarma için en az bir filtre girin (tüm kayıtlar için geniş bir tarih aralığı seçebilirsiniz).",
              "warning")
        return _back()
    log_admin_action(session.get("user"), "5651_DISA_AKTAR", "radacct", svc.filter_summary(f), get_client_ip())
    filename = f"5651_denetim_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    resp = Response(svc.export_csv_stream(f), mimetype="text/csv")
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.route("/audit/archive/verify")
@require_page("audit")
def audit_archive_verify():
    archive_dir = _archive_dir()
    if not os.path.isdir(archive_dir):
        flash("5651 arşiv dizini bulunamadı; doğrulanacak arşiv yok.", "warning")
        return _back()

    errors = []
    d_from = svc.parse_date(request.args.get("start"), "Başlangıç tarihi", errors)
    d_to = svc.parse_date(request.args.get("end"), "Bitiş tarihi", errors)
    for e in errors:
        flash(e, "danger")
    s_from = d_from.strftime("%Y-%m-%d") if d_from else ""
    s_to = d_to.strftime("%Y-%m-%d") if d_to else ""

    try:
        res = svc.verify_archive(archive_dir, s_from or None, s_to or None)
    except OSError as ex:
        flash(f"Arşiv okunamadı: {ex}", "danger")
        return _back()

    ok_count = sum(1 for r in res["rows"] if r["ok"])
    fail_count = len(res["rows"]) - ok_count
    chain_ok = (not res["chain_err"]) and not res["chain_broken"] and not res["chain_malformed"]
    clock_chain_ok = (not res["clock_err"]) and not res["clock_broken"] and not res["clock_malformed"]
    log_admin_action(session.get("user"), "5651_ARSIV_DOGRULA", archive_dir,
                     f"{len(res['rows'])} gün: {ok_count} OK, {fail_count} FAIL; zincir {'OK' if chain_ok else 'FAIL'}",
                     get_client_ip())
    return render_template(
        "audit/verify.html",
        title="5651 Arşiv Doğrulama",
        page_title="5651 Günlük İmzalı Arşiv Doğrulaması",
        active_tab="audit",
        res=res, ok_count=ok_count, fail_count=fail_count, chain_ok=chain_ok, clock_chain_ok=clock_chain_ok, s_from=s_from, s_to=s_to,
    )


@bp.route("/audit/archive/<filename>")
@require_page("audit")
def audit_archive_download(filename):
    name = os.path.basename(filename or "")
    if name != filename or not (name in svc.CHAIN_FILES or svc.FILE_RE.fullmatch(name)):
        flash("Geçersiz arşiv dosya adı.", "danger")
        return _back()
    path = svc.archive_file_path(_archive_dir(), name)
    if not path:
        flash("Arşiv dosyası bulunamadı.", "danger")
        return _back()
    if name.endswith(".csv"):
        mimetype = "text/csv"
    elif name.endswith(".json"):
        mimetype = "application/json"
    elif name.endswith(".tsr"):
        mimetype = "application/timestamp-reply"
    else:
        mimetype = "text/plain"
    log_admin_action(session.get("user"), "5651_ARSIV_INDIR", name, "", get_client_ip())
    return send_file(path, as_attachment=True, download_name=name, mimetype=mimetype, max_age=0)
