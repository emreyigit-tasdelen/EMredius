# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Page rendering and URL building shared by all blueprints."""
import logging
import urllib.parse

from flask import current_app, render_template, request
from flask import url_for as _flask_url_for
from markupsafe import Markup

log = logging.getLogger(__name__)

_ENDPOINT_MAP_KEY = "emredius_short_endpoints"


def build_endpoint_map(app):
    """Maps short endpoint names ("groups_page") to blueprint endpoints ("groups.groups_page"), so code and
    templates keep using the original single-module names. Ambiguous short names are left out (and logged)."""
    seen = {}
    for endpoint in app.view_functions:
        if "." in endpoint:
            seen.setdefault(endpoint.rsplit(".", 1)[1], []).append(endpoint)
    mapping, duplicates = {}, {}
    for short, fulls in seen.items():
        if short in app.view_functions:
            continue
        if len(fulls) == 1:
            mapping[short] = fulls[0]
        else:
            duplicates[short] = fulls
    for short, fulls in duplicates.items():
        log.warning("ambiguous short endpoint %r: %s (use the full name)", short, ", ".join(sorted(fulls)))
    app.extensions[_ENDPOINT_MAP_KEY] = mapping
    return duplicates


def url_for(endpoint, **values):
    """flask.url_for that also accepts the short endpoint names of the former single-module app."""
    if "." not in endpoint:
        endpoint = current_app.extensions.get(_ENDPOINT_MAP_KEY, {}).get(endpoint, endpoint)
    return _flask_url_for(endpoint, **values)


def render_page(body, title, page_title=None, active_tab="", **context):
    """Renders a panel page: `body` (HTML built by the view, all dynamic values already escaped) inside base.html."""
    return render_template(
        "base.html",
        title=title,
        page_title=page_title or title,
        active_tab=active_tab,
        body_content=Markup(body),
        **context,
    )


def local_referrer(default_endpoint="dashboard"):
    """Same-origin redirect target derived from the Referer header (path + query only, never another host)."""
    try:
        parts = urllib.parse.urlsplit(request.referrer or "")
        path = parts.path or ""
        if path.startswith("/") and not path.startswith("//") and "\\" not in path:
            return path + (("?" + parts.query) if parts.query else "")
    except ValueError:
        pass
    return url_for(default_endpoint)
