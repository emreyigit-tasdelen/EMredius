# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Output escaping helpers for HTML built in Python code (Jinja templates autoescape on their own)."""
import html
import json
import urllib.parse


def esc(value):
    """HTML-escape any value for safe interpolation into HTML text or quoted attributes."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def esc_js(value):
    """Escape a value for use INSIDE a quoted JS string literal that itself sits in an HTML attribute
    (e.g. onclick="confirm('...{esc_js(x)}...')") or inside a <script> string literal."""
    if value is None:
        return ""
    s = json.dumps(str(value))[1:-1].replace("'", "\\u0027").replace("<", "\\u003c").replace(">", "\\u003e")
    return html.escape(s, quote=True)


def url_seg(value):
    """Percent-encode a value for use as a single URL path segment."""
    return urllib.parse.quote(str(value if value is not None else ""), safe="")


def json_script(obj):
    """JSON-encode an object for safe embedding inside a <script> block."""
    return (json.dumps(obj, default=str, ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))
