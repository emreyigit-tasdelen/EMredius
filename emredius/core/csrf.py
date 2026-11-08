# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Session-bound CSRF token. Verified for every unsafe request in core.security; the base layout JS adds
the token to POST forms (`_csrf_token`) and same-origin fetch() calls (`X-CSRF-Token`)."""
import secrets

from flask import session
from markupsafe import Markup

from .escaping import esc


def csrf_token():
    tok = session.get("_csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["_csrf_token"] = tok
    return tok


def csrf_input():
    """Hidden input for server-rendered POST forms."""
    return Markup(f'<input type="hidden" name="_csrf_token" value="{esc(csrf_token())}">')
