# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
from flask import Blueprint

bp = Blueprint("alarms", __name__)

from . import routes  # noqa: E402,F401
