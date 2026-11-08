# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from flask import Blueprint

bp = Blueprint("audit", __name__)

from . import routes, purge  # noqa: E402,F401  (registers the views on bp)
