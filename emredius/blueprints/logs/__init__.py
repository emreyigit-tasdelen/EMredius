# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
from flask import Blueprint

bp = Blueprint("logs", __name__)

from . import routes  # noqa: E402,F401  (registers the views on bp)
