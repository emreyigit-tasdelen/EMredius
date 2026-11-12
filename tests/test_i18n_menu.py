# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Sol menü etiketleri base.html ile i18n sözlüğü arasında birebir ve titremesiz olmalı."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "emredius"


def test_menu_labels_match_data_i18n():
    base = (ROOT / "templates" / "base.html").read_text(encoding="utf8")
    for key, text in re.findall(r'data-i18n="([^"]+)"[^>]*>([^<]*)<', base):
        assert key.strip() == text.strip(), (key, text)


def test_canonical_lookup_prefers_exact_key():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf8")
    body = app.split("function getCanonicalKey", 1)[1].split("}\n", 1)[0]
    assert "I18N_RAW[exact]" in body
