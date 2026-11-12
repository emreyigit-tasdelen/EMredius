# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""Yeni menü iskeleti:  python scripts/new_menu.py <ad> "<Başlık>" [/url]
Üretir: blueprints/<ad>/, services/<ad>.py, templates/<ad>/index.html, tests/test_<ad>.py
Sonra elle (3 satır): blueprints/__init__.py listesi, core/rbac.py PAGE_DEFINITIONS, templates/base.html nav.
İndeks: python scripts/new_menu.py --index  -> docs/MODULES.md yeniden üretir."""
import re
import sys
from pathlib import Path

R = Path(__file__).resolve().parent.parent
P = R / "emredius"


def index():
    rows = ["# Modüller (otomatik: python scripts/new_menu.py --index)", "",
            "| menü | URL'ler | servis | şablon | test |", "|---|---|---|---|---|"]
    for d in sorted((P / "blueprints").iterdir()):
        r = d / "routes.py"
        if not r.exists():
            continue
        urls = sorted(set(re.findall(r'@bp\.route\("([^"]+)"', r.read_text(encoding="utf-8"))))
        shown = ", ".join(urls[:4]) + (f" +{len(urls) - 4}" if len(urls) > 4 else "")
        n = d.name
        rows.append(f"| {n} | {shown} | {'services/%s.py' % n if (P / 'services' / (n + '.py')).exists() else '-'} "
                    f"| {'templates/%s/' % n if (P / 'templates' / n).exists() else '-'} "
                    f"| {'tests/test_%s.py' % n if (R / 'tests' / ('test_%s.py' % n)).exists() else '-'} |")
    (R / "docs" / "MODULES.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print("docs/MODULES.md yazıldı")


def make(name, title, url):
    files = {
        P / "blueprints" / name / "__init__.py":
            f'from flask import Blueprint\n\nbp = Blueprint("{name}", __name__)\n\nfrom . import routes  # noqa: E402,F401\n',
        P / "blueprints" / name / "routes.py":
            f'"""{title} ({url})."""\nfrom ...core import render_page, require_page\nfrom ...services import {name} as svc\nfrom . import bp\n\n\n'
            f'@bp.route("{url}")\n@require_page("{name}")\ndef {name}_page():\n    return render_page(svc.overview(), "{title}", "{title}", "{name}")\n',
        P / "services" / f"{name}.py": f'"""{title}: iş mantığı (route\'tan bağımsız)."""\n\n\ndef overview():\n    return ""\n',
        P / "templates" / name / "index.html": f'<h2>{title}</h2>\n',
        R / "tests" / f"test_{name}.py":
            f'from conftest import login_as\n\n\ndef test_{name}_page(client):\n    login_as(client, "superadmin")\n    assert client.get("{url}").status_code == 200\n',
    }
    for f, c in files.items():
        if f.exists():
            sys.exit(f"zaten var: {f}")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(c, encoding="utf-8")
    print(f"""Üretildi. Elle yapılacak:
 1. emredius/blueprints/__init__.py listesine "{name}"
 2. emredius/core/rbac.py PAGE_DEFINITIONS: ("{name}", "{title}") (+ gerekirse rol kümelerine)
 3. emredius/templates/base.html: can_access('{name}') nav bloğu (ipscan bloğunu kopyala)
 Sonra: python tests/run_tests.py ; python scripts/new_menu.py --index""")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["--index"]:
        index()
    elif len(a) >= 2:
        make(a[0], a[1], a[2] if len(a) > 2 else "/" + a[0].replace("_", "-"))
    else:
        print(__doc__)
