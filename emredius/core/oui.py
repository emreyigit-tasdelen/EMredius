# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""MAC vendor (OUI) lookup backed by a data file that scripts/update_oui.py refreshes."""
import os
import re
import threading

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "oui.tsv")
UNKNOWN = "Bilinmeyen Üretici"
RANDOM = "Rastgele MAC (gizlilik)"

_lock = threading.Lock()
_cache = {"path": None, "mtime": None, "table": {}}


def oui_path():
    return os.environ.get("EMREDIUS_OUI_FILE") or DEFAULT_PATH


def parse_line(line):
    """'AABBCC<TAB>Vendor' -> (prefix, vendor) or None."""
    parts = line.rstrip("\r\n").split("\t", 1)
    if len(parts) != 2 or not re.fullmatch(r"[0-9A-Fa-f]{6}", parts[0]) or not parts[1].strip():
        return None
    return parts[0].upper(), parts[1].strip()


def _load(path):
    table = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            row = parse_line(line)
            if row:
                table[row[0]] = row[1]
    return table


def _table():
    """Loaded table; reloaded when the file's mtime changes (no service restart after an update)."""
    path = oui_path()
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        return _cache["table"] if _cache["path"] == path else {}
    if _cache["path"] != path or _cache["mtime"] != mtime:
        with _lock:
            if _cache["path"] != path or _cache["mtime"] != mtime:
                try:
                    _cache.update(path=path, mtime=mtime, table=_load(path))
                except (OSError, UnicodeDecodeError):
                    pass
    return _cache["table"]


def file_info():
    path = oui_path()
    try:
        st = os.stat(path)
    except OSError:
        return {"path": path, "exists": False, "entries": 0, "mtime": None}
    return {"path": path, "exists": True, "entries": len(_table()), "mtime": st.st_mtime}


def lookup(mac, overrides=None):
    """Vendor name for a MAC in any common notation; falls back to UNKNOWN / RANDOM."""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac or "").upper()
    if len(cleaned) < 6:
        return UNKNOWN
    prefix = cleaned[:6]
    colon = ":".join(prefix[i:i + 2] for i in (0, 2, 4))
    if overrides and colon in overrides:
        return overrides[colon]
    name = _table().get(prefix)
    if name:
        return name
    # locally administered bit set and no registered OUI: phone privacy / virtual MAC
    return RANDOM if int(prefix[:2], 16) & 0x02 else UNKNOWN
