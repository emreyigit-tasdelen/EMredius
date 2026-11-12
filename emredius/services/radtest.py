# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""radtest wrapper: sends one Access-Request to the local FreeRADIUS server."""
import re

from ..core import run_cmd

_PASSWORD_ECHO_RE = re.compile(r'(User-Password\s*=\s*)(".*"|\S+)')


def arg_error(label, value, max_len):
    if not value:
        return f"{label} boş olamaz!"
    if len(value) > max_len:
        return f"{label} en fazla {max_len} karakter olabilir!"
    if value.startswith("-"):
        return f"{label} '-' ile başlayamaz!"
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return f"{label} kontrol karakteri içeremez!"
    return None


def validate(username, password, secret):
    return (arg_error("Kullanıcı adı", username, 253)
            or arg_error("Şifre", password, 128)
            or arg_error("NAS secret", secret, 128))


def run_radtest(username, password, secret):
    """Returns {"success": bool, "output": str}; the echoed password is masked in the output."""
    rc, out, errout = run_cmd(["radtest", username, password, "127.0.0.1", "0", secret], timeout=15)
    output = ((out or "") + "\n" + (errout or "")).strip()
    output = _PASSWORD_ECHO_RE.sub(r'\1"********"', output)
    return {
        "success": "Received Access-Accept" in (out or ""),
        "output": output or f"radtest çıktı üretmedi (çıkış kodu {rc}).",
    }
