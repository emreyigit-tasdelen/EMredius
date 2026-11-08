# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Pure-Python TOTP (RFC 6238) for administrator 2FA."""
import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
import urllib.parse


def generate_totp_secret():
    """32-character base32 secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=").upper()


def _key(secret):
    secret = secret.strip().replace(" ", "").upper()
    return base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))


def _code(key, counter):
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[off:off + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def get_totp_token(secret, time_step=30):
    """Current 6-digit TOTP token."""
    if not secret:
        return ""
    return _code(_key(secret), int(time.time() // time_step))


def verify_totp_token(secret, token, window=1, time_step=30):
    """Verifies a 6-digit TOTP token within +- window steps."""
    if not secret or not token:
        return False
    try:
        token = str(token).strip()
        if not re.fullmatch(r"\d{6}", token):
            return False
        key = _key(secret)
        counter = int(time.time() // time_step)
        return any(hmac.compare_digest(_code(key, counter + o), token) for o in range(-window, window + 1))
    except Exception:
        return False


def get_totp_uri(username, secret, issuer="EMredius"):
    label = urllib.parse.quote(f"{issuer}:{username}")
    iss = urllib.parse.quote(issuer)
    return f"otpauth://totp/{label}?secret={secret}&issuer={iss}&algorithm=SHA1&digits=6&period=30"
