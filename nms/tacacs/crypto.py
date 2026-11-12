# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: AGPL-3.0-only
"""RFC 8907 §4.5 MD5 pseudo-random pad derivation, XOR masking, and payload integrity checking."""

from __future__ import annotations

import hashlib
import struct
from typing import Optional, Union

from nms.tacacs.codec import (
    TAC_PLUS_ACCT,
    TAC_PLUS_AUTHEN,
    TAC_PLUS_AUTHOR,
    TAC_PLUS_UNENCRYPTED_FLAG,
    TacacsHeader,
)


def generate_pad(
    session_id: int,
    key: Union[str, bytes],
    version: int,
    seq_no: int,
    length: int,
) -> bytes:
    """Generates RFC 8907 §4.5 pseudo-random MD5 pad using iterative hash chaining."""
    if length <= 0:
        return b""

    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    sess_bytes = struct.pack(">I", session_id)
    ver_bytes = struct.pack("B", version)
    seq_bytes = struct.pack("B", seq_no)
    prefix = sess_bytes + key_bytes + ver_bytes + seq_bytes

    pad = bytearray()
    prev_hash = b""
    while len(pad) < length:
        md5 = hashlib.md5(prefix + prev_hash)
        prev_hash = md5.digest()
        pad.extend(prev_hash)

    return bytes(pad[:length])


def generate_md5_pad(
    header_or_sess_id: Union[TacacsHeader, int],
    secret: Union[str, bytes],
    length: int,
    version: Optional[int] = None,
    seq_no: Optional[int] = None,
) -> bytes:
    """Convenience wrapper for generate_pad supporting TacacsHeader or raw parameters."""
    if isinstance(header_or_sess_id, TacacsHeader):
        return generate_pad(
            session_id=header_or_sess_id.session_id,
            key=secret,
            version=header_or_sess_id.raw_version,
            seq_no=header_or_sess_id.seq_no,
            length=length,
        )
    return generate_pad(
        session_id=header_or_sess_id,
        key=secret,
        version=version if version is not None else 0xC0,
        seq_no=seq_no if seq_no is not None else 1,
        length=length,
    )


def xor_bytes(data: bytes, pad: bytes) -> bytes:
    """Symmetric bitwise XOR stream masking."""
    return bytes(b ^ p for b, p in zip(data, pad))


def encrypt_body(
    header: TacacsHeader,
    plain_body: bytes,
    secret: Union[str, bytes],
) -> bytes:
    """Obfuscates packet body using RFC 8907 MD5 pad."""
    if header.flags & TAC_PLUS_UNENCRYPTED_FLAG:
        return plain_body
    pad = generate_pad(
        session_id=header.session_id,
        key=secret,
        version=header.raw_version,
        seq_no=header.seq_no,
        length=len(plain_body),
    )
    return xor_bytes(plain_body, pad)


obfuscate_body = encrypt_body


def decrypt_body(
    header: TacacsHeader,
    encrypted_body: bytes,
    secret: Union[str, bytes],
) -> Optional[bytes]:
    """Deobfuscates packet body and validates body integrity against header.length."""
    if header.flags & TAC_PLUS_UNENCRYPTED_FLAG:
        return encrypted_body if validate_body_integrity(header, encrypted_body) else None

    pad = generate_pad(
        session_id=header.session_id,
        key=secret,
        version=header.raw_version,
        seq_no=header.seq_no,
        length=len(encrypted_body),
    )
    plain_body = xor_bytes(encrypted_body, pad)
    if not validate_body_integrity(header, plain_body):
        return None
    return plain_body


def deobfuscate_body(
    header: TacacsHeader,
    secret: Union[str, bytes],
    encrypted_body: bytes,
) -> bytes:
    """Deobfuscates body without dropping on integrity failure (for raw tests)."""
    if header.flags & TAC_PLUS_UNENCRYPTED_FLAG:
        return encrypted_body
    pad = generate_pad(
        session_id=header.session_id,
        key=secret,
        version=header.raw_version,
        seq_no=header.seq_no,
        length=len(encrypted_body),
    )
    return xor_bytes(encrypted_body, pad)


def validate_body_integrity(header: TacacsHeader, body: bytes) -> bool:
    """Validates that internal subfield length headers sum up exactly to header.length."""
    if len(body) != header.length:
        return False

    # Empty payload is valid if header length is 0
    if header.length == 0:
        return True

    p_type = header.type
    seq = header.seq_no

    try:
        if p_type == TAC_PLUS_AUTHEN:
            if seq == 1:  # Authen START
                if len(body) < 8:
                    return False
                action, priv, atype, asvc, ulen, plen, rlen, dlen = struct.unpack(">BBBBBBBB", body[:8])
                return (8 + ulen + plen + rlen + dlen) == header.length
            elif seq % 2 == 0:  # Authen REPLY (seq 2, 4...)
                if len(body) < 6:
                    return False
                status, flags, smlen, dlen = struct.unpack(">BBHH", body[:6])
                return (6 + smlen + dlen) == header.length
            else:  # Authen CONTINUE (seq 3, 5...)
                if len(body) < 5:
                    return False
                umlen, dlen, flags = struct.unpack(">HHB", body[:5])
                return (5 + umlen + dlen) == header.length

        elif p_type == TAC_PLUS_AUTHOR:
            if seq == 1:  # Author REQUEST
                if len(body) < 8:
                    return False
                ameth, priv, atype, asvc, ulen, plen, rlen, arg_cnt = struct.unpack(">BBBBBBBB", body[:8])
                if len(body) < 8 + arg_cnt:
                    return False
                arg_lens = list(body[8:8 + arg_cnt])
                return (8 + arg_cnt + sum(arg_lens) + ulen + plen + rlen) == header.length
            elif seq == 2:  # Author REPLY
                if len(body) < 6:
                    return False
                status, arg_cnt, smlen, dlen = struct.unpack(">BBHH", body[:6])
                if len(body) < 6 + arg_cnt:
                    return False
                arg_lens = list(body[6:6 + arg_cnt])
                return (6 + arg_cnt + sum(arg_lens) + smlen + dlen) == header.length

        elif p_type == TAC_PLUS_ACCT:
            if seq == 1:  # Acct REQUEST
                if len(body) < 9:
                    return False
                flags, ameth, priv, atype, asvc, ulen, plen, rlen, arg_cnt = struct.unpack(">BBBBBBBBB", body[:9])
                if len(body) < 9 + arg_cnt:
                    return False
                arg_lens = list(body[9:9 + arg_cnt])
                return (9 + arg_cnt + sum(arg_lens) + ulen + plen + rlen) == header.length
            elif seq == 2:  # Acct REPLY
                if len(body) < 5:
                    return False
                smlen, dlen, status = struct.unpack(">HHB", body[:5])
                return (5 + smlen + dlen) == header.length

    except (struct.error, IndexError):
        return False

    return False
