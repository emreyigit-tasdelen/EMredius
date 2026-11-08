# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""RFC 8907 TACACS+ packet header and body codecs, serialization, and AV-pair parser."""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
from typing import Any, List, Optional, Union

# Protocol Versions
TAC_PLUS_MAJOR_VER = 0x0C          # 12
TAC_PLUS_MINOR_VER_DEFAULT = 0x00  # 0 (ASCII, Author, Acct)
TAC_PLUS_MINOR_VER_ONE = 0x01      # 1 (PAP, CHAP, MS-CHAP)

# Packet Types
TAC_PLUS_AUTHEN = 0x01
TAC_PLUS_AUTHOR = 0x02
TAC_PLUS_ACCT   = 0x03

# Header Flags
TAC_PLUS_UNENCRYPTED_FLAG    = 0x01
TAC_PLUS_SINGLE_CONNECT_FLAG = 0x04

# Authentication Actions
TAC_PLUS_AUTHEN_LOGIN    = 0x01
TAC_PLUS_AUTHEN_CHPASS   = 0x02
TAC_PLUS_AUTHEN_SENDAUTH = 0x04

# Authentication Types
TAC_PLUS_AUTHEN_TYPE_ASCII    = 0x01
TAC_PLUS_AUTHEN_TYPE_PAP      = 0x02
TAC_PLUS_AUTHEN_TYPE_CHAP     = 0x03
TAC_PLUS_AUTHEN_TYPE_ARAP     = 0x04
TAC_PLUS_AUTHEN_TYPE_MSCHAP   = 0x05
TAC_PLUS_AUTHEN_TYPE_MSCHAPV2 = 0x06

# Authentication Services
TAC_PLUS_AUTHEN_SVC_NONE    = 0x00
TAC_PLUS_AUTHEN_SVC_LOGIN   = 0x01
TAC_PLUS_AUTHEN_SVC_ENABLE  = 0x02
TAC_PLUS_AUTHEN_SVC_PPP     = 0x03
TAC_PLUS_AUTHEN_SVC_PT      = 0x04
TAC_PLUS_AUTHEN_SVC_RCMD    = 0x05
TAC_PLUS_AUTHEN_SVC_X25     = 0x06
TAC_PLUS_AUTHEN_SVC_NASI    = 0x07
TAC_PLUS_AUTHEN_SVC_FWPROXY = 0x08

# Authentication Status (REPLY)
TAC_PLUS_AUTHEN_STATUS_PASS    = 0x01
TAC_PLUS_AUTHEN_STATUS_FAIL    = 0x02
TAC_PLUS_AUTHEN_STATUS_GETDATA = 0x03
TAC_PLUS_AUTHEN_STATUS_GETUSER = 0x04
TAC_PLUS_AUTHEN_STATUS_GETPASS = 0x05
TAC_PLUS_AUTHEN_STATUS_RESTART = 0x06
TAC_PLUS_AUTHEN_STATUS_ERROR   = 0x07

# Authentication Reply Flags
TAC_PLUS_REPLY_FLAG_NOECHO = 0x01

# Authentication Continue Flags
TAC_PLUS_CONTINUE_FLAG_ABORT = 0x01

# Authorization Methods
TAC_PLUS_AUTHEN_METH_NOT_SET    = 0x01
TAC_PLUS_AUTHEN_METH_NONE       = 0x02
TAC_PLUS_AUTHEN_METH_KRB5       = 0x03
TAC_PLUS_AUTHEN_METH_LINE       = 0x04
TAC_PLUS_AUTHEN_METH_ENABLE     = 0x05
TAC_PLUS_AUTHEN_METH_LOCAL      = 0x06
TAC_PLUS_AUTHEN_METH_TACACSPLUS = 0x07
TAC_PLUS_AUTHEN_METH_GUEST      = 0x08
TAC_PLUS_AUTHEN_METH_RADIUS     = 0x09

# Authorization Status (REPLY)
TAC_PLUS_AUTHOR_STATUS_PASS_ADD  = 0x01
TAC_PLUS_AUTHOR_STATUS_PASS_REPL = 0x02
TAC_PLUS_AUTHOR_STATUS_FAIL      = 0x10
TAC_PLUS_AUTHOR_STATUS_ERROR     = 0x11
TAC_PLUS_AUTHOR_STATUS_FOLLOW    = 0x21

# Accounting Flags (REQUEST)
TAC_PLUS_ACCT_FLAG_START    = 0x02
TAC_PLUS_ACCT_FLAG_STOP     = 0x04
TAC_PLUS_ACCT_FLAG_WATCHDOG = 0x08

# Accounting Status (REPLY)
TAC_PLUS_ACCT_STATUS_SUCCESS = 0x01
TAC_PLUS_ACCT_STATUS_ERROR   = 0x02
TAC_PLUS_ACCT_STATUS_FOLLOW  = 0x21


class TacacsHeader:
    """RFC 8907 12-byte big-endian packet header."""

    def __init__(
        self,
        major_version: int = TAC_PLUS_MAJOR_VER,
        minor_version: int = TAC_PLUS_MINOR_VER_DEFAULT,
        type: int = TAC_PLUS_AUTHEN,
        seq_no: int = 1,
        flags: int = 0,
        session_id: int = 0,
        length: int = 0,
        major_ver: Optional[int] = None,
        minor_ver: Optional[int] = None,
        packet_type: Optional[int] = None,
    ):
        self.major_version = major_ver if major_ver is not None else major_version
        self.minor_version = minor_ver if minor_ver is not None else minor_version
        self.type = packet_type if packet_type is not None else type
        self.seq_no = seq_no
        self.flags = flags
        self.session_id = session_id
        self.length = length

    @property
    def major_ver(self) -> int:
        return self.major_version

    @major_ver.setter
    def major_ver(self, val: int) -> None:
        self.major_version = val

    @property
    def minor_ver(self) -> int:
        return self.minor_version

    @minor_ver.setter
    def minor_ver(self, val: int) -> None:
        self.minor_version = val

    @property
    def packet_type(self) -> int:
        return self.type

    @packet_type.setter
    def packet_type(self, val: int) -> None:
        self.type = val

    @property
    def raw_version(self) -> int:
        return ((self.major_version & 0x0F) << 4) | (self.minor_version & 0x0F)

    def pack(self) -> bytes:
        return struct.pack(
            ">BBBBII",
            self.raw_version,
            self.type,
            self.seq_no,
            self.flags,
            self.session_id,
            self.length,
        )

    def to_bytes(self) -> bytes:
        return self.pack()

    @classmethod
    def from_bytes(cls, data: bytes) -> "TacacsHeader":
        if len(data) < 12:
            raise ValueError(f"Header requires 12 bytes, received {len(data)}")
        raw_ver, p_type, seq_no, flags, sess_id, length = struct.unpack(">BBBBII", data[:12])
        major_ver = (raw_ver >> 4) & 0x0F
        minor_ver = raw_ver & 0x0F
        return cls(
            major_version=major_ver,
            minor_version=minor_ver,
            type=p_type,
            seq_no=seq_no,
            flags=flags,
            session_id=sess_id,
            length=length,
        )

    def __repr__(self) -> str:
        return (
            f"TacacsHeader(ver={self.major_version}.{self.minor_version}, "
            f"type={self.type}, seq={self.seq_no}, flags=0x{self.flags:02x}, "
            f"session_id=0x{self.session_id:08x}, len={self.length})"
        )


def unpack_header(data: bytes) -> TacacsHeader:
    """Helper function to unpack 12-byte TACACS+ header."""
    return TacacsHeader.from_bytes(data)


@dataclass
class AVPair:
    """RFC 8907 Attribute-Value Pair with mandatory (=) or optional (*) separator."""

    name: str
    separator: str  # '=' or '*'
    value: str
    mandatory: bool = True

    @property
    def is_mandatory(self) -> bool:
        return self.separator == "="

    @classmethod
    def parse(cls, raw: Union[bytes, str]) -> "AVPair":
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", errors="replace")
        else:
            text = raw

        idx_eq = text.find("=")
        idx_star = text.find("*")

        if idx_eq != -1 and (idx_star == -1 or idx_eq < idx_star):
            return cls(name=text[:idx_eq], separator="=", value=text[idx_eq + 1:], mandatory=True)
        elif idx_star != -1 and (idx_eq == -1 or idx_star < idx_eq):
            return cls(name=text[:idx_star], separator="*", value=text[idx_star + 1:], mandatory=False)
        else:
            # Fallback for bare attributes without separator
            return cls(name=text, separator="*", value="", mandatory=False)

    def to_bytes(self) -> bytes:
        return f"{self.name}{self.separator}{self.value}".encode("utf-8")

    def encode(self) -> bytes:
        return self.to_bytes()

    def __repr__(self) -> str:
        return f"AVPair({self.name}{self.separator}{self.value})"


@dataclass
class AuthenStart:
    """Authentication START body (RFC 8907 §5.1)."""

    action: int = TAC_PLUS_AUTHEN_LOGIN
    priv_lvl: int = 1
    authen_type: int = TAC_PLUS_AUTHEN_TYPE_ASCII
    authen_service: int = TAC_PLUS_AUTHEN_SVC_LOGIN
    user: str = ""
    port: str = ""
    rem_addr: str = ""
    data: bytes = b""

    @classmethod
    def unpack(cls, body: bytes) -> "AuthenStart":
        if len(body) < 8:
            raise ValueError(f"AuthenStart body too short: {len(body)} < 8")
        action, priv_lvl, atype, asvc, ulen, plen, rlen, dlen = struct.unpack(">BBBBBBBB", body[:8])
        expected_len = 8 + ulen + plen + rlen + dlen
        if len(body) < expected_len:
            raise ValueError(f"AuthenStart payload truncated: {len(body)} < {expected_len}")
        offset = 8
        user = body[offset:offset + ulen].decode("utf-8", errors="replace"); offset += ulen
        port = body[offset:offset + plen].decode("utf-8", errors="replace"); offset += plen
        rem_addr = body[offset:offset + rlen].decode("utf-8", errors="replace"); offset += rlen
        data = body[offset:offset + dlen]
        return cls(action, priv_lvl, atype, asvc, user, port, rem_addr, data)

    def pack(self) -> bytes:
        u_bytes = self.user.encode("utf-8")
        p_bytes = self.port.encode("utf-8")
        r_bytes = self.rem_addr.encode("utf-8")
        hdr = struct.pack(
            ">BBBBBBBB",
            self.action,
            self.priv_lvl,
            self.authen_type,
            self.authen_service,
            len(u_bytes),
            len(p_bytes),
            len(r_bytes),
            len(self.data),
        )
        return hdr + u_bytes + p_bytes + r_bytes + self.data


@dataclass
class AuthenReply:
    """Authentication REPLY body (RFC 8907 §5.3)."""

    status: int = TAC_PLUS_AUTHEN_STATUS_FAIL
    flags: int = 0
    server_msg: str = ""
    data: bytes = b""

    @classmethod
    def unpack(cls, body: bytes) -> "AuthenReply":
        if len(body) < 6:
            raise ValueError(f"AuthenReply body too short: {len(body)} < 6")
        status, flags, smlen, dlen = struct.unpack(">BBHH", body[:6])
        expected_len = 6 + smlen + dlen
        if len(body) < expected_len:
            raise ValueError(f"AuthenReply payload truncated: {len(body)} < {expected_len}")
        offset = 6
        server_msg = body[offset:offset + smlen].decode("utf-8", errors="replace"); offset += smlen
        data = body[offset:offset + dlen]
        return cls(status, flags, server_msg, data)

    def pack(self) -> bytes:
        s_bytes = self.server_msg.encode("utf-8")
        hdr = struct.pack(">BBHH", self.status, self.flags, len(s_bytes), len(self.data))
        return hdr + s_bytes + self.data


@dataclass
class AuthenContinue:
    """Authentication CONTINUE body (RFC 8907 §5.2)."""

    user_msg: str = ""
    data: bytes = b""
    flags: int = 0

    @classmethod
    def unpack(cls, body: bytes) -> "AuthenContinue":
        if len(body) < 5:
            raise ValueError(f"AuthenContinue body too short: {len(body)} < 5")
        umlen, dlen, flags = struct.unpack(">HHB", body[:5])
        expected_len = 5 + umlen + dlen
        if len(body) < expected_len:
            raise ValueError(f"AuthenContinue payload truncated: {len(body)} < {expected_len}")
        offset = 5
        user_msg = body[offset:offset + umlen].decode("utf-8", errors="replace"); offset += umlen
        data = body[offset:offset + dlen]
        return cls(user_msg, data, flags)

    def pack(self) -> bytes:
        u_bytes = self.user_msg.encode("utf-8")
        hdr = struct.pack(">HHB", len(u_bytes), len(self.data), self.flags)
        return hdr + u_bytes + self.data


@dataclass
class AuthorRequest:
    """Authorization REQUEST body (RFC 8907 §6.1)."""

    authen_method: int = TAC_PLUS_AUTHEN_METH_TACACSPLUS
    priv_lvl: int = 1
    authen_type: int = TAC_PLUS_AUTHEN_TYPE_ASCII
    authen_service: int = TAC_PLUS_AUTHEN_SVC_LOGIN
    user: str = ""
    port: str = ""
    rem_addr: str = ""
    args: List[AVPair] = field(default_factory=list)

    @classmethod
    def unpack(cls, body: bytes) -> "AuthorRequest":
        if len(body) < 8:
            raise ValueError(f"AuthorRequest body too short: {len(body)} < 8")
        ameth, priv, atype, asvc, ulen, plen, rlen, arg_cnt = struct.unpack(">BBBBBBBB", body[:8])
        if len(body) < 8 + arg_cnt:
            raise ValueError("AuthorRequest arg lengths truncated")
        arg_lens = list(body[8:8 + arg_cnt])
        expected_len = 8 + arg_cnt + ulen + plen + rlen + sum(arg_lens)
        if len(body) < expected_len:
            raise ValueError(f"AuthorRequest body truncated: {len(body)} < {expected_len}")
        offset = 8 + arg_cnt
        user = body[offset:offset + ulen].decode("utf-8", errors="replace"); offset += ulen
        port = body[offset:offset + plen].decode("utf-8", errors="replace"); offset += plen
        rem_addr = body[offset:offset + rlen].decode("utf-8", errors="replace"); offset += rlen
        args: List[AVPair] = []
        for alen in arg_lens:
            arg_raw = body[offset:offset + alen]
            args.append(AVPair.parse(arg_raw))
            offset += alen
        return cls(ameth, priv, atype, asvc, user, port, rem_addr, args)

    def pack(self) -> bytes:
        u_bytes = self.user.encode("utf-8")
        p_bytes = self.port.encode("utf-8")
        r_bytes = self.rem_addr.encode("utf-8")
        arg_byte_list = [a.to_bytes() for a in self.args]
        arg_cnt = len(arg_byte_list)
        hdr = struct.pack(
            ">BBBBBBBB",
            self.authen_method,
            self.priv_lvl,
            self.authen_type,
            self.authen_service,
            len(u_bytes),
            len(p_bytes),
            len(r_bytes),
            arg_cnt,
        )
        lens = bytes([len(b) for b in arg_byte_list])
        return hdr + lens + u_bytes + p_bytes + r_bytes + b"".join(arg_byte_list)


@dataclass
class AuthorReply:
    """Authorization REPLY body (RFC 8907 §6.2)."""

    status: int = TAC_PLUS_AUTHOR_STATUS_FAIL
    server_msg: str = ""
    data: bytes = b""
    args: List[AVPair] = field(default_factory=list)

    @classmethod
    def unpack(cls, body: bytes) -> "AuthorReply":
        if len(body) < 6:
            raise ValueError(f"AuthorReply body too short: {len(body)} < 6")
        status, arg_cnt, smlen, dlen = struct.unpack(">BBHH", body[:6])
        if len(body) < 6 + arg_cnt:
            raise ValueError("AuthorReply arg lengths truncated")
        arg_lens = list(body[6:6 + arg_cnt])
        expected_len = 6 + arg_cnt + smlen + dlen + sum(arg_lens)
        if len(body) < expected_len:
            raise ValueError(f"AuthorReply body truncated: {len(body)} < {expected_len}")
        offset = 6 + arg_cnt
        server_msg = body[offset:offset + smlen].decode("utf-8", errors="replace"); offset += smlen
        data = body[offset:offset + dlen]; offset += dlen
        args: List[AVPair] = []
        for alen in arg_lens:
            arg_raw = body[offset:offset + alen]
            args.append(AVPair.parse(arg_raw))
            offset += alen
        return cls(status, server_msg, data, args)

    def pack(self) -> bytes:
        s_bytes = self.server_msg.encode("utf-8")
        arg_byte_list = [a.to_bytes() for a in self.args]
        arg_cnt = len(arg_byte_list)
        hdr = struct.pack(">BBHH", self.status, arg_cnt, len(s_bytes), len(self.data))
        lens = bytes([len(b) for b in arg_byte_list])
        return hdr + lens + s_bytes + self.data + b"".join(arg_byte_list)


@dataclass
class AcctRequest:
    """Accounting REQUEST body (RFC 8907 §7.1)."""

    flags: int = TAC_PLUS_ACCT_FLAG_START
    authen_method: int = TAC_PLUS_AUTHEN_METH_TACACSPLUS
    priv_lvl: int = 1
    authen_type: int = TAC_PLUS_AUTHEN_TYPE_ASCII
    authen_service: int = TAC_PLUS_AUTHEN_SVC_LOGIN
    user: str = ""
    port: str = ""
    rem_addr: str = ""
    args: List[AVPair] = field(default_factory=list)

    @classmethod
    def unpack(cls, body: bytes) -> "AcctRequest":
        if len(body) < 9:
            raise ValueError(f"AcctRequest body too short: {len(body)} < 9")
        flags, ameth, priv, atype, asvc, ulen, plen, rlen, arg_cnt = struct.unpack(">BBBBBBBBB", body[:9])
        if len(body) < 9 + arg_cnt:
            raise ValueError("AcctRequest arg lengths truncated")
        arg_lens = list(body[9:9 + arg_cnt])
        expected_len = 9 + arg_cnt + ulen + plen + rlen + sum(arg_lens)
        if len(body) < expected_len:
            raise ValueError(f"AcctRequest body truncated: {len(body)} < {expected_len}")
        offset = 9 + arg_cnt
        user = body[offset:offset + ulen].decode("utf-8", errors="replace"); offset += ulen
        port = body[offset:offset + plen].decode("utf-8", errors="replace"); offset += plen
        rem_addr = body[offset:offset + rlen].decode("utf-8", errors="replace"); offset += rlen
        args: List[AVPair] = []
        for alen in arg_lens:
            arg_raw = body[offset:offset + alen]
            args.append(AVPair.parse(arg_raw))
            offset += alen
        return cls(flags, ameth, priv, atype, asvc, user, port, rem_addr, args)

    def pack(self) -> bytes:
        u_bytes = self.user.encode("utf-8")
        p_bytes = self.port.encode("utf-8")
        r_bytes = self.rem_addr.encode("utf-8")
        arg_byte_list = [a.to_bytes() for a in self.args]
        arg_cnt = len(arg_byte_list)
        hdr = struct.pack(
            ">BBBBBBBBB",
            self.flags,
            self.authen_method,
            self.priv_lvl,
            self.authen_type,
            self.authen_service,
            len(u_bytes),
            len(p_bytes),
            len(r_bytes),
            arg_cnt,
        )
        lens = bytes([len(b) for b in arg_byte_list])
        return hdr + lens + u_bytes + p_bytes + r_bytes + b"".join(arg_byte_list)


@dataclass
class AcctReply:
    """Accounting REPLY body (RFC 8907 §7.2)."""

    status: int = TAC_PLUS_ACCT_STATUS_SUCCESS
    server_msg: str = ""
    data: bytes = b""

    @classmethod
    def unpack(cls, body: bytes) -> "AcctReply":
        if len(body) < 5:
            raise ValueError(f"AcctReply body too short: {len(body)} < 5")
        smlen, dlen, status = struct.unpack(">HHB", body[:5])
        expected_len = 5 + smlen + dlen
        if len(body) < expected_len:
            raise ValueError(f"AcctReply payload truncated: {len(body)} < {expected_len}")
        offset = 5
        server_msg = body[offset:offset + smlen].decode("utf-8", errors="replace"); offset += smlen
        data = body[offset:offset + dlen]
        return cls(status, server_msg, data)

    def pack(self) -> bytes:
        s_bytes = self.server_msg.encode("utf-8")
        hdr = struct.pack(">HHB", len(s_bytes), len(self.data), self.status)
        return hdr + s_bytes + self.data


# Type aliases
AuthenStartPacket = AuthenStart
AuthenReplyPacket = AuthenReply
AuthenContinuePacket = AuthenContinue
AuthorRequestPacket = AuthorRequest
AuthorReplyPacket = AuthorReply
AcctRequestPacket = AcctRequest
AcctReplyPacket = AcctReply


def pack_authen_reply(status: int, flags: int = 0, server_msg: str = "", data: bytes = b"") -> bytes:
    """Convenience helper to pack AuthenReply."""
    return AuthenReply(status=status, flags=flags, server_msg=server_msg, data=data).pack()


def pack_author_reply(status: int, server_msg: str = "", data: bytes = b"", args: Optional[List[AVPair]] = None) -> bytes:
    """Convenience helper to pack AuthorReply."""
    return AuthorReply(status=status, server_msg=server_msg, data=data, args=args or []).pack()


pack_author_response = pack_author_reply


def pack_acct_reply(status: int, server_msg: str = "", data: bytes = b"") -> bytes:
    """Convenience helper to pack AcctReply."""
    return AcctReply(status=status, server_msg=server_msg, data=data).pack()


pack_acct_response = pack_acct_reply
