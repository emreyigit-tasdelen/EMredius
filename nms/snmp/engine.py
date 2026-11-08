# Copyright (c) 2026 Emre Yiğit Taşdelen
# SPDX-License-Identifier: Apache-2.0
"""Universal SNMPv2c / SNMPv3 USM Client Engine, Pure-Python ASN.1 BER Codec,
Cryptographic Subsystem (DES, AES-128/192/256-CFB, MD5, SHA-1/224/256),
Dynamic EngineID Discovery, and Asyncio UDP Networking.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import hmac
import logging
import os
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:
    from cryptography.hazmat.primitives.ciphers.modes import CFB
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.modes import CBC

logger = logging.getLogger("snmp.engine")


class Asn1Tag:
    """ASN.1 and SNMP BER Tag Definitions."""
    INTEGER = 0x02
    BIT_STRING = 0x03
    OCTET_STRING = 0x04
    NULL = 0x05
    OBJECT_IDENTIFIER = 0x06
    SEQUENCE = 0x30

    # SNMP Application Types
    IP_ADDRESS = 0x40        # [APPLICATION 0]
    COUNTER32 = 0x41         # [APPLICATION 1]
    GAUGE32 = 0x42           # [APPLICATION 2]
    TIMETICKS = 0x43         # [APPLICATION 3]
    OPAQUE = 0x44            # [APPLICATION 4]
    COUNTER64 = 0x46         # [APPLICATION 6]

    # SNMP VarBind Exception Types (RFC 1905)
    NO_SUCH_OBJECT = 0x80    # [CONTEXT 0] primitive
    NO_SUCH_INSTANCE = 0x81  # [CONTEXT 1] primitive
    END_OF_MIB_VIEW = 0x82   # [CONTEXT 2] primitive

    # SNMP PDU Types (Context Constructed)
    GET_REQUEST = 0xA0       # [CONTEXT 0] constructed
    GET_NEXT_REQUEST = 0xA1  # [CONTEXT 1] constructed
    RESPONSE = 0xA2          # [CONTEXT 2] constructed
    SET_REQUEST = 0xA3       # [CONTEXT 3] constructed
    GET_BULK_REQUEST = 0xA5  # [CONTEXT 5] constructed
    INFORM_REQUEST = 0xA6    # [CONTEXT 6] constructed
    SNMPV2_TRAP = 0xA7       # [CONTEXT 7] constructed
    REPORT = 0xA8            # [CONTEXT 8] constructed


# Error Status Mapping (RFC 1905)
ERROR_STATUS_NAMES = {
    0: "noError",
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError",
    17: "notWritable",
    18: "inconsistentName",
}


@dataclass
class VarBind:
    """SNMP Variable Binding."""
    oid: str
    value: Any = None
    tag: Optional[int] = None

    def __iter__(self) -> Iterator[Any]:
        yield self.oid
        yield self.value

    def __getitem__(self, idx: int) -> Any:
        if idx == 0:
            return self.oid
        elif idx == 1:
            return self.value
        raise IndexError("VarBind index out of range (0=oid, 1=value)")


@dataclass
class Pdu:
    """SNMP Protocol Data Unit (PDU)."""
    pdu_type: int
    request_id: int
    error_status: int = 0
    error_index: int = 0
    non_repeaters: int = 0
    max_repetitions: int = 0
    varbinds: List[VarBind] = field(default_factory=list)


@dataclass
class SnmpResponse:
    """SNMP Operation Response with dictionary-like access."""
    request_id: int
    error_status: int = 0
    error_index: int = 0
    varbinds: List[VarBind] = field(default_factory=list)
    error_description: str = ""
    is_error: bool = False

    def _clean_oid(self, oid: str) -> str:
        return oid.lstrip(".")

    def __getitem__(self, oid: str) -> Any:
        clean = self._clean_oid(oid)
        for vb in self.varbinds:
            if self._clean_oid(vb.oid) == clean:
                return vb.value
        raise KeyError(oid)

    def get(self, oid: str, default: Any = None) -> Any:
        clean = self._clean_oid(oid)
        for vb in self.varbinds:
            if self._clean_oid(vb.oid) == clean:
                return vb.value
        return default

    def __contains__(self, oid: str) -> bool:
        clean = self._clean_oid(oid)
        return any(self._clean_oid(vb.oid) == clean for vb in self.varbinds)

    def keys(self) -> List[str]:
        return [vb.oid for vb in self.varbinds]

    def values(self) -> List[Any]:
        return [vb.value for vb in self.varbinds]

    def items(self) -> List[Tuple[str, Any]]:
        return [(vb.oid, vb.value) for vb in self.varbinds]

    def __bool__(self) -> bool:
        return not self.is_error and len(self.varbinds) > 0


@dataclass
class SnmpV3Credentials:
    """SNMPv3 USM Security Configuration."""
    username: str
    auth_protocol: Optional[str] = None  # 'MD5', 'SHA', 'SHA1', 'SHA224', 'SHA256'
    auth_password: Optional[str] = None
    priv_protocol: Optional[str] = None  # 'DES', 'AES', 'AES128', 'AES192', 'AES256'
    priv_password: Optional[str] = None
    context_name: str = ""
    engine_id: Optional[bytes] = None


# =====================================================================
# ASN.1 BER Codec
# =====================================================================

class Asn1Codec:
    """Pure-Python ASN.1 Basic Encoding Rules (BER) Serializer and Parser."""

    @staticmethod
    def encode_length(length: int) -> bytes:
        if length < 128:
            return bytes([length])
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(length_bytes)]) + length_bytes

    @staticmethod
    def decode_length(data: bytes, offset: int) -> Tuple[int, int]:
        if offset >= len(data):
            raise ValueError(f"Length offset {offset} out of bounds for buffer of size {len(data)}")
        first = data[offset]
        if first < 128:
            return first, offset + 1
        num_octets = first & 0x7F
        if offset + 1 + num_octets > len(data):
            raise ValueError(f"Length field exceeds buffer size at offset {offset}")
        length = int.from_bytes(data[offset + 1 : offset + 1 + num_octets], "big")
        return length, offset + 1 + num_octets

    @staticmethod
    def encode_integer(value: int, tag: int = Asn1Tag.INTEGER) -> bytes:
        if value == 0:
            val_bytes = b"\x00"
        elif value > 0:
            byte_len = (value.bit_length() + 7) // 8
            val_bytes = value.to_bytes(byte_len, "big")
            if val_bytes[0] & 0x80:
                val_bytes = b"\x00" + val_bytes
        else:
            byte_len = (value.bit_length() + 8) // 8
            val_bytes = value.to_bytes(byte_len, "big", signed=True)
        return bytes([tag]) + Asn1Codec.encode_length(len(val_bytes)) + val_bytes

    @staticmethod
    def encode_unsigned(value: int, tag: int) -> bytes:
        val = int(value)
        if tag == Asn1Tag.COUNTER64:
            val &= 0xFFFFFFFFFFFFFFFF
        else:
            val &= 0xFFFFFFFF
        if val == 0:
            val_bytes = b"\x00"
        else:
            byte_len = (val.bit_length() + 7) // 8
            val_bytes = val.to_bytes(byte_len, "big")
            if val_bytes[0] & 0x80:
                val_bytes = b"\x00" + val_bytes
        return bytes([tag]) + Asn1Codec.encode_length(len(val_bytes)) + val_bytes

    @staticmethod
    def encode_octet_string(val: Union[bytes, str], tag: int = Asn1Tag.OCTET_STRING) -> bytes:
        if isinstance(val, str):
            val_bytes = val.encode("utf-8")
        else:
            val_bytes = bytes(val)
        return bytes([tag]) + Asn1Codec.encode_length(len(val_bytes)) + val_bytes

    @staticmethod
    def encode_null(tag: int = Asn1Tag.NULL) -> bytes:
        return bytes([tag, 0x00])

    @staticmethod
    def encode_oid(oid_str: str, tag: int = Asn1Tag.OBJECT_IDENTIFIER) -> bytes:
        subids = [int(p) for p in oid_str.strip().lstrip(".").split(".") if p]
        if len(subids) < 2:
            return bytes([tag, 0x00])
        first_byte = subids[0] * 40 + subids[1]
        encoded = bytearray([first_byte])
        for subid in subids[2:]:
            if subid == 0:
                encoded.append(0)
            else:
                parts = []
                n = subid
                while n > 0:
                    parts.append(n & 0x7F)
                    n >>= 7
                parts.reverse()
                for i in range(len(parts) - 1):
                    encoded.append(parts[i] | 0x80)
                encoded.append(parts[-1])
        return bytes([tag]) + Asn1Codec.encode_length(len(encoded)) + bytes(encoded)

    @staticmethod
    def decode_oid(data: bytes) -> str:
        if len(data) == 0:
            return ""
        first = data[0]
        s0 = first // 40
        s1 = first % 40
        subids = [s0, s1]
        curr = 0
        for b in data[1:]:
            curr = (curr << 7) | (b & 0x7F)
            if not (b & 0x80):
                subids.append(curr)
                curr = 0
        return ".".join(str(s) for s in subids)

    @staticmethod
    def encode_sequence(content: bytes, tag: int = Asn1Tag.SEQUENCE) -> bytes:
        return bytes([tag]) + Asn1Codec.encode_length(len(content)) + content

    @staticmethod
    def encode_value(val: Any, tag: Optional[int] = None) -> bytes:
        if val is None:
            actual_tag = tag if tag is not None else Asn1Tag.NULL
            return bytes([actual_tag, 0x00])

        if tag is not None and tag != Asn1Tag.NULL:
            if tag == Asn1Tag.INTEGER:
                return Asn1Codec.encode_integer(int(val))
            elif tag in (Asn1Tag.COUNTER32, Asn1Tag.GAUGE32, Asn1Tag.TIMETICKS, Asn1Tag.COUNTER64):
                return Asn1Codec.encode_unsigned(int(val), tag)
            elif tag in (Asn1Tag.OCTET_STRING, Asn1Tag.IP_ADDRESS, Asn1Tag.OPAQUE):
                return Asn1Codec.encode_octet_string(val, tag)
            elif tag == Asn1Tag.OBJECT_IDENTIFIER:
                return Asn1Codec.encode_oid(str(val))
            elif tag in (Asn1Tag.NO_SUCH_OBJECT, Asn1Tag.NO_SUCH_INSTANCE, Asn1Tag.END_OF_MIB_VIEW):
                return bytes([tag, 0x00])

        if isinstance(val, bool):
            return Asn1Codec.encode_integer(1 if val else 0)
        elif isinstance(val, int):
            return Asn1Codec.encode_integer(val)
        elif isinstance(val, (bytes, bytearray)):
            return Asn1Codec.encode_octet_string(val)
        elif isinstance(val, str):
            parts = val.split(".")
            if len(parts) >= 2 and all(p.isdigit() for p in parts if p):
                return Asn1Codec.encode_oid(val)
            return Asn1Codec.encode_octet_string(val)
        return Asn1Codec.encode_null()

    @staticmethod
    def decode_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
        if offset >= len(data):
            raise ValueError(f"Offset {offset} beyond data length {len(data)}")
        tag = data[offset]
        length, val_start = Asn1Codec.decode_length(data, offset + 1)
        val_end = val_start + length
        if val_end > len(data):
            raise ValueError(f"TLV value length {length} exceeds buffer size at offset {offset}")
        return tag, data[val_start:val_end], val_end

    @staticmethod
    def decode_value(tag: int, val_bytes: bytes) -> Any:
        if tag == Asn1Tag.INTEGER:
            return int.from_bytes(val_bytes, "big", signed=True)
        elif tag in (Asn1Tag.COUNTER32, Asn1Tag.GAUGE32, Asn1Tag.TIMETICKS):
            return int.from_bytes(val_bytes, "big", signed=False)
        elif tag == Asn1Tag.COUNTER64:
            return int.from_bytes(val_bytes, "big", signed=False)
        elif tag == Asn1Tag.OCTET_STRING:
            try:
                s = val_bytes.decode("utf-8")
                if all(c.isprintable() or c in "\r\n\t" for c in s):
                    return s
            except UnicodeDecodeError:
                pass
            return val_bytes
        elif tag == Asn1Tag.OBJECT_IDENTIFIER:
            return Asn1Codec.decode_oid(val_bytes)
        elif tag == Asn1Tag.IP_ADDRESS:
            if len(val_bytes) == 4:
                return ".".join(str(b) for b in val_bytes)
            return val_bytes
        elif tag == Asn1Tag.NULL:
            return None
        elif tag == Asn1Tag.NO_SUCH_OBJECT:
            return "NO_SUCH_OBJECT"
        elif tag == Asn1Tag.NO_SUCH_INSTANCE:
            return "NO_SUCH_INSTANCE"
        elif tag == Asn1Tag.END_OF_MIB_VIEW:
            return "END_OF_MIB_VIEW"
        return val_bytes

    @staticmethod
    def encode_varbind(vb: VarBind) -> bytes:
        oid_bytes = Asn1Codec.encode_oid(vb.oid)
        val_bytes = Asn1Codec.encode_value(vb.value, vb.tag)
        return Asn1Codec.encode_sequence(oid_bytes + val_bytes)

    @staticmethod
    def decode_varbind(data: bytes, offset: int = 0) -> Tuple[VarBind, int]:
        tag, seq_bytes, next_off = Asn1Codec.decode_tlv(data, offset)
        if tag != Asn1Tag.SEQUENCE:
            raise ValueError(f"Expected SEQUENCE tag 0x30 for VarBind, got {hex(tag)}")
        oid_tag, oid_bytes, val_off = Asn1Codec.decode_tlv(seq_bytes, 0)
        oid = Asn1Codec.decode_oid(oid_bytes)
        val_tag, val_bytes, _ = Asn1Codec.decode_tlv(seq_bytes, val_off)
        val = Asn1Codec.decode_value(val_tag, val_bytes)
        return VarBind(oid=oid, value=val, tag=val_tag), next_off

    @staticmethod
    def encode_varbind_list(varbinds: List[VarBind]) -> bytes:
        vb_bytes = b"".join(Asn1Codec.encode_varbind(vb) for vb in varbinds)
        return Asn1Codec.encode_sequence(vb_bytes)

    @staticmethod
    def decode_varbind_list(data: bytes) -> List[VarBind]:
        varbinds = []
        offset = 0
        while offset < len(data):
            vb, offset = Asn1Codec.decode_varbind(data, offset)
            varbinds.append(vb)
        return varbinds

    @staticmethod
    def encode_pdu(pdu: Pdu) -> bytes:
        fields = bytearray()
        fields.extend(Asn1Codec.encode_integer(pdu.request_id))
        if pdu.pdu_type == Asn1Tag.GET_BULK_REQUEST:
            fields.extend(Asn1Codec.encode_integer(pdu.non_repeaters))
            fields.extend(Asn1Codec.encode_integer(pdu.max_repetitions))
        else:
            fields.extend(Asn1Codec.encode_integer(pdu.error_status))
            fields.extend(Asn1Codec.encode_integer(pdu.error_index))
        fields.extend(Asn1Codec.encode_varbind_list(pdu.varbinds))
        return Asn1Codec.encode_sequence(bytes(fields), tag=pdu.pdu_type)

    @staticmethod
    def decode_pdu(data: bytes, offset: int = 0) -> Tuple[Pdu, int]:
        pdu_type, pdu_bytes, next_off = Asn1Codec.decode_tlv(data, offset)
        off = 0
        _, req_bytes, off = Asn1Codec.decode_tlv(pdu_bytes, off)
        req_id = int.from_bytes(req_bytes, "big", signed=True)

        _, err_bytes, off = Asn1Codec.decode_tlv(pdu_bytes, off)
        err_val = int.from_bytes(err_bytes, "big", signed=True)

        _, idx_bytes, off = Asn1Codec.decode_tlv(pdu_bytes, off)
        idx_val = int.from_bytes(idx_bytes, "big", signed=True)

        _, vblist_bytes, _ = Asn1Codec.decode_tlv(pdu_bytes, off)
        varbinds = Asn1Codec.decode_varbind_list(vblist_bytes)

        if pdu_type == Asn1Tag.GET_BULK_REQUEST:
            return Pdu(
                pdu_type=pdu_type,
                request_id=req_id,
                non_repeaters=err_val,
                max_repetitions=idx_val,
                varbinds=varbinds,
            ), next_off
        else:
            return Pdu(
                pdu_type=pdu_type,
                request_id=req_id,
                error_status=err_val,
                error_index=idx_val,
                varbinds=varbinds,
            ), next_off


# =====================================================================
# SNMPv3 USM Cryptography
# =====================================================================

class UsmCrypto:
    """SNMPv3 USM Authentication and Privacy Cryptographic Engine."""

    @staticmethod
    def password_to_key(password: str, auth_proto: str) -> bytes:
        """Expands password to 1MB buffer and hashes per RFC 3414."""
        if not password:
            raise ValueError("Password must be a non-empty string for USM key derivation")
        pw_bytes = password.encode("utf-8")
        buf_size = 1048576  # 1MB
        buf = (pw_bytes * (buf_size // len(pw_bytes) + 1))[:buf_size]
        algo = auth_proto.upper()
        if algo == "MD5":
            return hashlib.md5(buf).digest()
        elif algo in ("SHA", "SHA1"):
            return hashlib.sha1(buf).digest()
        elif algo == "SHA224":
            return hashlib.sha224(buf).digest()
        elif algo == "SHA256":
            return hashlib.sha256(buf).digest()
        raise ValueError(f"Unsupported auth protocol: {auth_proto}")

    @staticmethod
    def localize_key(master_key: bytes, engine_id: bytes, auth_proto: str) -> bytes:
        """Localizes master key with authoritative EngineID per RFC 3414."""
        algo = auth_proto.upper()
        payload = master_key + engine_id + master_key
        if algo == "MD5":
            return hashlib.md5(payload).digest()
        elif algo in ("SHA", "SHA1"):
            return hashlib.sha1(payload).digest()
        elif algo == "SHA224":
            return hashlib.sha224(payload).digest()
        elif algo == "SHA256":
            return hashlib.sha256(payload).digest()
        raise ValueError(f"Unsupported auth protocol: {auth_proto}")

    @staticmethod
    def derive_priv_key(priv_pw: str, engine_id: bytes, auth_proto: str, priv_proto: str) -> bytes:
        """Derives localized privacy key with algorithm-specific key length and extension."""
        master = UsmCrypto.password_to_key(priv_pw, auth_proto)
        loc = UsmCrypto.localize_key(master, engine_id, auth_proto)
        proto = priv_proto.upper()
        if proto == "DES":
            return loc[:16]  # 8 bytes key + 8 bytes pre-IV
        elif proto in ("AES", "AES128"):
            return loc[:16]
        elif proto == "AES192":
            if len(loc) >= 24:
                return loc[:24]
            # Key extension per RFC 3414 draft / Cisco
            k2 = hashlib.sha1(loc).digest()
            return (loc + k2)[:24]
        elif proto == "AES256":
            if len(loc) >= 32:
                return loc[:32]
            # Key extension
            k2 = hashlib.sha1(loc).digest()
            return (loc + k2)[:32]
        raise ValueError(f"Unsupported priv protocol: {priv_proto}")

    @staticmethod
    def compute_hmac(msg_bytes: bytes, auth_key: bytes, auth_proto: str) -> bytes:
        """Computes truncated HMAC digest per RFC 3414 and RFC 7860."""
        algo = auth_proto.upper()
        if algo == "MD5":
            return hmac.new(auth_key, msg_bytes, hashlib.md5).digest()[:12]
        elif algo in ("SHA", "SHA1"):
            return hmac.new(auth_key, msg_bytes, hashlib.sha1).digest()[:12]
        elif algo == "SHA224":
            return hmac.new(auth_key, msg_bytes, hashlib.sha224).digest()[:16]
        elif algo == "SHA256":
            return hmac.new(auth_key, msg_bytes, hashlib.sha256).digest()[:24]
        raise ValueError(f"Unsupported auth protocol: {auth_proto}")

    @staticmethod
    def encrypt_scoped_pdu(
        scoped_pdu: bytes,
        priv_key: bytes,
        priv_proto: str,
        engine_boots: int,
        engine_time: int,
    ) -> Tuple[bytes, bytes]:
        """Encrypts serialized ScopedPDU returning (salt, ciphertext)."""
        proto = priv_proto.upper()
        salt = os.urandom(8)
        if proto == "DES":
            des_key = priv_key[:8]
            pre_iv = priv_key[8:16]
            iv = bytes(s ^ p for s, p in zip(salt, pre_iv))
            pad_len = (8 - (len(scoped_pdu) % 8)) % 8
            padded = scoped_pdu + (bytes([pad_len] * pad_len) if pad_len > 0 else b"")
            cipher = Cipher(TripleDES(des_key * 3), CBC(iv))
            ciphertext = cipher.encryptor().update(padded)
            return salt, ciphertext
        elif proto in ("AES", "AES128", "AES192", "AES256"):
            iv = engine_boots.to_bytes(4, "big") + engine_time.to_bytes(4, "big") + salt
            cipher = Cipher(algorithms.AES(priv_key), CFB(iv))
            ciphertext = cipher.encryptor().update(scoped_pdu)
            return salt, ciphertext
        raise ValueError(f"Unsupported priv protocol: {priv_proto}")

    @staticmethod
    def decrypt_scoped_pdu(
        ciphertext: bytes,
        priv_key: bytes,
        priv_proto: str,
        engine_boots: int,
        engine_time: int,
        salt: bytes,
    ) -> bytes:
        """Decrypts ScopedPDU ciphertext."""
        proto = priv_proto.upper()
        if proto == "DES":
            des_key = priv_key[:8]
            pre_iv = priv_key[8:16]
            iv = bytes(s ^ p for s, p in zip(salt, pre_iv))
            cipher = Cipher(TripleDES(des_key * 3), CBC(iv))
            padded = cipher.decryptor().update(ciphertext)
            return padded
        elif proto in ("AES", "AES128", "AES192", "AES256"):
            iv = engine_boots.to_bytes(4, "big") + engine_time.to_bytes(4, "big") + salt
            cipher = Cipher(algorithms.AES(priv_key), CFB(iv))
            return cipher.decryptor().update(ciphertext)
        raise ValueError(f"Unsupported priv protocol: {priv_proto}")


# =====================================================================
# Engine Cache & Time Synchronization
# =====================================================================

@dataclass
class CachedEngineInfo:
    engine_id: bytes
    boots: int
    time: int
    local_sync_time: float


class EngineCache:
    """Tracks authoritative EngineID, boots, and dynamic time window."""

    def __init__(self) -> None:
        self._cache: Dict[Tuple[str, int], CachedEngineInfo] = {}

    def get_info(self, host: str, port: int) -> Tuple[bytes, int, int]:
        info = self._cache.get((host, port))
        if not info:
            return b"", 0, 0
        delta = int(time.time() - info.local_sync_time)
        return info.engine_id, info.boots, info.time + delta

    def update(self, host: str, port: int, engine_id: bytes, boots: int, engine_time: int) -> None:
        self._cache[(host, port)] = CachedEngineInfo(
            engine_id=engine_id,
            boots=boots,
            time=engine_time,
            local_sync_time=time.time(),
        )

    def is_in_time_window(self, host: str, port: int, boots: int, engine_time: int, max_window: int = 150) -> bool:
        """Verifies if incoming (boots, engine_time) is within authoritative engine time window (RFC 3414)."""
        cached_id, cached_boots, cached_time = self.get_info(host, port)
        if not cached_id:
            return True  # Discovery phase
        if boots != cached_boots:
            return False
        return abs(engine_time - cached_time) <= max_window


# =====================================================================
# Message Builders & Parsers
# =====================================================================

class SnmpMessageCodec:
    """SNMPv2c and SNMPv3 Wire-Format Message Serializer and Parser."""

    @staticmethod
    def encode_v2c_message(community: str, pdu: Pdu) -> bytes:
        ver_bytes = Asn1Codec.encode_integer(1)  # SNMPv2c version 1
        comm_bytes = Asn1Codec.encode_octet_string(community)
        pdu_bytes = Asn1Codec.encode_pdu(pdu)
        return Asn1Codec.encode_sequence(ver_bytes + comm_bytes + pdu_bytes)

    @staticmethod
    def decode_v2c_message(data: bytes) -> Tuple[str, Pdu]:
        tag, seq_bytes, _ = Asn1Codec.decode_tlv(data, 0)
        off = 0
        _, ver_bytes, off = Asn1Codec.decode_tlv(seq_bytes, off)
        _, comm_bytes, off = Asn1Codec.decode_tlv(seq_bytes, off)
        community = comm_bytes.decode("utf-8", errors="replace")
        pdu, _ = Asn1Codec.decode_pdu(seq_bytes, off)
        return community, pdu

    @staticmethod
    def encode_v3_message(
        msg_id: int,
        pdu: Pdu,
        creds: Optional[SnmpV3Credentials],
        engine_id: bytes,
        engine_boots: int,
        engine_time: int,
    ) -> bytes:
        # Determine security level
        auth_proto = creds.auth_protocol if (creds and creds.auth_protocol and creds.auth_password) else None
        priv_proto = creds.priv_protocol if (creds and creds.priv_protocol and creds.priv_password and auth_proto) else None
        username = creds.username if creds else ""
        context_name = creds.context_name if creds else ""

        # msgFlags (1 byte)
        # Bit 0 (0x01): authFlag
        # Bit 1 (0x02): privFlag
        # Bit 2 (0x04): reportableFlag
        flags_byte = 0x04  # reportable
        if auth_proto:
            flags_byte |= 0x01
        if priv_proto:
            flags_byte |= 0x02
        msg_flags = bytes([flags_byte])

        # HeaderData
        header_data = Asn1Codec.encode_sequence(
            Asn1Codec.encode_integer(msg_id)
            + Asn1Codec.encode_integer(65507)  # max message size
            + Asn1Codec.encode_octet_string(msg_flags)
            + Asn1Codec.encode_integer(3)  # USM security model
        )

        # ScopedPDU
        scoped_pdu = Asn1Codec.encode_sequence(
            Asn1Codec.encode_octet_string(engine_id)
            + Asn1Codec.encode_octet_string(context_name)
            + Asn1Codec.encode_pdu(pdu)
        )

        # Privacy Encryption
        salt = b""
        if priv_proto and creds and creds.priv_password:
            priv_key = UsmCrypto.derive_priv_key(creds.priv_password, engine_id, auth_proto, priv_proto)
            salt, enc_data = UsmCrypto.encrypt_scoped_pdu(
                scoped_pdu, priv_key, priv_proto, engine_boots, engine_time
            )
            msg_data = Asn1Codec.encode_octet_string(enc_data)
        else:
            msg_data = scoped_pdu

        # Authentication Placeholder
        placeholder_len = 0
        if auth_proto:
            algo = auth_proto.upper()
            if algo in ("MD5", "SHA", "SHA1"):
                placeholder_len = 12
            elif algo == "SHA224":
                placeholder_len = 16
            elif algo == "SHA256":
                placeholder_len = 24
        auth_param_placeholder = b"\x00" * placeholder_len

        # SecurityParameters SEQUENCE
        part_before_auth = (
            Asn1Codec.encode_octet_string(engine_id)
            + Asn1Codec.encode_integer(engine_boots)
            + Asn1Codec.encode_integer(engine_time)
            + Asn1Codec.encode_octet_string(username)
        )
        auth_param_encoded = Asn1Codec.encode_octet_string(auth_param_placeholder)
        part_after_auth = Asn1Codec.encode_octet_string(salt)

        sec_params_payload = part_before_auth + auth_param_encoded + part_after_auth
        sec_params = Asn1Codec.encode_sequence(sec_params_payload)
        msg_sec_params = Asn1Codec.encode_octet_string(sec_params)

        msg_version = Asn1Codec.encode_integer(3)  # version 3
        raw_msg = Asn1Codec.encode_sequence(
            msg_version
            + header_data
            + msg_sec_params
            + msg_data
        )

        # Compute and insert HMAC if auth active
        if auth_proto and creds and creds.auth_password:
            auth_key = UsmCrypto.localize_key(
                UsmCrypto.password_to_key(creds.auth_password, auth_proto),
                engine_id,
                auth_proto,
            )
            mac = UsmCrypto.compute_hmac(raw_msg, auth_key, auth_proto)

            # Locate placeholder inside raw_msg using exact ASN.1 structural offset
            _, raw_seq_start = Asn1Codec.decode_length(raw_msg, 1)
            _, sec_param_str_start = Asn1Codec.decode_length(msg_sec_params, 1)
            _, sec_param_seq_start = Asn1Codec.decode_length(sec_params, 1)
            _, auth_val_start = Asn1Codec.decode_length(auth_param_encoded, 1)

            auth_offset_in_raw = (
                raw_seq_start
                + len(msg_version)
                + len(header_data)
                + sec_param_str_start
                + sec_param_seq_start
                + len(part_before_auth)
                + auth_val_start
            )

            if raw_msg[auth_offset_in_raw : auth_offset_in_raw + placeholder_len] == auth_param_placeholder:
                raw_msg = raw_msg[:auth_offset_in_raw] + mac + raw_msg[auth_offset_in_raw + placeholder_len :]
            else:
                idx = raw_msg.find(auth_param_placeholder)
                if idx != -1:
                    raw_msg = raw_msg[:idx] + mac + raw_msg[idx + placeholder_len :]

        return raw_msg

    @staticmethod
    def decode_v3_message(
        data: bytes,
        creds: Optional[SnmpV3Credentials],
    ) -> Tuple[int, Pdu, bytes, int, int]:
        """Decodes SNMPv3 packet returning (msg_id, pdu, engine_id, engine_boots, engine_time)."""
        tag, seq_bytes, _ = Asn1Codec.decode_tlv(data, 0)
        _, top_seq_start = Asn1Codec.decode_length(data, 1)
        off = 0
        _, ver_bytes, off = Asn1Codec.decode_tlv(seq_bytes, off)  # version 3

        # HeaderData
        _, header_bytes, off = Asn1Codec.decode_tlv(seq_bytes, off)
        h_off = 0
        _, msg_id_bytes, h_off = Asn1Codec.decode_tlv(header_bytes, h_off)
        msg_id = int.from_bytes(msg_id_bytes, "big", signed=True)
        _, _, h_off = Asn1Codec.decode_tlv(header_bytes, h_off)  # maxSize
        _, flags_bytes, _ = Asn1Codec.decode_tlv(header_bytes, h_off)
        flags = flags_bytes[0] if flags_bytes else 0
        is_auth = bool(flags & 0x01)
        is_priv = bool(flags & 0x02)

        # SecurityParameters (OCTET STRING containing SEQUENCE)
        sec_param_tag_offset = off
        _, sec_param_raw_val_start = Asn1Codec.decode_length(seq_bytes, sec_param_tag_offset + 1)
        _, sec_param_raw, off = Asn1Codec.decode_tlv(seq_bytes, off)

        _, sec_param_seq_val_start = Asn1Codec.decode_length(sec_param_raw, 1)
        _, sec_param_bytes, _ = Asn1Codec.decode_tlv(sec_param_raw, 0)

        s_off = 0
        _, engine_id, s_off = Asn1Codec.decode_tlv(sec_param_bytes, s_off)
        _, boots_bytes, s_off = Asn1Codec.decode_tlv(sec_param_bytes, s_off)
        boots = int.from_bytes(boots_bytes, "big", signed=True)
        _, time_bytes, s_off = Asn1Codec.decode_tlv(sec_param_bytes, s_off)
        eng_time = int.from_bytes(time_bytes, "big", signed=True)
        _, user_bytes, s_off = Asn1Codec.decode_tlv(sec_param_bytes, s_off)

        # Authoritative EngineID Validation (RFC 3414)
        if creds and creds.engine_id and engine_id != creds.engine_id:
            raise ValueError(f"SNMPv3 EngineID mismatch: expected {creds.engine_id!r}, got {engine_id!r}")

        auth_param_tag_offset = s_off
        _, auth_param_val_start = Asn1Codec.decode_length(sec_param_bytes, auth_param_tag_offset + 1)
        _, auth_params, s_off = Asn1Codec.decode_tlv(sec_param_bytes, s_off)
        _, priv_params, _ = Asn1Codec.decode_tlv(sec_param_bytes, s_off)

        # Authenticate packet if auth flag set
        if is_auth and creds and creds.auth_protocol and creds.auth_password:
            # Zero out auth_params in packet data
            placeholder = b"\x00" * len(auth_params)
            mac_offset = top_seq_start + sec_param_raw_val_start + sec_param_seq_val_start + auth_param_val_start
            if not (mac_offset < len(data) and data[mac_offset : mac_offset + len(auth_params)] == auth_params):
                mac_offset = data.find(auth_params)

            if mac_offset != -1:
                zeroed_data = data[:mac_offset] + placeholder + data[mac_offset + len(auth_params) :]
                auth_key = UsmCrypto.localize_key(
                    UsmCrypto.password_to_key(creds.auth_password, creds.auth_protocol),
                    engine_id,
                    creds.auth_protocol,
                )
                computed_mac = UsmCrypto.compute_hmac(zeroed_data, auth_key, creds.auth_protocol)
                if not hmac.compare_digest(auth_params, computed_mac):
                    raise ValueError("SNMPv3 Authentication verification failed: invalid HMAC digest")

        # msgData (ScopedPDU or encrypted OCTET STRING)
        msg_data_tag, msg_data_bytes, _ = Asn1Codec.decode_tlv(seq_bytes, off)

        if is_priv and creds and creds.priv_protocol and creds.priv_password:
            priv_key = UsmCrypto.derive_priv_key(
                creds.priv_password, engine_id, creds.auth_protocol or "SHA1", creds.priv_protocol
            )
            decrypted = UsmCrypto.decrypt_scoped_pdu(
                msg_data_bytes, priv_key, creds.priv_protocol, boots, eng_time, priv_params
            )
            _, scoped_bytes, _ = Asn1Codec.decode_tlv(decrypted, 0)
        else:
            scoped_bytes = msg_data_bytes

        # ScopedPDU: contextEngineID, contextName, PDU
        sc_off = 0
        _, _, sc_off = Asn1Codec.decode_tlv(scoped_bytes, sc_off)  # contextEngineID
        _, _, sc_off = Asn1Codec.decode_tlv(scoped_bytes, sc_off)  # contextName
        pdu, _ = Asn1Codec.decode_pdu(scoped_bytes, sc_off)

        return msg_id, pdu, engine_id, boots, eng_time


# =====================================================================
# UDP Network Transport & Protocol
# =====================================================================

class SnmpClientProtocol(asyncio.DatagramProtocol):
    """Async UDP Protocol dispatching responses to waiting request futures."""

    def __init__(self, pending: Dict[int, asyncio.Future[bytes]]) -> None:
        self.pending = pending
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        try:
            # Peek packet type
            tag, seq_bytes, _ = Asn1Codec.decode_tlv(data, 0)
            if tag != Asn1Tag.SEQUENCE:
                return

            off = 0
            _, ver_bytes, off = Asn1Codec.decode_tlv(seq_bytes, off)
            ver = int.from_bytes(ver_bytes, "big", signed=True)

            req_id: Optional[int] = None
            if ver in (0, 1):  # SNMPv1 / SNMPv2c
                _, _, off = Asn1Codec.decode_tlv(seq_bytes, off)  # community
                pdu_type, pdu_bytes, _ = Asn1Codec.decode_tlv(seq_bytes, off)
                _, req_id_bytes, _ = Asn1Codec.decode_tlv(pdu_bytes, 0)
                req_id = int.from_bytes(req_id_bytes, "big", signed=True)
            elif ver == 3:  # SNMPv3
                _, header_bytes, _ = Asn1Codec.decode_tlv(seq_bytes, off)
                _, msg_id_bytes, _ = Asn1Codec.decode_tlv(header_bytes, 0)
                req_id = int.from_bytes(msg_id_bytes, "big", signed=True)

            if req_id is not None and req_id in self.pending:
                fut = self.pending[req_id]
                if not fut.done():
                    fut.set_result(data)
        except Exception as exc:
            logger.debug("Failed parsing incoming datagram from %s: %s", addr, exc)

    def error_received(self, exc: Exception) -> None:
        logger.debug("UDP error received: %s", exc)


# =====================================================================
# High-Level Engine & Client
# =====================================================================

class SnmpEngine:
    """Universal Multi-Vendor SNMPv2c / SNMPv3 Client Engine."""

    def __init__(self) -> None:
        self.engine_cache = EngineCache()
        self._request_counter: int = 1000
        self._pending: Dict[int, asyncio.Future[bytes]] = {}
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._protocol: Optional[SnmpClientProtocol] = None
        self._lock = asyncio.Lock()

    def _next_request_id(self) -> int:
        self._request_counter = (self._request_counter + 1) & 0x7FFFFFFF
        if self._request_counter == 0:
            self._request_counter = 1
        return self._request_counter

    async def _ensure_transport(self) -> Tuple[asyncio.DatagramTransport, SnmpClientProtocol]:
        async with self._lock:
            if self._transport is None or self._transport.is_closing():
                loop = asyncio.get_running_loop()
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: SnmpClientProtocol(self._pending),
                    local_addr=("0.0.0.0", 0),
                )
                self._transport = transport
                self._protocol = protocol
            return self._transport, self._protocol  # type: ignore[return-value]

    async def close(self) -> None:
        """Closes UDP transport and cancels pending queries."""
        async with self._lock:
            if self._transport and not self._transport.is_closing():
                self._transport.close()
                self._transport = None
                self._protocol = None
            for fut in self._pending.values():
                if not fut.done():
                    fut.cancel()
            self._pending.clear()

    async def _send_and_receive(
        self,
        ip: str,
        port: int,
        raw_msg: bytes,
        request_id: int,
        timeout: float,
        retries: int,
    ) -> bytes:
        transport, _ = await self._ensure_transport()
        loop = asyncio.get_running_loop()

        for attempt in range(retries + 1):
            fut: asyncio.Future[bytes] = loop.create_future()
            self._pending[request_id] = fut
            try:
                transport.sendto(raw_msg, (ip, port))
                return await asyncio.wait_for(fut, timeout=timeout)
            except asyncio.TimeoutError:
                if attempt == retries:
                    raise TimeoutError(f"SNMP request {request_id} to {ip}:{port} timed out after {retries + 1} attempts")
            finally:
                self._pending.pop(request_id, None)

        raise TimeoutError(f"SNMP request {request_id} to {ip}:{port} failed")

    async def discover_engine_id(
        self,
        target: str,
        port: int = 161,
        timeout: float = 2.0,
    ) -> bytes:
        """Discovers authoritative EngineID, boots, and time using RFC 3414 discovery probe."""
        req_id = self._next_request_id()
        pdu = Pdu(
            pdu_type=Asn1Tag.GET_REQUEST,
            request_id=req_id,
            varbinds=[VarBind("1.3.6.1.6.3.15.1.1.4.0", None)],
        )

        probe_msg = SnmpMessageCodec.encode_v3_message(
            msg_id=req_id,
            pdu=pdu,
            creds=None,
            engine_id=b"",
            engine_boots=0,
            engine_time=0,
        )

        try:
            resp_bytes = await self._send_and_receive(target, port, probe_msg, req_id, timeout, 1)
            _, _, engine_id, boots, eng_time = SnmpMessageCodec.decode_v3_message(resp_bytes, None)
            if engine_id:
                self.engine_cache.update(target, port, engine_id, boots, eng_time)
                return engine_id
        except Exception as exc:
            logger.debug("EngineID discovery probe to %s:%d failed: %s", target, port, exc)

        return b""

    def _normalize_creds(self, **kwargs: Any) -> Optional[SnmpV3Credentials]:
        if "v3_creds" in kwargs and kwargs["v3_creds"] is not None:
            return kwargs["v3_creds"]
        v3_user = kwargs.get("v3_user")
        if v3_user:
            return SnmpV3Credentials(
                username=v3_user,
                auth_protocol=kwargs.get("v3_auth_proto"),
                auth_password=kwargs.get("v3_auth_key") or kwargs.get("v3_auth_password"),
                priv_protocol=kwargs.get("v3_priv_proto"),
                priv_password=kwargs.get("v3_priv_key") or kwargs.get("v3_priv_password"),
                context_name=kwargs.get("v3_context_name", ""),
            )
        return None

    async def _execute_pdu(
        self,
        ip: str,
        port: int,
        pdu: Pdu,
        version: str,
        community: str,
        creds: Optional[SnmpV3Credentials],
        timeout: float,
        retries: int,
    ) -> SnmpResponse:
        req_id = pdu.request_id

        if version == "v2c":
            raw_msg = SnmpMessageCodec.encode_v2c_message(community, pdu)
            try:
                resp_bytes = await self._send_and_receive(ip, port, raw_msg, req_id, timeout, retries)
                _, resp_pdu = SnmpMessageCodec.decode_v2c_message(resp_bytes)
                err_desc = ERROR_STATUS_NAMES.get(resp_pdu.error_status, "unknownError")
                return SnmpResponse(
                    request_id=resp_pdu.request_id,
                    error_status=resp_pdu.error_status,
                    error_index=resp_pdu.error_index,
                    varbinds=resp_pdu.varbinds,
                    error_description=err_desc,
                    is_error=(resp_pdu.error_status != 0),
                )
            except Exception as err:
                return SnmpResponse(
                    request_id=req_id,
                    error_status=5,
                    error_description=str(err),
                    is_error=True,
                )

        elif version == "v3":
            # Check or discover engineID
            engine_id, boots, eng_time = self.engine_cache.get_info(ip, port)
            if not engine_id:
                engine_id = await self.discover_engine_id(ip, port, timeout)
                engine_id, boots, eng_time = self.engine_cache.get_info(ip, port)
                if not engine_id and creds and creds.engine_id:
                    engine_id = creds.engine_id

            raw_msg = SnmpMessageCodec.encode_v3_message(
                msg_id=req_id,
                pdu=pdu,
                creds=creds,
                engine_id=engine_id,
                engine_boots=boots,
                engine_time=eng_time,
            )

            try:
                resp_bytes = await self._send_and_receive(ip, port, raw_msg, req_id, timeout, retries)
                _, resp_pdu, r_engine_id, r_boots, r_time = SnmpMessageCodec.decode_v3_message(resp_bytes, creds)

                # Check Report PDU time sync
                if resp_pdu.pdu_type == Asn1Tag.REPORT:
                    if engine_id and r_engine_id and r_engine_id != engine_id:
                        raise ValueError(f"SNMPv3 response from unknown/unexpected engineID: expected {engine_id!r}, got {r_engine_id!r}")
                    # Update cache and retry once if not in time window
                    self.engine_cache.update(ip, port, r_engine_id or engine_id, r_boots, r_time)
                    # Retry query
                    req_id2 = self._next_request_id()
                    pdu.request_id = req_id2
                    raw_msg2 = SnmpMessageCodec.encode_v3_message(
                        msg_id=req_id2,
                        pdu=pdu,
                        creds=creds,
                        engine_id=r_engine_id or engine_id,
                        engine_boots=r_boots,
                        engine_time=r_time,
                    )
                    resp_bytes2 = await self._send_and_receive(ip, port, raw_msg2, req_id2, timeout, retries)
                    _, resp_pdu, r_engine_id2, r_boots2, r_time2 = SnmpMessageCodec.decode_v3_message(resp_bytes2, creds)
                    if engine_id and r_engine_id2 != engine_id:
                        raise ValueError(f"SNMPv3 response from unknown/unexpected engineID: expected {engine_id!r}, got {r_engine_id2!r}")
                    if not self.engine_cache.is_in_time_window(ip, port, r_boots2, r_time2):
                        raise ValueError(f"SNMPv3 response outside 150s time window (replay attack detected): boots={r_boots2}, time={r_time2}")
                    self.engine_cache.update(ip, port, r_engine_id2 or engine_id, r_boots2, r_time2)
                else:
                    if engine_id and r_engine_id != engine_id:
                        raise ValueError(f"SNMPv3 response from unknown/unexpected engineID: expected {engine_id!r}, got {r_engine_id!r}")
                    if not self.engine_cache.is_in_time_window(ip, port, r_boots, r_time):
                        raise ValueError(f"SNMPv3 response outside 150s time window (replay attack detected): boots={r_boots}, time={r_time}")
                    self.engine_cache.update(ip, port, r_engine_id or engine_id, r_boots, r_time)

                err_desc = ERROR_STATUS_NAMES.get(resp_pdu.error_status, "unknownError")
                return SnmpResponse(
                    request_id=resp_pdu.request_id,
                    error_status=resp_pdu.error_status,
                    error_index=resp_pdu.error_index,
                    varbinds=resp_pdu.varbinds,
                    error_description=err_desc,
                    is_error=(resp_pdu.error_status != 0),
                )
            except Exception as err:
                return SnmpResponse(
                    request_id=req_id,
                    error_status=5,
                    error_description=str(err),
                    is_error=True,
                )

        raise ValueError(f"Unsupported SNMP version: {version}")

    async def get(
        self,
        target: Optional[str] = None,
        oids: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> SnmpResponse:
        """Executes SNMP GetRequest."""
        ip = target or kwargs.get("ip") or "127.0.0.1"
        port = kwargs.get("port", 161)
        oids_list = oids or kwargs.get("oids", [])
        version = kwargs.get("version", "v2c")
        community = kwargs.get("community", "public")
        timeout = kwargs.get("timeout", 2.0)
        retries = kwargs.get("retries", 1)
        creds = self._normalize_creds(**kwargs)

        req_id = self._next_request_id()
        varbinds = [VarBind(oid=oid, value=None, tag=Asn1Tag.NULL) for oid in oids_list]
        pdu = Pdu(pdu_type=Asn1Tag.GET_REQUEST, request_id=req_id, varbinds=varbinds)

        return await self._execute_pdu(ip, port, pdu, version, community, creds, timeout, retries)

    async def get_next(
        self,
        target: Optional[str] = None,
        oids: Optional[List[str]] = None,
        **kwargs: Any,
    ) -> SnmpResponse:
        """Executes SNMP GetNextRequest."""
        ip = target or kwargs.get("ip") or "127.0.0.1"
        port = kwargs.get("port", 161)
        oids_list = oids or kwargs.get("oids", [])
        version = kwargs.get("version", "v2c")
        community = kwargs.get("community", "public")
        timeout = kwargs.get("timeout", 2.0)
        retries = kwargs.get("retries", 1)
        creds = self._normalize_creds(**kwargs)

        req_id = self._next_request_id()
        varbinds = [VarBind(oid=oid, value=None, tag=Asn1Tag.NULL) for oid in oids_list]
        pdu = Pdu(pdu_type=Asn1Tag.GET_NEXT_REQUEST, request_id=req_id, varbinds=varbinds)

        return await self._execute_pdu(ip, port, pdu, version, community, creds, timeout, retries)

    async def get_bulk(
        self,
        target: Optional[str] = None,
        oids: Optional[List[str]] = None,
        non_repeaters: int = 0,
        max_repetitions: int = 10,
        **kwargs: Any,
    ) -> SnmpResponse:
        """Executes SNMP GetBulkRequest."""
        ip = target or kwargs.get("ip") or "127.0.0.1"
        port = kwargs.get("port", 161)
        oids_list = oids or kwargs.get("oids", [])
        version = kwargs.get("version", "v2c")
        community = kwargs.get("community", "public")
        timeout = kwargs.get("timeout", 2.0)
        retries = kwargs.get("retries", 1)
        creds = self._normalize_creds(**kwargs)

        req_id = self._next_request_id()
        varbinds = [VarBind(oid=oid, value=None, tag=Asn1Tag.NULL) for oid in oids_list]
        pdu = Pdu(
            pdu_type=Asn1Tag.GET_BULK_REQUEST,
            request_id=req_id,
            non_repeaters=non_repeaters,
            max_repetitions=max_repetitions,
            varbinds=varbinds,
        )

        return await self._execute_pdu(ip, port, pdu, version, community, creds, timeout, retries)

    async def set(
        self,
        target: Optional[str] = None,
        varbinds: Optional[List[VarBind]] = None,
        **kwargs: Any,
    ) -> SnmpResponse:
        """Executes SNMP SetRequest."""
        ip = target or kwargs.get("ip") or "127.0.0.1"
        port = kwargs.get("port", 161)
        vbs = varbinds or kwargs.get("varbinds", [])
        version = kwargs.get("version", "v2c")
        community = kwargs.get("community", "private")
        timeout = kwargs.get("timeout", 2.0)
        retries = kwargs.get("retries", 1)
        creds = self._normalize_creds(**kwargs)

        req_id = self._next_request_id()
        pdu = Pdu(pdu_type=Asn1Tag.SET_REQUEST, request_id=req_id, varbinds=vbs)

        return await self._execute_pdu(ip, port, pdu, version, community, creds, timeout, retries)

    async def walk(
        self,
        target: Optional[str] = None,
        root_oid: str = "1.3.6.1.2.1",
        **kwargs: Any,
    ) -> List[VarBind]:
        """Iteratively walks the MIB subtree rooted at root_oid using GetBulk or GetNext."""
        ip = target or kwargs.get("ip") or "127.0.0.1"
        clean_root = root_oid.lstrip(".")
        results: List[VarBind] = []
        curr_oid = root_oid

        max_iterations = kwargs.get("max_iterations", 500)
        iterations = 0

        while iterations < max_iterations:
            iterations += 1
            # Try GetBulk first if v2c or v3
            bulk_res = await self.get_bulk(
                target=ip,
                oids=[curr_oid],
                non_repeaters=0,
                max_repetitions=20,
                **kwargs,
            )

            if bulk_res.is_error or not bulk_res.varbinds:
                # Fallback to GetNext
                next_res = await self.get_next(target=ip, oids=[curr_oid], **kwargs)
                if next_res.is_error or not next_res.varbinds:
                    break
                new_vbs = next_res.varbinds
            else:
                new_vbs = bulk_res.varbinds

            advanced = False
            for vb in new_vbs:
                clean_vb_oid = vb.oid.lstrip(".")
                if vb.tag in (Asn1Tag.END_OF_MIB_VIEW, Asn1Tag.NO_SUCH_OBJECT, Asn1Tag.NO_SUCH_INSTANCE):
                    return results

                # Check if still within subtree
                if not (clean_vb_oid == clean_root or clean_vb_oid.startswith(clean_root + ".")):
                    return results

                # Avoid looping on same OID
                if any(r.oid == vb.oid for r in results):
                    return results

                results.append(vb)
                curr_oid = vb.oid
                advanced = True

            if not advanced:
                break

        return results


# Convenient alias for multi-module compatibility
SnmpClient = SnmpEngine
