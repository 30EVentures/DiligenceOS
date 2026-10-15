"""Spine primitives: canonical JSON, sha256, domain-separated Ed25519 (raw hex keys and signatures).

Wire format (spine): signature = Ed25519 over  domain + "\\0" + canonical(doc)  (UTF-8).
This is deliberately NOT diligenceos.signing (that uses "domain\\n" + message and an "ed25519:" prefix):
the spine format is fixed by the cross-language vectors, so it lives beside, not inside, the existing code.
"""

from __future__ import annotations

import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAX_SAFE_INT = 9007199254740991
HEX32 = re.compile(r"^[0-9a-f]{64}$")
HEX64 = re.compile(r"^[0-9a-f]{128}$")
AMOUNT = re.compile(r"^(0|[1-9][0-9]*)$")
ADDR = re.compile(r"^0x[0-9a-f]{40}$")
TXHASH = re.compile(r"^0x[0-9a-f]{64}$")
ISO_MS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z$")

DOMAIN_INVOICE = "30e-demo/invoice/1"
DOMAIN_RECEIPT = "30e-demo/receipt/1"
DOMAIN_LOG_ENTRY = "30e-demo/log-entry/1"


class CanonError(ValueError):
    pass


def _utf16_key(k: str) -> bytes:
    # JavaScript sorts object keys by UTF-16 code unit; Python sorts by code point. They differ
    # beyond the BMP, so sort on UTF-16BE bytes to match the reference exactly.
    return k.encode("utf-16-be", "surrogatepass")


def _str(s: str) -> str:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonError("lone surrogate in string") from exc
    return json.dumps(s, ensure_ascii=False)


def canonical(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _str(v)
    if isinstance(v, int):
        if abs(v) > MAX_SAFE_INT:
            raise CanonError("integer outside the safe range")
        return str(v)
    if isinstance(v, float):
        raise CanonError("floats are refused; money travels as integer strings")
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        if not all(isinstance(k, str) for k in v):
            raise CanonError("object keys must be strings")
        return "{" + ",".join(_str(k) + ":" + canonical(v[k]) for k in sorted(v, key=_utf16_key)) + "}"
    raise CanonError(f"unsupported value of type {type(v).__name__}")


def sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def hash_of(v) -> str:
    return sha256hex(canonical(v))


class SpineKey:
    """An Ed25519 key in the spine's raw-hex form."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key
        self.pub_hex = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> "SpineKey":
        if not (isinstance(seed_hex, str) and HEX32.match(seed_hex)):
            raise ValueError("seed must be 32 bytes of lowercase hex")
        return cls(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex)))

    @classmethod
    def generate(cls) -> "SpineKey":
        return cls(Ed25519PrivateKey.generate())

    def sign(self, domain: str, doc) -> str:
        return self._key.sign((domain + "\0" + canonical(doc)).encode("utf-8")).hex()


def verify_doc(pub_hex, domain: str, doc, sig_hex) -> bool:
    """Verify against a PINNED public key. Never raises; anything wrong is False."""
    try:
        if not (isinstance(pub_hex, str) and HEX32.match(pub_hex)):
            return False
        if not (isinstance(sig_hex, str) and HEX64.match(sig_hex)):
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(sig_hex), (domain + "\0" + canonical(doc)).encode("utf-8")
        )
        return True
    except (InvalidSignature, ValueError, TypeError, CanonError):
        return False
