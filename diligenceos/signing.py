"""Ed25519 issuer identity: sign what is issued, verify without trusting the server."""

from __future__ import annotations

import os
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PREFIX = "ed25519:"
# One string per key and per signature: lowercase hex, exact length. bytes.fromhex alone also
# accepts uppercase and embedded whitespace, which would give every signature many valid spellings.
_KEY_HEX = re.compile(r"[0-9a-f]{64}")
_SIG_HEX = re.compile(r"[0-9a-f]{128}")


def _small_order_keys() -> frozenset[bytes]:
    """Encodings of the points of order dividing 8 (and their non-canonical spellings).

    Under such a key the signature (R = the key itself or the identity, S = 0) verifies for
    every message, so it must never count as a signer. y-coordinates: 0 and +-1 and the two
    order-8 points; y and y+p are the same point written two ways; the sign bit may be either."""
    p = 2**255 - 19
    ys = {0, 1, p - 1, p, p + 1,
          2707385501144840649318225287225658788936804267575313519463743609750303402022,
          55188659117513257062467267217118295137698188065244968500265048394206261417927}
    return frozenset((y | (sign << 255)).to_bytes(32, "little") for y in ys for sign in (0, 1))


_SMALL_ORDER = _small_order_keys()
RECEIPT_DOMAIN = "diligenceos.receipt/1"
LOG_HEAD_DOMAIN = "diligenceos.log-head/1"


class SignerError(Exception):
    pass


def _payload(domain: str, message: str) -> bytes:
    return f"{domain}\n{message}".encode("utf-8")


class Signer:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key
        raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.issuer_id = PREFIX + raw.hex()

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_create(cls, path: Path) -> "Signer":
        """Never replaces an existing file: a new key would silently be a new identity."""
        if path.exists():
            try:
                raw = bytes.fromhex(path.read_text().strip())
                return cls(Ed25519PrivateKey.from_private_bytes(raw))
            except (ValueError, OSError) as exc:
                raise SignerError(f"issuer key file {path} is unusable: {exc}") from exc
        signer = cls.generate()
        raw = signer._key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(raw.hex() + "\n")
        return signer

    def sign(self, domain: str, message: str) -> str:
        return PREFIX + self._key.sign(_payload(domain, message)).hex()


def verify_signature(issuer_id, domain: str, message: str, signature) -> bool:
    """Pure; any malformed input is simply False."""
    try:
        if not (isinstance(issuer_id, str) and issuer_id.startswith(PREFIX)):
            return False
        if not (isinstance(signature, str) and signature.startswith(PREFIX)):
            return False
        key_hex, sig_hex = issuer_id[len(PREFIX):], signature[len(PREFIX):]
        if not (_KEY_HEX.fullmatch(key_hex) and _SIG_HEX.fullmatch(sig_hex)):
            return False
        raw_key = bytes.fromhex(key_hex)
        if raw_key in _SMALL_ORDER:
            return False
        Ed25519PublicKey.from_public_bytes(raw_key).verify(bytes.fromhex(sig_hex), _payload(domain, message))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def head_message(length: int, head_hash: str) -> str:
    return f"{length}:{head_hash}"


def verify_head(doc) -> bool:
    """Offline check of a signed /v1/log/head document. `length` must be a real integer: the signed
    message is text, so "3" would otherwise be a second, validly signed spelling of 3."""
    try:
        if type(doc["length"]) is not int or doc["length"] < 0 or not isinstance(doc["head_hash"], str):
            return False
        return verify_signature(
            doc["issuer"], LOG_HEAD_DOMAIN,
            head_message(doc["length"], doc["head_hash"]), doc["signature"],
        )
    except (KeyError, TypeError):
        return False
