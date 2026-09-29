"""Ed25519 issuer identity: sign what is issued, verify without trusting the server."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PREFIX = "ed25519:"
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
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(issuer_id[len(PREFIX):]))
        key.verify(bytes.fromhex(signature[len(PREFIX):]), _payload(domain, message))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def head_message(length: int, head_hash: str) -> str:
    return f"{length}:{head_hash}"


def verify_head(doc) -> bool:
    """Offline check of a signed /v1/log/head document."""
    try:
        return verify_signature(
            doc["issuer"], LOG_HEAD_DOMAIN,
            head_message(doc["length"], doc["head_hash"]), doc["signature"],
        )
    except (KeyError, TypeError):
        return False
