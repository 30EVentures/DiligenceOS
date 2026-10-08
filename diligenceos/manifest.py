"""A signed, self-describing manifest: who runs this, which key to pin, how to verify."""

from __future__ import annotations

import hashlib
import json
import os

from diligenceos import auth, delegation, engine, receipt, receipt_log, signing, witness
from diligenceos.signing import Signer, verify_signature

SCHEMA = "diligenceos.manifest/1"
DOMAIN = "diligenceos.manifest/1"
DEFAULT_OPERATOR = "30E Ventures"


def operator_name() -> str:
    return os.environ.get("DILIGENCEOS_OPERATOR_NAME", "").strip() or DEFAULT_OPERATOR


def _vector() -> dict:
    sample = {"b": 1, "a": [2, "é"]}
    canonical = json.dumps(sample, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "input": sample,
        "canonical": canonical,
        "sha256": "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def build_manifest(
    *, issuer_id: str, routes: dict, authenticated, witnesses, limits: dict, generated_at: str,
    operator: str | None = None,
) -> dict:
    sign_note = "signed payload = UTF-8 bytes of  <domain> + \"\\n\" + <message>"
    return {
        "schema": SCHEMA,
        "service": "diligenceos",
        "operator": {"name": operator or operator_name()},
        "generated_at": generated_at,
        "issuer": {
            "id": issuer_id,
            "algorithm": "ed25519",
            "trust": "a claim, not a trust anchor: pin this id out of band before relying on anything signed by it",
        },
        "api": {
            "version": "v1",
            "capabilities": "/v1/capabilities",
            "routes": [
                {"method": method, "path": path, "authenticated": path in set(authenticated)}
                for path, method in sorted(routes.items())
            ],
        },
        "encoding": {
            "canonical_json": "JSON with keys sorted, separators (',', ':'), non-ASCII left as-is, encoded as UTF-8",
            "digest": "sha256 over the canonical JSON, written 'sha256:<64 hex>'",
            "signature": "ed25519, written 'ed25519:<128 hex>'; issuer/witness/delegate ids are 'ed25519:<64 hex>' public keys",
            "signing": sign_note,
        },
        "documents": {
            "receipt": {
                "schema": receipt.SCHEMA,
                "rules": receipt.RULES,
                "id": "digest of the receipt without its `id` and `signature` fields",
                "untrusted_fields": receipt.unsanitized_fields_doc(),
                "signature": {"domain": signing.RECEIPT_DOMAIN, "message": "the receipt `id`", "signer": "the receipt's `issuer`"},
                "replay": {
                    "rules": receipt.RULES,
                    "verdict": "RED_FLAG if any finding with category 'sanctions' has status 'flag'; otherwise HOLD if any finding has status 'flag'; otherwise PROCEED",
                    "trust_score": "start at base_trust_score, subtract sanctions_penalty for each flagged 'sanctions' finding and other_penalty for each other flagged finding, clamp to 0..100",
                    "base_trust_score": engine.DEFAULT_BASE_TRUST_SCORE,
                    "sanctions_penalty": engine.SANCTIONS_PENALTY,
                    "other_penalty": engine.OTHER_PENALTY,
                    "check": "the receipt's `verdict` and `trust_score` must equal the replayed values",
                },
            },
            "delegation": {
                "schema": delegation.SCHEMA,
                "scopes": sorted(delegation.SCOPES),
                "id": "digest of the delegation without `id` and `signature`",
                "signature": {"domain": delegation.DOMAIN, "message": "the delegation `id`", "signer": "its `delegator`"},
                "rule": "each link may only narrow the one above: scopes, expiry, budget, policy",
            },
            "request_auth": {
                "domain": auth.REQUEST_DOMAIN,
                "message": "digest of {path, body without `auth`, issued_at, nonce}",
                "signer": "auth.signer, which must be the operator (empty chain) or the last delegate of the chain",
                "freshness": f"issued_at within {auth.MAX_SKEW_SECONDS}s of the server; nonce single-use",
            },
            "log_entry": {
                "hash": "entry_hash = digest of the entry without `entry_hash` and `signature`; prev_hash links entries; genesis prev_hash is " + receipt_log.GENESIS,
                "signature": {"domain": receipt_log.LOG_ENTRY_DOMAIN, "message": "the entry's `entry_hash`", "signer": "the entry's `issuer` (entries before signing was added have none)"},
            },
            "log_head": {
                "signature": {"domain": signing.LOG_HEAD_DOMAIN, "message": "<length>:<head_hash>", "signer": "the head's `issuer`"},
            },
            "cosignature": {
                "signature": {"domain": witness.COSIGN_DOMAIN, "message": "<issuer>:<length>:<head_hash>", "signer": "the `witness`"},
                "meaning": "the witness saw this head and it extended what the witness had seen before",
            },
            "manifest": {
                "schema": SCHEMA,
                "signature": {"domain": DOMAIN, "message": "digest of the `manifest` object", "signer": "the document's `issuer`"},
            },
        },
        "limits": limits,
        "witnesses": sorted(witnesses),
        "vectors": {"canonical_json": [_vector()]},
    }


def sign_manifest(manifest: dict, signer: Signer) -> dict:
    return {
        "manifest": manifest,
        "issuer": signer.issuer_id,
        "signature": signer.sign(DOMAIN, receipt.digest(manifest)),
    }


def verify_manifest(doc, *, pinned_issuer: str | None = None) -> list[str]:
    """Empty list = the document is intact and was signed by the issuer it names
    (and by `pinned_issuer`, if given). Pure; never raises."""
    try:
        manifest, issuer, signature = doc["manifest"], doc["issuer"], doc["signature"]
        errors = []
        if manifest.get("schema") != SCHEMA:
            errors.append(f"unknown schema {manifest.get('schema')!r}")
        if manifest["issuer"]["id"] != issuer:
            errors.append("manifest names a different issuer than the one that signed it")
        if not verify_signature(issuer, DOMAIN, receipt.digest(manifest), signature):
            errors.append("signature does not verify")
        if pinned_issuer is not None and issuer != pinned_issuer:
            errors.append("signed by an issuer other than the pinned one")
        return errors
    except (KeyError, TypeError, AttributeError, ValueError):
        return ["manifest document is malformed"]
