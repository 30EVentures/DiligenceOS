"""Verdict receipts: a verdict anyone can re-check offline, from the document alone."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from diligenceos.engine import assemble_verdict
from diligenceos.evidence import verify_evidence
from diligenceos.serialize import finding_from_dict, verdict_result_to_dict
from diligenceos.types import VerdictResult

SCHEMA = "diligenceos.receipt/1"
RULES = "verdict-rules/1"


def canonical_json(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(obj) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(obj)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def issue_receipt(
    *,
    subject: dict,
    inputs: dict,
    result: VerdictResult,
    transaction: dict | None = None,
    issued_at: str | None = None,
    ttl_seconds: int | None = None,
) -> dict:
    wire = verdict_result_to_dict(result)
    issued = issued_at or _now()
    expires = wire["expires"]
    if expires is None and ttl_seconds:
        expires = (datetime.fromisoformat(issued) + timedelta(seconds=ttl_seconds)).isoformat()
    body = {
        "schema": SCHEMA,
        "rules": RULES,
        "subject": subject,
        "transaction": transaction,
        "inputs_digest": digest(inputs),
        "verdict": wire["verdict"],
        "trust_score": wire["trust_score"],
        "findings": wire["findings"],
        "issued_at": issued,
        "expires": expires,
    }
    return {**body, "id": digest(body)}


@dataclass(frozen=True)
class ReceiptCheck:
    valid: bool
    expired: bool = False
    errors: tuple[str, ...] = field(default_factory=tuple)
    unchecked: tuple[str, ...] = field(default_factory=tuple)
    revoked: bool = False
    revoked_reason: str | None = None


def verify_receipt(
    receipt,
    *,
    now: str | None = None,
    sources: dict[str, str] | None = None,
    revocations: dict[str, dict] | None = None,
) -> ReceiptCheck:
    if not isinstance(receipt, dict):
        return ReceiptCheck(False, errors=("receipt must be a JSON object",))

    errors: list[str] = []
    unchecked: list[str] = []
    if receipt.get("schema") != SCHEMA:
        errors.append(f"unknown schema {receipt.get('schema')!r}")
    if receipt.get("rules") != RULES:
        errors.append(f"unknown rules {receipt.get('rules')!r}")

    body = {k: v for k, v in receipt.items() if k != "id"}
    try:
        if receipt.get("id") != digest(body):
            errors.append("id does not match the document contents")
    except (TypeError, ValueError):
        errors.append("document is not canonicalizable JSON")

    try:
        findings = [finding_from_dict(f) for f in receipt["findings"]]
        for finding in findings:
            for ev in finding.evidence:
                if sources is not None and ev.source in sources:
                    errors.extend(verify_evidence(ev, sources[ev.source]))
                elif ev.source not in unchecked:
                    unchecked.append(ev.source)
        replayed = assemble_verdict(findings)
        if replayed.verdict.value != receipt.get("verdict"):
            errors.append(
                f"verdict {receipt.get('verdict')!r} does not follow from the "
                f"findings (replay gives {replayed.verdict.value!r})"
            )
        if replayed.trust_score != receipt.get("trust_score"):
            errors.append(
                f"trust_score {receipt.get('trust_score')!r} does not follow from "
                f"the findings (replay gives {replayed.trust_score})"
            )
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        errors.append(f"findings unreadable: {exc}")

    expired = False
    expires = receipt.get("expires")
    if expires and now:
        try:
            expired = datetime.fromisoformat(now) > datetime.fromisoformat(expires)
        except (TypeError, ValueError):
            errors.append("expires/now is not an ISO-8601 timestamp")

    revocation = (revocations or {}).get(receipt.get("id"))
    return ReceiptCheck(
        valid=not errors, expired=expired, errors=tuple(errors), unchecked=tuple(unchecked),
        revoked=revocation is not None,
        revoked_reason=revocation.get("reason") if revocation else None,
    )
