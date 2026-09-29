"""Machine API: JSON in, receipts out. Pure — no WSGI — so it tests directly."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone

from diligenceos.pipeline import run_diligence
from diligenceos.policy import Policy, WideningError, decide, effective_policy
from diligenceos.spend import try_spend
from diligenceos.receipt import RULES, SCHEMA, digest, issue_receipt, verify_receipt
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Money, Verdict

MAX_BODY_BYTES = 1024 * 1024
DEFAULT_TTL_SECONDS = 24 * 60 * 60
_RECEIPT_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
CATEGORIES = ("sanctions", "identity", "track_record", "document_scan")

_ROUTES = {
    "/v1/verdict": "POST",
    "/v1/verify": "POST",
    "/v1/decide": "POST",
    "/v1/revoke": "POST",
    "/v1/revocations": "GET",
    "/v1/spend": "POST",
    "/v1/capabilities": "GET",
}


def _json(status: int, payload, extra_headers=()):
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    headers = [("Content-Type", "application/json"), *extra_headers]
    return status, headers, body


def _error(status: int, code: str, message: str, field: str | None = None, extra_headers=()):
    err = {"code": code, "message": message}
    if field:
        err["field"] = field
    return _json(status, {"error": err}, extra_headers)


def _capabilities():
    return {
        "service": "diligenceos",
        "receipt_schema": SCHEMA,
        "rules": RULES,
        "verdicts": [v.value for v in Verdict],
        "finding_statuses": [s.value for s in CheckStatus],
        "categories": list(CATEGORIES),
        "endpoints": {
            "POST /v1/verdict": {
                "request": {
                    "subject": {"name": "string", "registration_id": "string"},
                    "document_text": "string, optional",
                    "transaction": {"amount_minor": "integer minor units, never a float", "currency": "3-letter uppercase code"},
                },
                "response": "receipt (schema above)",
            },
            "POST /v1/verify": {
                "request": "a receipt, or {receipt, sources?: {source_id: text}} to also re-check evidence",
                "response": {"valid": "bool (integrity)", "expired": "bool", "revoked": "bool", "revoked_reason": "string|null", "errors": ["string"], "unchecked": ["source ids not re-checked"]},
            },
            "POST /v1/decide": {
                "request": {
                    "receipt": "a receipt",
                    "policy | policy_chain": "{max_amount: {amount_minor, currency}, acceptable_verdicts: [PROCEED|HOLD], min_trust_score: 0-100}; a chain may only narrow",
                    "sources": "optional, as for /v1/verify",
                },
                "response": {"decision": "ALLOW|ESCALATE|DENY", "reasons": ["string"], "effective_policy": "policy"},
            },
            "POST /v1/revoke": {
                "request": {"receipt_id": "sha256:<64 hex>", "reason": "string"},
                "response": {"receipt_id": "string", "reason": "string", "revoked_at": "iso8601"},
                "note": "idempotent; unauthenticated (localhost only for now)",
            },
            "GET /v1/revocations": {"response": {"revocations": "{receipt_id: {reason, revoked_at}}"}},
            "POST /v1/spend": {
                "request": {"budget_id": "string", "receipt": "a receipt", "policy | policy_chain": "as /v1/decide", "sources": "optional"},
                "response": {
                    "decision": "ALLOW|ESCALATE|DENY", "reasons": ["string"], "spent_minor": "int",
                    "remaining_minor": "int", "already_committed": "bool", "effective_policy": "policy",
                },
                "note": "commits on ALLOW; cumulative per budget_id; idempotent per receipt id",
            },
            "GET /v1/capabilities": {"response": "this document"},
        },
        "errors": {
            "shape": {"error": {"code": "string", "message": "string", "field": "optional"}},
            "codes": [
                "invalid_json", "invalid_request", "policy_widening", "not_found",
                "method_not_allowed", "body_too_large",
            ],
        },
    }


def _parse_body(body: bytes):
    if len(body) > MAX_BODY_BYTES:
        return None, _error(413, "body_too_large", f"body exceeds {MAX_BODY_BYTES} bytes")
    try:
        return json.loads(body.decode("utf-8")), None
    except (UnicodeDecodeError, ValueError) as exc:
        return None, _error(400, "invalid_json", f"body is not valid JSON: {exc}")


def _ttl_seconds() -> int:
    try:
        return int(os.environ.get("DILIGENCEOS_RECEIPT_TTL_SECONDS", DEFAULT_TTL_SECONDS))
    except ValueError:
        return DEFAULT_TTL_SECONDS


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _verdict(body: bytes, store: Store):
    data, err = _parse_body(body)
    if err:
        return err
    if not isinstance(data, dict):
        return _error(400, "invalid_request", "body must be a JSON object")
    subject = data.get("subject")
    if not isinstance(subject, dict):
        return _error(400, "invalid_request", "subject must be an object", "subject")
    for key in ("name", "registration_id"):
        value = subject.get(key)
        if not isinstance(value, str) or not value.strip():
            return _error(400, "invalid_request", f"{key} is required", f"subject.{key}")
    document_text = data.get("document_text")
    if document_text is not None and not isinstance(document_text, str):
        return _error(400, "invalid_request", "document_text must be a string", "document_text")

    transaction = None
    raw_tx = data.get("transaction")
    if raw_tx is not None:
        if not isinstance(raw_tx, dict):
            return _error(400, "invalid_request", "transaction must be an object", "transaction")
        for key in ("amount_minor", "currency"):
            try:
                Money(**{"amount_minor": 0, "currency": "USD", **{key: raw_tx.get(key)}})
            except ValueError as exc:
                return _error(400, "invalid_request", str(exc), f"transaction.{key}")
        transaction = Money.from_dict(raw_tx).to_dict()

    name, reg = subject["name"].strip(), subject["registration_id"].strip()
    result = run_diligence(
        name=name,
        registration_id=reg,
        sanctions_list=store.sanctions_list(),
        registry_lookup=store.registry_lookup(),
        ledger=store.ledger,
        document_text=document_text,
    )
    inputs = {
        "subject": {"name": name, "registration_id": reg},
        "document_text": document_text,
        "transaction": transaction,
        "data_digest": digest(store.to_dict()),
    }
    return _json(200, issue_receipt(
        subject=inputs["subject"], inputs=inputs, result=result, transaction=transaction,
        ttl_seconds=_ttl_seconds(),
    ))


def _verify(body: bytes, store: Store):
    data, err = _parse_body(body)
    if err:
        return err
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    sources = None
    if isinstance(data, dict) and "receipt" in data:  # envelope: {"receipt", "sources"?}
        sources = data.get("sources")
        if sources is not None and not (
            isinstance(sources, dict) and all(isinstance(v, str) for v in sources.values())
        ):
            return _error(400, "invalid_request", "sources must map source ids to text", "sources")
        data = data["receipt"]
    check = verify_receipt(data, now=now, sources=sources, revocations=store.revocations)
    return _json(200, {
        "valid": check.valid, "expired": check.expired,
        "revoked": check.revoked, "revoked_reason": check.revoked_reason,
        "errors": list(check.errors), "unchecked": list(check.unchecked),
    })


def _resolve_policy(data: dict):
    """(policy, None) or (None, error response). Accepts `policy` xor `policy_chain`."""
    raw_chain = data.get("policy_chain")
    if (raw_chain is None) == ("policy" not in data):
        return None, _error(400, "invalid_request", "give exactly one of policy or policy_chain", "policy")
    raw_chain = raw_chain if raw_chain is not None else [data["policy"]]
    if not isinstance(raw_chain, list) or not raw_chain:
        return None, _error(400, "invalid_request", "policy_chain must be a non-empty list", "policy_chain")
    chain = []
    for i, raw in enumerate(raw_chain):
        try:
            chain.append(Policy.from_dict(raw))
        except ValueError as exc:
            return None, _error(
                400, "invalid_request", str(exc),
                f"policy_chain[{i}]" if "policy_chain" in data else "policy",
            )
    try:
        return effective_policy(chain), None
    except WideningError as exc:
        where = f"policy_chain[{exc.link}]"
        return None, _error(400, "policy_widening", f"{where}: {exc}", f"{where}.{exc.axis}")


def _sources_of(data: dict):
    sources = data.get("sources")
    if sources is not None and not (
        isinstance(sources, dict) and all(isinstance(v, str) for v in sources.values())
    ):
        return None, _error(400, "invalid_request", "sources must map source ids to text", "sources")
    return sources, None


def _decide(body: bytes, store: Store):
    data, err = _parse_body(body)
    if err:
        return err
    if not isinstance(data, dict) or "receipt" not in data:
        return _error(400, "invalid_request", "body must be an object with a receipt", "receipt")
    policy, err = _resolve_policy(data)
    if err:
        return err
    sources, err = _sources_of(data)
    if err:
        return err
    decision = decide(
        data["receipt"], policy, now=_now(), sources=sources, revocations=store.revocations
    )
    return _json(200, {
        "decision": decision.outcome.value,
        "reasons": list(decision.reasons),
        "effective_policy": policy.to_dict(),
    })


def _revoke(body: bytes, store: Store):
    data, err = _parse_body(body)
    if err:
        return err
    if not isinstance(data, dict):
        return _error(400, "invalid_request", "body must be a JSON object")
    receipt_id, reason = data.get("receipt_id"), data.get("reason")
    if not isinstance(receipt_id, str) or not _RECEIPT_ID.match(receipt_id):
        return _error(400, "invalid_request", "receipt_id must look like sha256:<64 hex>", "receipt_id")
    if not isinstance(reason, str) or not reason.strip():
        return _error(400, "invalid_request", "reason is required", "reason")
    entry = store.revoke(receipt_id, reason.strip())
    return _json(200, {"receipt_id": receipt_id, **entry})


def _spend(body: bytes, store: Store):
    data, err = _parse_body(body)
    if err:
        return err
    if not isinstance(data, dict) or "receipt" not in data:
        return _error(400, "invalid_request", "body must be an object with a receipt", "receipt")
    budget_id = data.get("budget_id")
    if not isinstance(budget_id, str) or not budget_id.strip():
        return _error(400, "invalid_request", "budget_id is required", "budget_id")
    policy, err = _resolve_policy(data)
    if err:
        return err
    sources, err = _sources_of(data)
    if err:
        return err
    result = try_spend(store, budget_id.strip(), data["receipt"], policy, now=_now(), sources=sources)
    return _json(200, {
        "decision": result.decision.outcome.value,
        "reasons": list(result.decision.reasons),
        "spent_minor": result.spent_minor,
        "remaining_minor": result.remaining_minor,
        "already_committed": result.already_committed,
        "effective_policy": policy.to_dict(),
    })


def handle(method: str, path: str, body: bytes, store: Store):
    expected = _ROUTES.get(path)
    if expected is None:
        return _error(404, "not_found", f"no such endpoint: {path}")
    if method != expected:
        return _error(
            405, "method_not_allowed", f"{path} accepts {expected}",
            extra_headers=[("Allow", expected)],
        )
    if path == "/v1/capabilities":
        return _json(200, _capabilities())
    if path == "/v1/verdict":
        return _verdict(body, store)
    if path == "/v1/decide":
        return _decide(body, store)
    if path == "/v1/revoke":
        return _revoke(body, store)
    if path == "/v1/spend":
        return _spend(body, store)
    if path == "/v1/revocations":
        return _json(200, {"revocations": store.revocations})
    return _verify(body, store)
