"""Machine API: JSON in, receipts out. Pure — no WSGI — so it tests directly."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from diligenceos.pipeline import run_diligence
from diligenceos.policy import Policy, WideningError, decide, effective_policy
from diligenceos.receipt import RULES, SCHEMA, digest, issue_receipt, verify_receipt
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Money, Verdict

MAX_BODY_BYTES = 1024 * 1024
CATEGORIES = ("sanctions", "identity", "track_record", "document_scan")

_ROUTES = {
    "/v1/verdict": "POST",
    "/v1/verify": "POST",
    "/v1/decide": "POST",
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
                "response": {"valid": "bool", "expired": "bool", "errors": ["string"], "unchecked": ["source ids not re-checked"]},
            },
            "POST /v1/decide": {
                "request": {
                    "receipt": "a receipt",
                    "policy | policy_chain": "{max_amount: {amount_minor, currency}, acceptable_verdicts: [PROCEED|HOLD], min_trust_score: 0-100}; a chain may only narrow",
                    "sources": "optional, as for /v1/verify",
                },
                "response": {"decision": "ALLOW|ESCALATE|DENY", "reasons": ["string"], "effective_policy": "policy"},
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
    ))


def _verify(body: bytes):
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
    check = verify_receipt(data, now=now, sources=sources)
    return _json(200, {
        "valid": check.valid, "expired": check.expired,
        "errors": list(check.errors), "unchecked": list(check.unchecked),
    })


def _decide(body: bytes):
    data, err = _parse_body(body)
    if err:
        return err
    if not isinstance(data, dict) or "receipt" not in data:
        return _error(400, "invalid_request", "body must be an object with a receipt", "receipt")
    raw_chain = data.get("policy_chain")
    if (raw_chain is None) == ("policy" not in data):
        return _error(400, "invalid_request", "give exactly one of policy or policy_chain", "policy")
    raw_chain = raw_chain if raw_chain is not None else [data["policy"]]
    if not isinstance(raw_chain, list) or not raw_chain:
        return _error(400, "invalid_request", "policy_chain must be a non-empty list", "policy_chain")
    chain = []
    for i, raw in enumerate(raw_chain):
        try:
            chain.append(Policy.from_dict(raw))
        except ValueError as exc:
            return _error(400, "invalid_request", str(exc), f"policy_chain[{i}]" if "policy_chain" in data else "policy")
    try:
        policy = effective_policy(chain)
    except WideningError as exc:
        where = f"policy_chain[{exc.link}]"
        return _error(400, "policy_widening", f"{where}: {exc}", f"{where}.{exc.axis}")
    sources = data.get("sources")
    if sources is not None and not (
        isinstance(sources, dict) and all(isinstance(v, str) for v in sources.values())
    ):
        return _error(400, "invalid_request", "sources must map source ids to text", "sources")
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    decision = decide(data["receipt"], policy, now=now, sources=sources)
    return _json(200, {
        "decision": decision.outcome.value,
        "reasons": list(decision.reasons),
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
        return _decide(body)
    return _verify(body)
