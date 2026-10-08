"""Machine API: JSON in, receipts out. Pure — no WSGI — so it tests directly."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import parse_qs

from diligenceos.pipeline import run_diligence
from diligenceos import manifest as manifest_doc
from diligenceos.auth import MAX_SKEW_SECONDS, authenticate
from diligenceos.delegation import DOMAIN as DELEGATION_DOMAIN, MAX_CHAIN
from diligenceos.policy import Policy, WideningError, decide, effective_policy, narrow
from diligenceos.spend import try_spend
from diligenceos.receipt_log import LogCorruptError
from diligenceos.signing import LOG_HEAD_DOMAIN, SignerError, head_message, verify_signature
from diligenceos.receipt import RULES, SCHEMA, digest, unsanitized_fields_doc, issue_receipt, verify_receipt
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Money, Verdict

MAX_BODY_BYTES = 1024 * 1024
DEFAULT_TTL_SECONDS = 24 * 60 * 60
DEFAULT_LOG_PAGE = 100  # GET /v1/log/entries: entries per page when `limit` is omitted
MAX_LOG_PAGE = 500      # ...and the most a caller may ask for; more is a 400, not a clamp
_RECEIPT_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
CATEGORIES = ("sanctions", "identity", "track_record", "document_scan")

_ROUTES = {
    "/v1/verdict": "POST",
    "/v1/verify": "POST",
    "/v1/issuer": "GET",
    "/v1/decide": "POST",
    "/v1/revoke": "POST",
    "/v1/revocations": "GET",
    "/v1/spend": "POST",
    "/v1/log/head": "GET",
    "/v1/log/entries": "GET",
    "/v1/log/conflicts": "GET",
    "/v1/log/verify": "GET",
    "/v1/log/lookup": "POST",
    "/v1/log/cosign": "POST",
    "/v1/capabilities": "GET",
    "/v1/manifest": "GET",
}
AUTHENTICATED = ("/v1/revoke", "/v1/spend")


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
        "untrusted_fields": unsanitized_fields_doc(),
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
                "request": "a receipt, or {receipt, sources?: {source_id: text}, trusted_issuers?: [issuer ids; default: this server]}",
                "response": {"signed": "bool", "issuer": "string|null", "trusted": "bool (issuer in trusted_issuers)", "valid": "bool (integrity)", "expired": "bool", "revoked": "bool", "revoked_reason": "string|null", "errors": ["string"], "unchecked": ["source ids not re-checked"]},
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
                "request": {
                    "receipt_id | delegation_id | delegation": "sha256:<64 hex> (receipt_id/delegation_id), or the full signed delegation object, to prove authorship",
                    "reason": "string", "auth": "auth envelope, scope 'revoke'",
                },
                "response": {"receipt_id | delegation_id": "string", "reason": "string", "revoked_at": "iso8601"},
                "note": "idempotent; authenticated (401 unauthenticated / 403 forbidden); only the operator may revoke a receipt or revoke a delegation by id alone; a delegate may revoke a delegation it issued itself by submitting the delegation object",
            },
            "GET /v1/revocations": {"response": {"revocations": "{id: {reason, revoked_at, revoked_by, log_seq}}", "entries": "the signed log entries (kind=revocation) that back them"}},
            "POST /v1/spend": {
                "request": {"budget_id": "string", "receipt": "a receipt", "policy | policy_chain": "as /v1/decide; optional if the credential carries a policy, and may then only narrow it", "sources": "optional", "auth": "auth envelope, scope 'spend'"},
                "response": {
                    "decision": "ALLOW|ESCALATE|DENY", "reasons": ["string"], "spent_minor": "int",
                    "remaining_minor": "int", "already_committed": "bool", "effective_policy": "policy",
                },
                "note": "commits on ALLOW; cumulative per budget_id; idempotent per receipt id",
            },
            "GET /v1/manifest": {"response": "{manifest, issuer, signature}: who runs this, the key to pin, and how to verify every signed document"},
            "GET /v1/issuer": {"response": {"issuer": "ed25519:<hex>", "algorithm": "ed25519"}},
            "GET /v1/log/head": {"response": {"length": "int", "head_hash": "string", "issuer": "string", "signature": "signed <length>:<head_hash>", "cosignatures": "witness cosignatures for this head"}},
            "POST /v1/log/cosign": {
                "request": {"issuer": "string", "length": "int", "head_hash": "string", "witness": "ed25519 id", "signature": "string"},
                "response": {"accepted": True},
                "note": "accepted only from witnesses listed in DILIGENCEOS_WITNESSES, for a head this log really has",
            },
            "GET /v1/log/entries": {
                "request": {
                    "after_seq": "query, optional integer >= 0: return only entries with seq greater than this (the cursor; omit for the first page)",
                    "limit": f"query, optional integer 1..{MAX_LOG_PAGE} (default {DEFAULT_LOG_PAGE}); outside that range is a 400, not clamped",
                },
                "response": {
                    "entries": ["log entry, in seq order"], "head_hash": "string (the head of the whole log, not of the page)",
                    "length": "int (entries in the whole log)", "has_more": "bool",
                    "next_after_seq": "int|null (pass as after_seq to get the next page)",
                },
                "note": "bounded pages; follow next_after_seq until has_more is false. The signed head from /v1/log/head covers the whole log, so a client must download every page to check it",
            },
            "GET /v1/log/conflicts": {"response": {"conflicts": ["log entry with conflict_with set"]}},
            "GET /v1/log/verify": {"response": {"valid": "bool", "errors": ["string"], "length": "int", "head_hash": "string"}},
            "POST /v1/log/lookup": {
                "request": {"receipt_id": "sha256:<64 hex>"},
                "response": {"entry": "log entry", "head_hash": "string"},
            },
            "POST /v1/verdict headers": "X-DiligenceOS-Log-Seq, X-DiligenceOS-Log-Entry-Hash, X-DiligenceOS-Log-Conflict (only on a conflict)",
            "GET /v1/capabilities": {"response": "this document"},
        },
        "auth": {
            "envelope": {
                "signer": "ed25519 id of the request key", "chain": "[delegation, ...] (empty = the operator)",
                "issued_at": "iso8601, within 300s of the server", "nonce": "single-use string",
                "signature": "over {path, body without auth, issued_at, nonce}, domain diligenceos.request/1",
            },
            "delegation": "diligenceos.delegation/1: scopes, policy?, budget_id?, expires; each link may only narrow",
        },
        "errors": {
            "shape": {"error": {"code": "string", "message": "string", "field": "optional"}},
            "codes": [
                "invalid_json", "invalid_request", "policy_widening", "not_found",
                "method_not_allowed", "body_too_large", "log_unavailable", "signer_unavailable", "unauthenticated", "forbidden",
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


def _witnesses() -> list[str]:
    return [w.strip() for w in os.environ.get("DILIGENCEOS_WITNESSES", "").split(",") if w.strip()]


def _manifest(store: Store):
    try:
        signer = store.signer
    except SignerError as exc:
        return _signer_unavailable(exc)
    doc = manifest_doc.build_manifest(
        issuer_id=signer.issuer_id, routes=_ROUTES, authenticated=AUTHENTICATED,
        witnesses=_witnesses(), generated_at=_now(),
        limits={
            "max_body_bytes": MAX_BODY_BYTES,
            "request_clock_skew_seconds": MAX_SKEW_SECONDS,
            "max_delegation_chain": MAX_CHAIN,
            "default_receipt_ttl_seconds": _ttl_seconds(),
            "default_log_entries_page": DEFAULT_LOG_PAGE,
            "max_log_entries_page": MAX_LOG_PAGE,
        },
    )
    return _json(200, manifest_doc.sign_manifest(doc, signer))


def _log_unavailable(exc: Exception):
    return _error(503, "log_unavailable", str(exc))


def _signer_unavailable(exc: Exception):
    return _error(503, "signer_unavailable", str(exc))


def _trusted_issuers(data: dict, store: Store):
    """(list, None) or (None, error). `data` must be the verifying caller's own
    request field — never the object being verified itself (that would let a
    receipt certify its own trust). Default: only this server's own issuer."""
    given = data.get("trusted_issuers")
    if given is None:
        return [store.signer.issuer_id], None
    if not (isinstance(given, list) and all(isinstance(x, str) for x in given)):
        return None, _error(400, "invalid_request", "trusted_issuers must be a list of issuer ids", "trusted_issuers")
    return given, None


def _server_trusted_issuers(store: Store) -> list[str]:
    """The operator's own trust root for /v1/spend — server-side config only,
    never influenced by the request body. A caller must never be able to name
    itself (or anyone else) trusted for a call that commits real spend; see
    docs/decisions.md, 2026-10-01."""
    return [store.signer.issuer_id]


_DIGITS = re.compile(r"^[0-9]{1,15}$")  # ASCII only: str.isdigit() would accept other scripts


def _page_params(query: str):
    """(after_seq|None, limit, None) or (None, None, error). Strict: unknown or
    repeated parameters, signs, spaces and non-ASCII digits are all a 400."""
    try:
        params = parse_qs(query, keep_blank_values=True, strict_parsing=bool(query), max_num_fields=8)
    except ValueError:
        return None, None, _error(400, "invalid_request", "query string is malformed")
    for name in params:
        if name not in ("after_seq", "limit"):
            return None, None, _error(400, "invalid_request", f"unknown query parameter {name!r}", name)
    values = {}
    for name, found in params.items():
        if len(found) != 1:
            return None, None, _error(400, "invalid_request", f"{name} may be given only once", name)
        if not _DIGITS.match(found[0]):
            return None, None, _error(400, "invalid_request", f"{name} must be a non-negative integer", name)
        values[name] = int(found[0])
    limit = values.get("limit", DEFAULT_LOG_PAGE)
    if not 1 <= limit <= MAX_LOG_PAGE:
        return None, None, _error(400, "invalid_request", f"limit must be between 1 and {MAX_LOG_PAGE}", "limit")
    return values.get("after_seq"), limit, None


def _log_endpoint(path: str, body: bytes, store: Store, query: str = ""):
    try:
        log = store.log
    except LogCorruptError as exc:
        return _log_unavailable(exc)
    if path == "/v1/log/head":
        try:
            signer = store.signer
        except SignerError as exc:
            return _signer_unavailable(exc)
        length = len(log.entries)
        return _json(200, {
            "length": length, "head_hash": log.head, "issuer": signer.issuer_id,
            "signature": signer.sign(LOG_HEAD_DOMAIN, head_message(length, log.head)),
            "cosignatures": store.cosignatures_for(log.head),
        })
    if path == "/v1/log/cosign":
        data, err = _parse_body(body)
        if err:
            return err
        if not isinstance(data, dict):
            return _error(400, "invalid_request", "body must be a cosignature object")
        allowed = _witnesses()
        if not allowed:
            return _error(403, "forbidden", "no witnesses are configured on this server", "witness")
        try:
            store.add_cosignature(data, allowed)
        except SignerError as exc:
            return _signer_unavailable(exc)
        except ValueError as exc:
            return _error(400, "invalid_request", str(exc), "cosignature")
        return _json(200, {"accepted": True})
    if path == "/v1/log/entries":
        after_seq, limit, err = _page_params(query)
        if err:
            return err
        entries = log.entries  # one snapshot: length, head and page all describe the same moment
        start = 0 if after_seq is None else after_seq + 1  # seq == position, so the cursor is stable under appends
        page = entries[start:start + limit]
        has_more = start + len(page) < len(entries)
        return _json(200, {
            "entries": page, "head_hash": entries[-1]["entry_hash"] if entries else log.head,
            "length": len(entries), "has_more": has_more,
            "next_after_seq": page[-1]["seq"] if has_more else None,
        })
    if path == "/v1/log/conflicts":
        return _json(200, {"conflicts": log.conflicts()})
    if path == "/v1/log/verify":
        errors = log.verify()
        return _json(200, {
            "valid": not errors, "errors": errors,
            "length": len(log.entries), "head_hash": log.head,
        })
    data, err = _parse_body(body)  # /v1/log/lookup
    if err:
        return err
    receipt_id = data.get("receipt_id") if isinstance(data, dict) else None
    if not isinstance(receipt_id, str) or not _RECEIPT_ID.match(receipt_id):
        return _error(400, "invalid_request", "receipt_id must look like sha256:<64 hex>", "receipt_id")
    entry = log.lookup(receipt_id)
    if entry is None:
        return _error(404, "not_found", "receipt is not in the log", "receipt_id")
    return _json(200, {"entry": entry, "head_hash": log.head})


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
    try:
        log = store.log
        signer = store.signer
    except LogCorruptError as exc:
        return _log_unavailable(exc)  # fail closed: no receipt without a log entry
    except SignerError as exc:
        return _signer_unavailable(exc)
    receipt = issue_receipt(
        subject=inputs["subject"], inputs=inputs, result=result, transaction=transaction,
        ttl_seconds=_ttl_seconds(), signer=signer,
    )
    entry = log.append(receipt, signer=signer)
    headers = [
        ("X-DiligenceOS-Log-Seq", str(entry["seq"])),
        ("X-DiligenceOS-Log-Entry-Hash", entry["entry_hash"]),
    ]
    if entry["conflict_with"] is not None:
        headers.append(("X-DiligenceOS-Log-Conflict", str(entry["conflict_with"])))
    return _json(200, receipt, headers)


def _verify(body: bytes, store: Store):
    data, err = _parse_body(body)
    if err:
        return err
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    sources = None
    # trusted_issuers may only come from the caller's own envelope fields,
    # never from the receipt being verified — otherwise a receipt posted
    # bare (no envelope) could carry its own trusted_issuers and certify
    # itself. A bare receipt gets no caller-supplied override at all.
    trusted_source: dict = {}
    if isinstance(data, dict) and "receipt" in data:  # envelope: {"receipt", "sources"?, "trusted_issuers"?}
        sources = data.get("sources")
        if sources is not None and not (
            isinstance(sources, dict) and all(isinstance(v, str) for v in sources.values())
        ):
            return _error(400, "invalid_request", "sources must map source ids to text", "sources")
        trusted_source = data
        data = data["receipt"]
    try:
        trusted, err = _trusted_issuers(trusted_source, store)
    except SignerError as exc:
        return _signer_unavailable(exc)
    if err:
        return err
    check = verify_receipt(
        data, now=now, sources=sources, revocations=store.revocations, trusted_issuers=trusted,
    )
    return _json(200, {
        "signed": check.signed, "issuer": check.issuer, "trusted": check.trusted,
        "valid": check.valid, "expired": check.expired,
        "revoked": check.revoked, "revoked_reason": check.revoked_reason,
        "errors": list(check.errors), "unchecked": list(check.unchecked),
    })


def _resolve_policy(data: dict, *, required: bool = True):
    """(policy, None) or (None, error response). Accepts `policy` xor `policy_chain`;
    with required=False, neither is allowed and yields (None, None)."""
    raw_chain = data.get("policy_chain")
    if not required and raw_chain is None and "policy" not in data:
        return None, None
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
    try:
        trusted, err = _trusted_issuers(data, store)
    except SignerError as exc:
        return _signer_unavailable(exc)
    if err:
        return err
    decision = decide(
        data["receipt"], policy, now=_now(), sources=sources, revocations=store.revocations,
        trusted_issuers=trusted,
    )
    return _json(200, {
        "decision": decision.outcome.value,
        "reasons": list(decision.reasons),
        "effective_policy": policy.to_dict(),
    })


def _authenticate(path: str, data: dict, store: Store, scope: str):
    """(AuthResult, None) or (None, error response). Strips `auth` from `data`, which
    must therefore be a dict; the signature covers everything else in it."""
    auth = data.pop("auth", None)
    if not isinstance(auth, dict):
        return None, _error(401, "unauthenticated", "this endpoint requires an auth envelope", "auth")
    try:
        root = [store.signer.issuer_id]
    except SignerError as exc:
        return None, _signer_unavailable(exc)
    result = authenticate(
        path, data, auth, root_issuers=root, now=_now(),
        revocations=store.revocations, remember_nonce=store.remember_nonce,
    )
    if not result.ok:
        return None, _error(401, "unauthenticated", "; ".join(result.errors), "auth")
    if scope not in result.scopes:
        return None, _error(403, "forbidden", f"credential does not grant the {scope!r} scope", "auth")
    return result, None


def _revoke(body: bytes, store: Store):
    data, err = _parse_body(body)
    if err:
        return err
    if not isinstance(data, dict):
        return _error(400, "invalid_request", "body must be a JSON object")
    auth, err = _authenticate("/v1/revoke", data, store, "revoke")
    if err:
        return err

    reason = data.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return _error(400, "invalid_request", "reason is required", "reason")

    # Scope: a delegate may only revoke something it (or something it issued)
    # actually created — never the whole tree. Receipts are always issued
    # with this server's own key, never a delegate's, so only the operator
    # may revoke one. A delegation names its own delegator, so a delegate can
    # revoke one of its own by presenting the signed object itself (the
    # server never stores delegations, so it has no other way to check
    # authorship); revoking by `delegation_id` alone is accepted only from
    # the operator. See docs/decisions.md, 2026-10-01.
    if "delegation" in data:
        delegation = data.get("delegation")
        if not isinstance(delegation, dict):
            return _error(400, "invalid_request", "delegation must be an object", "delegation")
        delegation_body = {k: v for k, v in delegation.items() if k not in ("id", "signature")}
        claimed_id = delegation.get("id")
        if not isinstance(claimed_id, str) or claimed_id != digest(delegation_body):
            return _error(400, "invalid_request", "delegation id does not match its contents", "delegation")
        if not verify_signature(
            delegation.get("delegator"), DELEGATION_DOMAIN, claimed_id, delegation.get("signature")
        ):
            return _error(400, "invalid_request", "delegation signature does not verify", "delegation")
        if not auth.is_root and delegation.get("delegator") != auth.caller:
            return _error(
                403, "forbidden",
                "credential may only revoke a delegation it issued itself, not the whole tree",
                "delegation",
            )
        key, target_id = "delegation_id", claimed_id
    elif "delegation_id" in data:
        if not auth.is_root:
            return _error(
                403, "forbidden",
                "revoking a delegation by id alone requires the operator; a delegate must "
                "submit the delegation object it issued (field 'delegation') instead",
                "delegation_id",
            )
        target_id = data.get("delegation_id")
        if not isinstance(target_id, str) or not _RECEIPT_ID.match(target_id):
            return _error(400, "invalid_request", "delegation_id must look like sha256:<64 hex>", "delegation_id")
        key = "delegation_id"
    else:
        if not auth.is_root:
            return _error(
                403, "forbidden",
                "only the operator may revoke a receipt (receipts are always issued by the operator's key)",
                "receipt_id",
            )
        target_id = data.get("receipt_id")
        if not isinstance(target_id, str) or not _RECEIPT_ID.match(target_id):
            return _error(400, "invalid_request", "receipt_id must look like sha256:<64 hex>", "receipt_id")
        key = "receipt_id"

    try:
        entry = store.revoke(target_id, reason.strip(), by=auth.caller)
    except LogCorruptError as exc:
        return _log_unavailable(exc)  # fail closed: no revocation without a log entry
    except SignerError as exc:
        return _signer_unavailable(exc)
    return _json(200, {key: target_id, **entry})


def _spend(body: bytes, store: Store):
    data, err = _parse_body(body)
    if err:
        return err
    if not isinstance(data, dict):
        return _error(400, "invalid_request", "body must be a JSON object")
    auth, err = _authenticate("/v1/spend", data, store, "spend")  # before any field validation
    if err:
        return err
    if "receipt" not in data:
        return _error(400, "invalid_request", "body must be an object with a receipt", "receipt")
    budget_id = data.get("budget_id")
    if not isinstance(budget_id, str) or not budget_id.strip():
        return _error(400, "invalid_request", "budget_id is required", "budget_id")
    if auth.budget_id is not None and budget_id.strip() != auth.budget_id:
        return _error(403, "forbidden", f"credential is bound to budget {auth.budget_id!r}", "budget_id")
    requested, err = _resolve_policy(data, required=auth.policy is None)
    if err:
        return err
    if auth.policy is not None and requested is not None:
        try:
            narrow(auth.policy, requested)  # a caller may only ask for less than it holds
        except WideningError as exc:
            return _error(403, "forbidden", f"requested policy widens the credential's: {exc}", f"policy.{exc.axis}")
    policy = requested if requested is not None else auth.policy
    sources, err = _sources_of(data)
    if err:
        return err
    try:
        trusted = _server_trusted_issuers(store)  # server config only; see docs/decisions.md
    except SignerError as exc:
        return _signer_unavailable(exc)
    result = try_spend(
        store, budget_id.strip(), data["receipt"], policy, now=_now(), sources=sources,
        trusted_issuers=trusted, caller=auth.caller,
    )
    return _json(200, {
        "decision": result.decision.outcome.value,
        "reasons": list(result.decision.reasons),
        "spent_minor": result.spent_minor,
        "remaining_minor": result.remaining_minor,
        "already_committed": result.already_committed,
        "effective_policy": policy.to_dict(),
    })


def handle(method: str, path: str, body: bytes, store: Store, query: str = ""):
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
    if path == "/v1/manifest":
        return _manifest(store)
    if path == "/v1/issuer":
        try:
            return _json(200, {"issuer": store.signer.issuer_id, "algorithm": "ed25519",
                               "note": "a claim, not a trust anchor: pin this key out of band"})
        except SignerError as exc:
            return _signer_unavailable(exc)
    if path.startswith("/v1/log/"):
        return _log_endpoint(path, body, store, query)
    if path == "/v1/verdict":
        return _verdict(body, store)
    if path == "/v1/decide":
        return _decide(body, store)
    if path == "/v1/revoke":
        return _revoke(body, store)
    if path == "/v1/spend":
        return _spend(body, store)
    if path == "/v1/revocations":
        try:
            entries = store.log.revocation_entries()
        except LogCorruptError as exc:
            return _log_unavailable(exc)
        return _json(200, {"revocations": store.revocations, "entries": entries})
    return _verify(body, store)
