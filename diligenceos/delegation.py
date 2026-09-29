"""Signed delegations: authority that can be passed down a chain but only narrowed."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from diligenceos.policy import Policy, WideningError, narrow
from diligenceos.receipt import digest
from diligenceos.signing import Signer, verify_signature

SCHEMA = "diligenceos.delegation/1"
DOMAIN = "diligenceos.delegation/1"
SCOPES = frozenset({"spend", "revoke"})
MAX_CHAIN = 4


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _parse_time(value) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must carry a timezone")
    return parsed


def issue_delegation(
    signer: Signer,
    *,
    delegate: str,
    scopes,
    expires: str,
    policy: Policy | None = None,
    budget_id: str | None = None,
    parent: str | None = None,
    issued_at: str | None = None,
) -> dict:
    scopes = sorted(set(scopes))
    if not scopes or not set(scopes) <= SCOPES:
        raise ValueError(f"scopes must be a non-empty subset of {sorted(SCOPES)}")
    _parse_time(expires)
    body = {
        "schema": SCHEMA,
        "delegator": signer.issuer_id,
        "delegate": delegate,
        "scopes": scopes,
        "policy": policy.to_dict() if policy else None,
        "budget_id": budget_id,
        "issued_at": issued_at or _now(),
        "expires": expires,
        "parent": parent,
    }
    delegation_id = digest(body)
    return {**body, "id": delegation_id, "signature": signer.sign(DOMAIN, delegation_id)}


@dataclass(frozen=True)
class ChainResult:
    valid: bool
    errors: tuple[str, ...] = field(default_factory=tuple)
    root: str | None = None
    delegate: str | None = None
    scopes: frozenset[str] = frozenset()
    policy: Policy | None = None
    budget_id: str | None = None


def verify_chain(chain, *, root_issuers, now: str, revocations=None) -> ChainResult:
    if not isinstance(chain, list) or not chain:
        return ChainResult(False, ("delegation chain must be a non-empty list",))
    if len(chain) > MAX_CHAIN:
        return ChainResult(False, (f"delegation chain is longer than {MAX_CHAIN}",))

    errors: list[str] = []
    prev: dict | None = None
    prev_policy: Policy | None = None
    policy: Policy | None = None
    try:
        now_dt = _parse_time(now)
    except ValueError:
        return ChainResult(False, ("now is not a timezone-aware ISO-8601 timestamp",))

    for i, d in enumerate(chain):
        try:
            if not isinstance(d, dict) or d.get("schema") != SCHEMA:
                raise ValueError("unknown or missing schema")
            body = {k: v for k, v in d.items() if k not in ("id", "signature")}
            if d.get("id") != digest(body):
                errors.append(f"link {i}: id does not match the contents")
            if not verify_signature(d["delegator"], DOMAIN, str(d.get("id")), d.get("signature")):
                errors.append(f"link {i}: signature does not verify for its delegator")
            scopes = d["scopes"]
            if not (isinstance(scopes, list) and scopes and set(scopes) <= SCOPES):
                raise ValueError("scopes must be a non-empty subset of the known scopes")
            policy = Policy.from_dict(d["policy"]) if d.get("policy") is not None else None
            expires = _parse_time(d["expires"])
            if not isinstance(d["delegate"], str):
                raise ValueError("delegate must be a string")
            if now_dt >= expires:
                errors.append(f"link {i}: expired")
            if d["id"] in (revocations or {}):
                errors.append(f"link {i}: revoked")

            if prev is None:
                if d["delegator"] not in set(root_issuers):
                    errors.append("chain does not start at a trusted root")
                if d.get("parent") is not None:
                    errors.append("link 0 must not name a parent")
            else:
                if d["delegator"] != prev["delegate"]:
                    errors.append(f"link {i}: delegator is not the previous link's delegate")
                if d.get("parent") != prev["id"]:
                    errors.append(f"link {i}: parent does not name the previous link")
                if not set(scopes) <= set(prev["scopes"]):
                    errors.append(f"link {i}: widens scopes")
                if expires > _parse_time(prev["expires"]):
                    errors.append(f"link {i}: expires later than its parent")
                if prev.get("budget_id") is not None and d.get("budget_id") != prev["budget_id"]:
                    errors.append(f"link {i}: changes the budget its parent is bound to")
                if prev_policy is not None:
                    if policy is None:
                        errors.append(f"link {i}: drops the policy its parent carries")
                    else:
                        try:
                            narrow(prev_policy, policy)
                        except WideningError as exc:
                            errors.append(f"link {i}: widens {exc.axis}: {exc}")
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            errors.append(f"link {i}: malformed ({exc})")
            break
        prev, prev_policy = d, policy

    if errors:
        return ChainResult(False, tuple(errors))
    leaf = chain[-1]
    return ChainResult(
        True, (), root=chain[0]["delegator"], delegate=leaf["delegate"],
        scopes=frozenset(leaf["scopes"]), policy=policy, budget_id=leaf.get("budget_id"),
    )


def extend_chain(chain: list, signer: Signer, **kwargs) -> list:
    """Append a child delegation signed by `signer` (the chain's current leaf
    delegate). Raises ValueError, naming why, if the result would not verify —
    so a widening child is refused at creation, not first at use."""
    child = issue_delegation(signer, parent=chain[-1]["id"] if chain else None, **kwargs)
    new_chain = [*chain, child]
    result = verify_chain(
        new_chain, root_issuers=[new_chain[0]["delegator"]],
        now=child["issued_at"], revocations=None,
    )
    if not result.valid:
        raise ValueError("; ".join(result.errors))
    return new_chain
