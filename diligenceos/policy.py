"""Delegated authority that only narrows, and the decision a receipt yields against it."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from diligenceos.receipt import verify_receipt
from diligenceos.types import Money, Verdict


class WideningError(ValueError):
    def __init__(self, axis: str, message: str) -> None:
        super().__init__(message)
        self.axis = axis
        self.link: int | None = None  # index in the chain, set by effective_policy


@dataclass(frozen=True)
class Policy:
    max_amount: Money
    acceptable_verdicts: frozenset[Verdict]
    min_trust_score: int

    def __post_init__(self) -> None:
        if Verdict.RED_FLAG in self.acceptable_verdicts:
            raise ValueError("RED_FLAG can never be an acceptable verdict")
        if not all(isinstance(v, Verdict) for v in self.acceptable_verdicts):
            raise ValueError("acceptable_verdicts must be Verdict values")
        if isinstance(self.min_trust_score, bool) or not isinstance(self.min_trust_score, int) \
                or not 0 <= self.min_trust_score <= 100:
            raise ValueError("min_trust_score must be an integer from 0 to 100")

    def to_dict(self) -> dict:
        return {
            "max_amount": self.max_amount.to_dict(),
            "acceptable_verdicts": sorted(v.value for v in self.acceptable_verdicts),
            "min_trust_score": self.min_trust_score,
        }

    @classmethod
    def from_dict(cls, data) -> "Policy":
        if not isinstance(data, dict):
            raise ValueError("policy must be an object")
        try:
            verdicts = data["acceptable_verdicts"]
            if not isinstance(verdicts, list):
                raise ValueError("acceptable_verdicts must be a list")
            return cls(
                max_amount=Money.from_dict(data["max_amount"]),
                acceptable_verdicts=frozenset(Verdict(v) for v in verdicts),
                min_trust_score=data["min_trust_score"],
            )
        except (KeyError, TypeError) as exc:
            raise ValueError(f"policy is missing or malformed: {exc!r}") from exc


def narrow(parent: Policy, child: Policy) -> Policy:
    if child.max_amount.currency != parent.max_amount.currency:
        raise WideningError("max_amount.currency", "currency differs from the parent's")
    if child.max_amount.amount_minor > parent.max_amount.amount_minor:
        raise WideningError("max_amount.amount_minor", "cap is larger than the parent's")
    if not child.acceptable_verdicts <= parent.acceptable_verdicts:
        raise WideningError("acceptable_verdicts", "accepts a verdict the parent does not")
    if child.min_trust_score < parent.min_trust_score:
        raise WideningError("min_trust_score", "trust floor is lower than the parent's")
    return child


def effective_policy(chain: list[Policy]) -> Policy:
    if not chain:
        raise ValueError("a policy chain needs at least one policy")
    current = chain[0]
    for i, child in enumerate(chain[1:], start=1):
        try:
            current = narrow(current, child)
        except WideningError as exc:
            exc.link = i
            raise
    return current


class Outcome(Enum):
    ALLOW = "ALLOW"
    ESCALATE = "ESCALATE"
    DENY = "DENY"


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reasons: tuple[str, ...]


def decide(
    receipt, policy: Policy, *, now: str | None = None, sources=None, revocations=None,
    trusted_issuers=None,
) -> Decision:
    check = verify_receipt(
        receipt, now=now, sources=sources, revocations=revocations,
        trusted_issuers=trusted_issuers,
    )
    if not check.valid:
        return Decision(Outcome.DENY, tuple(f"receipt invalid: {e}" for e in check.errors))
    if check.trusted is False:
        return Decision(Outcome.DENY, ("receipt is not validly signed by a trusted issuer",))
    if check.revoked:
        return Decision(Outcome.DENY, (f"receipt was revoked: {check.revoked_reason}",))
    if receipt["verdict"] == Verdict.RED_FLAG.value:
        return Decision(Outcome.DENY, ("verdict is RED_FLAG",))

    reasons = []
    if receipt["verdict"] not in {v.value for v in policy.acceptable_verdicts}:
        reasons.append(f"verdict {receipt['verdict']} is not acceptable under this policy")
    if receipt["trust_score"] < policy.min_trust_score:
        reasons.append(
            f"trust score {receipt['trust_score']} is below the minimum {policy.min_trust_score}"
        )
    tx = receipt.get("transaction")
    if not tx:
        reasons.append("receipt carries no transaction, so the amount cannot be checked")
    elif tx["currency"] != policy.max_amount.currency:
        reasons.append(f"currency {tx['currency']} differs from policy {policy.max_amount.currency}")
    elif tx["amount_minor"] > policy.max_amount.amount_minor:
        reasons.append(
            f"amount {tx['amount_minor']} exceeds the cap {policy.max_amount.amount_minor}"
        )
    if check.expired:
        reasons.append("receipt has expired; run a fresh check")

    return Decision(Outcome.ESCALATE if reasons else Outcome.ALLOW, tuple(reasons))
