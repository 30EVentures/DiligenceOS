"""A verdict gates a release. Small, local, illustrative — not a payment rail."""

from __future__ import annotations

from dataclasses import dataclass, replace

from diligenceos.policy import Decision, Outcome, Policy, decide
from diligenceos.types import Money, Verdict, VerdictResult


@dataclass(frozen=True)
class EscrowGate:
    subject: str
    held: Money
    released: bool = False


def apply_verdict(gate: EscrowGate, verdict_result: VerdictResult) -> EscrowGate:
    """Demo-only: releases on a bare PROCEED, ignoring amount, policy and receipt
    authenticity. Real release paths use release_if_allowed."""
    if gate.released:
        return gate  # release is one-way; nothing left to decide
    if verdict_result.verdict is Verdict.PROCEED:
        return replace(gate, released=True)
    return gate  # HOLD or RED_FLAG: stays held


@dataclass(frozen=True)
class GateOutcome:
    gate: EscrowGate
    decision: Decision


def release_if_allowed(
    gate: EscrowGate, receipt, policy: Policy, *, now: str | None = None, sources=None
) -> GateOutcome:
    decision = decide(receipt, policy, now=now, sources=sources)

    if decision.outcome is not Outcome.DENY and isinstance(receipt, dict):
        mismatches = []
        if (receipt.get("subject") or {}).get("name") != gate.subject:
            mismatches.append("receipt was issued for a different subject than this gate holds")
        if receipt.get("transaction") != gate.held.to_dict():
            mismatches.append("receipt's transaction differs from the amount this gate holds")
        if mismatches:
            decision = Decision(Outcome.DENY, tuple(mismatches))

    if decision.outcome is Outcome.ALLOW and not gate.released:
        return GateOutcome(replace(gate, released=True), decision)
    return GateOutcome(gate, decision)
