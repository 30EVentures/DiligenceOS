"""A verdict gates a release. Small, local, illustrative — not a payment rail."""

from __future__ import annotations

from dataclasses import dataclass, replace

from diligenceos.types import Money, Verdict, VerdictResult


@dataclass(frozen=True)
class EscrowGate:
    subject: str
    held: Money
    released: bool = False


def apply_verdict(gate: EscrowGate, verdict_result: VerdictResult) -> EscrowGate:
    if gate.released:
        return gate  # release is one-way; nothing left to decide
    if verdict_result.verdict is Verdict.PROCEED:
        return replace(gate, released=True)
    return gate  # HOLD or RED_FLAG: stays held
