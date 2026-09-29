"""Cumulative spend against a policy cap, idempotent per receipt."""

from __future__ import annotations

from dataclasses import dataclass

from diligenceos.policy import Decision, Outcome, Policy, decide
from diligenceos.store import Store
from diligenceos.types import Money


@dataclass(frozen=True)
class SpendResult:
    decision: Decision
    spent_minor: int
    remaining_minor: int
    already_committed: bool = False


def try_spend(
    store: Store, budget_id: str, receipt, policy: Policy, *, now: str | None = None,
    sources=None, trusted_issuers=None, caller: str | None = None,
) -> SpendResult:
    cap = policy.max_amount
    spent = store.spent(budget_id, cap.currency)
    remaining = max(0, cap.amount_minor - spent)

    decision = decide(
        receipt, policy, now=now, sources=sources, revocations=store.revocations,
        trusted_issuers=trusted_issuers,
    )
    if decision.outcome is not Outcome.ALLOW:
        return SpendResult(decision, spent, remaining)

    amount = Money.from_dict(receipt["transaction"])  # decide() guarantees it is present
    if store.spend_entry(budget_id, receipt["id"]) is not None:
        return SpendResult(decision, spent, remaining, already_committed=True)

    if spent + amount.amount_minor > cap.amount_minor:
        reason = (
            f"cumulative spend would exceed the cap: {spent} already spent + "
            f"{amount.amount_minor} > {cap.amount_minor}"
        )
        return SpendResult(Decision(Outcome.ESCALATE, (reason,)), spent, remaining)

    store.commit_spend(budget_id, receipt["id"], amount, caller=caller)
    return SpendResult(decision, spent + amount.amount_minor, remaining - amount.amount_minor)
