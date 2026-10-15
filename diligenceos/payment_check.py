"""A payer's check: is there a fresh, unrevoked PROCEED receipt for this counterparty?

A library function, not an endpoint. See specs/payment-receipt-check/spec.md for what
it checks and, as importantly, what it does not (it binds no destination address and
consumes nothing).

The result is a closed vocabulary: an outcome, a reason code from `Reason`, and the
receipt's own id when that id has the shape of a digest. It never repeats text taken
from the receipt, the counterparty, or the revocation entries, so a hostile subject
name cannot reach whatever reads the decision (a log line, a model's context).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from diligenceos.policy import Outcome, Policy
from diligenceos.receipt import verify_receipt
from diligenceos.receipt_log import LogCorruptError
from diligenceos.types import MAX_AMOUNT_MINOR, Money, Verdict

CLOCK_SKEW_SECONDS = 60  # how far in the future a receipt's issued_at may be, for clock drift
_RECEIPT_ID = re.compile(r"sha256:[0-9a-f]{64}")  # used with fullmatch: "$" would also accept a trailing newline


class Reason(str, Enum):
    OK = "OK"
    # DENY: integrity, identity, freshness. Approving by hand does not fix these.
    MISSING_INPUT = "MISSING_INPUT"
    BAD_PARAMETER = "BAD_PARAMETER"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    RECEIPT_INVALID = "RECEIPT_INVALID"
    ISSUER_UNTRUSTED = "ISSUER_UNTRUSTED"
    REVOCATIONS_UNAVAILABLE = "REVOCATIONS_UNAVAILABLE"
    REVOKED = "REVOKED"
    CLOCK_UNREADABLE = "CLOCK_UNREADABLE"
    NO_EXPIRY = "NO_EXPIRY"
    EXPIRED = "EXPIRED"
    STALE = "STALE"
    FUTURE_DATED = "FUTURE_DATED"
    RED_FLAG = "RED_FLAG"
    NO_TRANSACTION = "NO_TRANSACTION"
    COUNTERPARTY_UNIDENTIFIED = "COUNTERPARTY_UNIDENTIFIED"
    SUBJECT_MISMATCH = "SUBJECT_MISMATCH"
    ASSET_UNKNOWN = "ASSET_UNKNOWN"
    CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
    AMOUNT_MISMATCH = "AMOUNT_MISMATCH"
    # ESCALATE: the payer's own policy limits, as in decide(). A human may approve.
    VERDICT_NOT_ACCEPTABLE = "VERDICT_NOT_ACCEPTABLE"
    SCORE_BELOW_FLOOR = "SCORE_BELOW_FLOOR"
    OVER_CAP = "OVER_CAP"


@dataclass(frozen=True)
class PaymentDecision:
    outcome: Outcome
    reason: Reason
    reasons: tuple[Reason, ...]
    receipt_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "outcome": self.outcome.value,
            "reason": self.reason.value,
            "reasons": [r.value for r in self.reasons],
            "receipt_id": self.receipt_id,
        }


class _Deny(Exception):
    def __init__(self, reason: Reason) -> None:
        self.reason = reason


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _text(value) -> bool:
    return isinstance(value, str) and value != ""


def _instant(value, on_fail: Reason) -> datetime:
    """An ISO-8601 timestamp that names its timezone; anything else is `on_fail`."""
    if not isinstance(value, str):
        raise _Deny(on_fail)
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        raise _Deny(on_fail) from None
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise _Deny(on_fail)
    return moment


def verify_receipt_for_payment(
    receipt, counterparty, amount_minor, asset_ref, max_age, *,
    now, trusted_issuers, revocations, policy, assets,
) -> PaymentDecision:
    """ALLOW / ESCALATE / DENY for paying `counterparty` `amount_minor` of `asset_ref`.

    Never raises on bad input: anything it cannot positively verify is a DENY.
    `now` has no default on purpose; the caller's clock is an input, not ambient state.
    """
    receipt_id = None
    try:
        if isinstance(receipt, dict) and isinstance(receipt.get("id"), str) and _RECEIPT_ID.fullmatch(receipt["id"]):
            receipt_id = receipt["id"]
        escalations = _evaluate(
            receipt, counterparty, amount_minor, asset_ref, max_age, now, trusted_issuers, revocations, policy, assets,
        )
    except _Deny as denial:
        return PaymentDecision(Outcome.DENY, denial.reason, (denial.reason,), receipt_id)
    except Exception:  # noqa: BLE001 - the gate must close on anything unforeseen, never propagate
        return PaymentDecision(Outcome.DENY, Reason.INTERNAL_ERROR, (Reason.INTERNAL_ERROR,), receipt_id)
    if escalations:
        return PaymentDecision(Outcome.ESCALATE, escalations[0], tuple(escalations), receipt_id)
    return PaymentDecision(Outcome.ALLOW, Reason.OK, (Reason.OK,), receipt_id)


def _evaluate(receipt, counterparty, amount_minor, asset_ref, max_age, now, trusted_issuers, revocations, policy, assets):
    """Raises _Deny on the first integrity/identity/freshness failure; otherwise returns
    the (possibly empty) list of policy-limit reasons."""
    # 1. Nothing may be absent.
    if None in (receipt, counterparty, amount_minor, asset_ref, max_age, now, assets, policy):
        raise _Deny(Reason.MISSING_INPUT)
    if trusted_issuers is None or (hasattr(trusted_issuers, "__len__") and len(trusted_issuers) == 0):
        raise _Deny(Reason.MISSING_INPUT)

    # 2. Parameters have exactly the shapes the caller promised.
    if not _is_int(amount_minor) or not 0 <= amount_minor <= MAX_AMOUNT_MINOR:
        raise _Deny(Reason.BAD_PARAMETER)
    if not _is_int(max_age) or max_age < 0:
        raise _Deny(Reason.BAD_PARAMETER)
    if not _text(asset_ref):
        raise _Deny(Reason.BAD_PARAMETER)
    if not isinstance(policy, Policy):
        raise _Deny(Reason.BAD_PARAMETER)
    if not isinstance(assets, Mapping) or not all(_text(k) and _text(v) for k, v in assets.items()):
        raise _Deny(Reason.BAD_PARAMETER)
    if isinstance(trusted_issuers, str) or not isinstance(trusted_issuers, (list, tuple, set, frozenset)) \
            or not all(_text(i) for i in trusted_issuers):
        raise _Deny(Reason.BAD_PARAMETER)
    if not isinstance(counterparty, dict) or not _text(counterparty.get("name")) \
            or not _text(counterparty.get("registration_id")):
        raise _Deny(Reason.COUNTERPARTY_UNIDENTIFIED)  # a name alone does not identify anyone
    clock = _instant(now, Reason.CLOCK_UNREADABLE)

    # 3. The receipt is a real, signed, trusted document.
    if not isinstance(receipt, dict):
        raise _Deny(Reason.RECEIPT_INVALID)
    check = verify_receipt(receipt, trusted_issuers=list(trusted_issuers))  # no now: freshness is judged below
    if not check.valid:
        raise _Deny(Reason.RECEIPT_INVALID)
    if check.trusted is not True:
        raise _Deny(Reason.ISSUER_UNTRUSTED)

    # 4. It has not been revoked, as far as the caller's view of revocations knows.
    if not isinstance(revocations, Mapping):
        raise _Deny(Reason.REVOCATIONS_UNAVAILABLE)
    if receipt["id"] in revocations:
        raise _Deny(Reason.REVOKED)

    # 5. It is fresh.
    if receipt.get("expires") is None:
        raise _Deny(Reason.NO_EXPIRY)
    expires = _instant(receipt["expires"], Reason.RECEIPT_INVALID)
    issued = _instant(receipt.get("issued_at"), Reason.RECEIPT_INVALID)
    if clock > expires:
        raise _Deny(Reason.EXPIRED)
    if issued > clock + timedelta(seconds=CLOCK_SKEW_SECONDS):
        raise _Deny(Reason.FUTURE_DATED)
    if clock - issued > timedelta(seconds=max_age):
        raise _Deny(Reason.STALE)

    # 6. It is a clean verdict about this counterparty and this payment.
    if receipt["verdict"] == Verdict.RED_FLAG.value:
        raise _Deny(Reason.RED_FLAG)
    if not receipt.get("transaction"):
        raise _Deny(Reason.NO_TRANSACTION)
    try:
        spent = Money.from_dict(receipt["transaction"])
    except (KeyError, TypeError, ValueError):
        raise _Deny(Reason.RECEIPT_INVALID) from None
    subject = receipt.get("subject")
    if not isinstance(subject, dict) or subject.get("name") != counterparty["name"] \
            or subject.get("registration_id") != counterparty["registration_id"]:
        raise _Deny(Reason.SUBJECT_MISMATCH)
    unit = assets.get(asset_ref)
    if unit is None:
        raise _Deny(Reason.ASSET_UNKNOWN)
    if spent.currency != unit or policy.max_amount.currency != unit:
        raise _Deny(Reason.CURRENCY_MISMATCH)
    if spent.amount_minor != amount_minor:
        raise _Deny(Reason.AMOUNT_MISMATCH)

    # 7. Only now the payer's own limits, which a human may choose to override.
    reasons = []
    if receipt["verdict"] not in {v.value for v in policy.acceptable_verdicts}:
        reasons.append(Reason.VERDICT_NOT_ACCEPTABLE)
    if receipt["trust_score"] < policy.min_trust_score:
        reasons.append(Reason.SCORE_BELOW_FLOOR)
    if amount_minor > policy.max_amount.amount_minor:
        reasons.append(Reason.OVER_CAP)
    return reasons


def revocations_for_payment(store):
    """The store's revocations, or None if they cannot be trusted.

    `Store.revocations` quietly falls back to the saved index when the signed log is
    unreadable, which is right for a server that must keep serving. A payer deciding
    whether to move money must not: an unreadable log means "unknown", so this returns
    None and `verify_receipt_for_payment` then denies with REVOCATIONS_UNAVAILABLE.
    """
    try:
        store._reconcile_revocations()  # raises LogCorruptError if the log fails verification
        return dict(store.revocations)
    except (LogCorruptError, OSError, ValueError):
        return None
