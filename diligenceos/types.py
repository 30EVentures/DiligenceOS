"""Core vocabulary: what one check finds, and what one verdict looks like."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(Enum):
    PROCEED = "PROCEED"
    HOLD = "HOLD"
    RED_FLAG = "RED_FLAG"


class CheckStatus(Enum):
    PASS = "pass"
    FLAG = "flag"


@dataclass(frozen=True)
class Money:
    """Integer minor units (cents, pence) + currency. Never a float."""

    amount_minor: int
    currency: str

    def __post_init__(self) -> None:
        if isinstance(self.amount_minor, bool) or not isinstance(self.amount_minor, int):
            raise ValueError("amount_minor must be an integer count of minor units")
        if self.amount_minor < 0:
            raise ValueError("amount_minor must not be negative")
        if not (
            isinstance(self.currency, str)
            and len(self.currency) == 3
            and self.currency.isascii()
            and self.currency.isupper()
            and self.currency.isalpha()
        ):
            raise ValueError("currency must be a 3-letter uppercase code, e.g. 'USD'")

    def to_dict(self) -> dict:
        return {"amount_minor": self.amount_minor, "currency": self.currency}

    @classmethod
    def from_dict(cls, data: dict) -> "Money":
        return cls(amount_minor=data["amount_minor"], currency=data["currency"])


@dataclass(frozen=True)
class Evidence:
    """A re-checkable claim about a named source.

    Exactly one of `quote` (must appear in the source) or `absent` (must not).
    `source_digest` pins which bytes of the source the claim was made against.
    """

    source: str
    source_digest: str
    quote: str | None = None
    absent: str | None = None

    def __post_init__(self) -> None:
        if (self.quote is None) == (self.absent is None):
            raise ValueError("evidence needs exactly one of quote or absent")


@dataclass(frozen=True)
class Finding:
    category: str
    status: CheckStatus
    detail: str | None = None
    evidence_url: str | None = None
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        if self.status is CheckStatus.FLAG and not self.detail:
            raise ValueError(
                f"a FLAG finding must carry a detail (category={self.category!r}); "
                "a flag with no explanation is not a finding, it's a guess"
            )


@dataclass(frozen=True)
class VerdictResult:
    verdict: Verdict
    trust_score: int
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    expires: str | None = None

    def __post_init__(self) -> None:
        if not 0 <= self.trust_score <= 100:
            raise ValueError(
                f"trust_score must be between 0 and 100, got {self.trust_score}"
            )
