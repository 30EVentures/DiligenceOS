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
