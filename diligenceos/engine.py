"""Verdict assembly: many Findings in, one VerdictResult out."""

from __future__ import annotations

from typing import Iterable

from diligenceos.sanctions import CATEGORY as SANCTIONS_CATEGORY
from diligenceos.types import CheckStatus, Finding, Verdict, VerdictResult

SANCTIONS_PENALTY = 40
OTHER_PENALTY = 15


def assemble_verdict(
    findings: Iterable[Finding],
    *,
    base_trust_score: int = 85,
) -> VerdictResult:
    findings = tuple(findings)
    flagged = [f for f in findings if f.status is CheckStatus.FLAG]
    sanctions_flagged = any(f.category == SANCTIONS_CATEGORY for f in flagged)

    if sanctions_flagged:
        verdict = Verdict.RED_FLAG
    elif flagged:
        verdict = Verdict.HOLD
    else:
        verdict = Verdict.PROCEED

    score = base_trust_score
    for f in flagged:
        score -= SANCTIONS_PENALTY if f.category == SANCTIONS_CATEGORY else OTHER_PENALTY
    score = max(0, min(100, score))

    return VerdictResult(verdict=verdict, trust_score=score, findings=findings)
