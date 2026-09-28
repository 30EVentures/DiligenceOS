"""Evidence discipline: a flagged finding without a citation is a bug."""

from __future__ import annotations

import re
from typing import Iterable

from diligenceos.types import CheckStatus, Finding


class EvidenceError(ValueError):
    pass


def fold(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


def verify_citation(quote: str, source_text: str) -> bool:
    return fold(quote) in fold(source_text)


def require_citable(
    findings: Iterable[Finding],
    *,
    exempt_categories: frozenset[str] = frozenset(),
) -> None:
    for f in findings:
        if f.status is not CheckStatus.FLAG:
            continue
        if f.category in exempt_categories:
            continue
        if f.evidence_url is None:
            raise EvidenceError(
                f"finding in category {f.category!r} is flagged with no evidence_url "
                f"(detail: {f.detail!r}); either supply a citable source or add "
                f"{f.category!r} to exempt_categories explicitly"
            )
