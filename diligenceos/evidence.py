"""Evidence discipline: a flagged finding without a citation is a bug."""

from __future__ import annotations

import hashlib
import re
from typing import Iterable

from diligenceos.types import CheckStatus, Evidence, Finding


class EvidenceError(ValueError):
    pass


def fold(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


def text_digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_evidence(evidence: Evidence, source_text: str) -> list[str]:
    """Empty list means the claim holds against this source text."""
    errors = []
    if text_digest(source_text) != evidence.source_digest:
        errors.append(f"source {evidence.source!r} does not match the digest the claim was made against")
    if evidence.quote is not None and not verify_citation(evidence.quote, source_text):
        errors.append(f"quote {evidence.quote!r} not found in {evidence.source!r}")
    if evidence.absent is not None and verify_citation(evidence.absent, source_text):
        errors.append(f"{evidence.absent!r} was claimed absent but appears in {evidence.source!r}")
    return errors


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
        if f.evidence_url is None and not f.evidence:
            raise EvidenceError(
                f"finding in category {f.category!r} is flagged with no evidence or evidence_url "
                f"(detail: {f.detail!r}); either supply a citable source or add "
                f"{f.category!r} to exempt_categories explicitly"
            )
