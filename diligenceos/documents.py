"""Document red-flag scan: are the expected protective clauses present at all."""

from __future__ import annotations

from diligenceos.evidence import fold, text_digest
from diligenceos.types import CheckStatus, Evidence, Finding

CATEGORY = "document_scan"
SOURCE = "input:document_text"

DEFAULT_REQUIRED_CLAUSES = ("liability cap", "termination", "indemnification")


def scan_document(
    text: str,
    *,
    required_clauses: tuple[str, ...] = DEFAULT_REQUIRED_CLAUSES,
) -> Finding:
    folded_text = fold(text)
    missing = [clause for clause in required_clauses if fold(clause) not in folded_text]

    if missing:
        source_digest = text_digest(text)
        return Finding(
            category=CATEGORY,
            status=CheckStatus.FLAG,
            detail=f"missing clause(s): {', '.join(missing)}",
            evidence=tuple(
                Evidence(source=SOURCE, source_digest=source_digest, absent=clause)
                for clause in missing
            ),
        )
    return Finding(category=CATEGORY, status=CheckStatus.PASS)
