"""JSON wire shape for Finding / VerdictResult — added now that a CLI needs one."""

from __future__ import annotations

from diligenceos.types import CheckStatus, Finding, VerdictResult


def finding_to_dict(finding: Finding) -> dict:
    return {
        "category": finding.category,
        "status": finding.status.value,
        "detail": finding.detail,
        "evidence_url": finding.evidence_url,
    }


def verdict_result_to_dict(result: VerdictResult) -> dict:
    return {
        "verdict": result.verdict.value,
        "trust_score": result.trust_score,
        "findings": [finding_to_dict(f) for f in result.findings],
        "expires": result.expires,
    }


def finding_from_dict(data: dict) -> Finding:
    return Finding(
        category=data["category"],
        status=CheckStatus(data["status"]),
        detail=data.get("detail"),
        evidence_url=data.get("evidence_url"),
    )
