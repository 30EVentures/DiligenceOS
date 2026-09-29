"""Glue: run every check for one subject and assemble one verdict."""

from __future__ import annotations

from diligenceos.documents import scan_document
from diligenceos.engine import assemble_verdict
from diligenceos.evidence import require_citable
from diligenceos.identity import RegistryLookup, check_identity
from diligenceos.sanctions import SanctionsList, screen_subject
from diligenceos.track_record import Ledger, check_track_record
from diligenceos.types import VerdictResult

UNCITED_CATEGORIES = frozenset({"identity", "track_record"})


def run_diligence(
    *,
    name: str,
    registration_id: str,
    sanctions_list: SanctionsList,
    registry_lookup: RegistryLookup,
    ledger: Ledger,
    document_text: str | None = None,
) -> VerdictResult:
    findings = [
        screen_subject(name, sanctions_list),
        check_identity(name, registration_id, registry_lookup),
        check_track_record(name, ledger),
    ]
    if document_text is not None:
        findings.append(scan_document(document_text))

    # Exempt in plain sight: no linkable source exists yet for these two.
    require_citable(findings, exempt_categories=UNCITED_CATEGORIES)
    return assemble_verdict(findings)
