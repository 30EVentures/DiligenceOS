import unittest

from diligenceos.documents import scan_document
from diligenceos.types import CheckStatus

FULL_CONTRACT = """
Section 3: Termination. Either party may terminate with 30 days notice.
Section 4: Liability Cap. Total liability is capped at the contract value.
Section 5: Indemnification. Each party indemnifies the other for its own breaches.
"""


class ScanDocumentTest(unittest.TestCase):
    def test_all_clauses_present_passes(self):
        finding = scan_document(FULL_CONTRACT)
        self.assertEqual(finding.status, CheckStatus.PASS)

    def test_missing_one_clause_is_flagged(self):
        text = "Section 3: Termination. Section 5: Indemnification."
        finding = scan_document(text)
        self.assertEqual(finding.status, CheckStatus.FLAG)
        self.assertIn("liability cap", finding.detail)
        self.assertNotIn("termination", finding.detail)

    def test_missing_multiple_clauses_names_all(self):
        text = "This document has no relevant sections at all."
        finding = scan_document(text)
        self.assertEqual(finding.status, CheckStatus.FLAG)
        for clause in ("liability cap", "termination", "indemnification"):
            self.assertIn(clause, finding.detail)

    def test_required_clauses_are_overridable(self):
        text = "Section 1: Confidentiality. Both parties keep terms private."
        finding = scan_document(text, required_clauses=("confidentiality",))
        self.assertEqual(finding.status, CheckStatus.PASS)

    def test_matching_is_case_insensitive(self):
        text = "TERMINATION, LIABILITY CAP, and INDEMNIFICATION are all covered."
        finding = scan_document(text)
        self.assertEqual(finding.status, CheckStatus.PASS)


if __name__ == "__main__":
    unittest.main()
