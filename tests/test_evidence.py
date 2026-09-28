import unittest

from diligenceos.evidence import EvidenceError, require_citable, verify_citation
from diligenceos.types import CheckStatus, Finding


class VerifyCitationTest(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(verify_citation("liability cap", "Section 4: liability cap of $1M"))

    def test_case_and_whitespace_insensitive(self):
        self.assertTrue(
            verify_citation("Liability   Cap", "section 4:\nliability\ncap of $1m")
        )

    def test_quote_not_present_fails(self):
        self.assertFalse(verify_citation("indemnification", "Section 4: liability cap of $1M"))


class RequireCitableTest(unittest.TestCase):
    def test_raises_on_flagged_finding_with_no_evidence_url(self):
        findings = [
            Finding(category="document_scan", status=CheckStatus.FLAG, detail="missing clause"),
        ]
        with self.assertRaises(EvidenceError):
            require_citable(findings)

    def test_does_not_raise_when_evidence_url_present(self):
        findings = [
            Finding(
                category="document_scan",
                status=CheckStatus.FLAG,
                detail="missing clause",
                evidence_url="https://example.com/contract.pdf#page=4",
            ),
        ]
        require_citable(findings)  # no raise

    def test_exempt_category_does_not_raise(self):
        findings = [
            Finding(category="sanctions", status=CheckStatus.FLAG, detail="fixture match"),
        ]
        require_citable(findings, exempt_categories=frozenset({"sanctions"}))

    def test_pass_findings_never_raise_regardless_of_evidence_url(self):
        findings = [Finding(category="identity", status=CheckStatus.PASS)]
        require_citable(findings)  # no raise

    def test_mixed_findings_one_offender_still_raises(self):
        findings = [
            Finding(category="sanctions", status=CheckStatus.FLAG, detail="fixture match"),
            Finding(category="document_scan", status=CheckStatus.FLAG, detail="missing clause"),
        ]
        with self.assertRaises(EvidenceError):
            require_citable(findings, exempt_categories=frozenset({"sanctions"}))


if __name__ == "__main__":
    unittest.main()
