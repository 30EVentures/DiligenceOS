import unittest

from diligenceos.types import CheckStatus, Finding, Verdict, VerdictResult


class FindingTest(unittest.TestCase):
    def test_pass_needs_no_detail(self):
        f = Finding(category="identity", status=CheckStatus.PASS)
        self.assertEqual(f.category, "identity")
        self.assertIsNone(f.detail)

    def test_flag_with_detail_is_valid(self):
        f = Finding(
            category="track_record",
            status=CheckStatus.FLAG,
            detail="2 of 5 past deliveries late more than 30 days",
            evidence_url="https://example.com/delivery-log#L14",
        )
        self.assertEqual(f.status, CheckStatus.FLAG)
        self.assertTrue(f.detail)

    def test_flag_without_detail_is_rejected(self):
        with self.assertRaises(ValueError):
            Finding(category="track_record", status=CheckStatus.FLAG)

    def test_flag_with_empty_detail_is_rejected(self):
        with self.assertRaises(ValueError):
            Finding(category="track_record", status=CheckStatus.FLAG, detail="")


class VerdictResultTest(unittest.TestCase):
    def test_valid_construction(self):
        result = VerdictResult(
            verdict=Verdict.HOLD,
            trust_score=61,
            findings=(
                Finding(category="identity", status=CheckStatus.PASS),
                Finding(
                    category="document_scan",
                    status=CheckStatus.FLAG,
                    detail="liability cap clause missing, page 4",
                ),
            ),
            expires="2026-10-05T00:00:00Z",
        )
        self.assertEqual(result.verdict, Verdict.HOLD)
        self.assertEqual(len(result.findings), 2)

    def test_trust_score_above_range_is_rejected(self):
        with self.assertRaises(ValueError):
            VerdictResult(verdict=Verdict.PROCEED, trust_score=101)

    def test_trust_score_below_range_is_rejected(self):
        with self.assertRaises(ValueError):
            VerdictResult(verdict=Verdict.PROCEED, trust_score=-1)

    def test_trust_score_boundaries_are_valid(self):
        VerdictResult(verdict=Verdict.RED_FLAG, trust_score=0)
        VerdictResult(verdict=Verdict.PROCEED, trust_score=100)


if __name__ == "__main__":
    unittest.main()
