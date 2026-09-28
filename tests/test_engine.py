import unittest

from diligenceos.engine import assemble_verdict
from diligenceos.types import CheckStatus, Finding, Verdict


def flag(category, detail="flagged"):
    return Finding(category=category, status=CheckStatus.FLAG, detail=detail)


def ok(category):
    return Finding(category=category, status=CheckStatus.PASS)


class AssembleVerdictTest(unittest.TestCase):
    def test_all_pass_is_proceed_at_base_score(self):
        result = assemble_verdict([ok("identity"), ok("sanctions")])
        self.assertEqual(result.verdict, Verdict.PROCEED)
        self.assertEqual(result.trust_score, 85)

    def test_empty_findings_is_proceed_at_base_score(self):
        result = assemble_verdict([])
        self.assertEqual(result.verdict, Verdict.PROCEED)
        self.assertEqual(result.trust_score, 85)

    def test_sanctions_flag_is_red_flag_even_with_other_passes(self):
        result = assemble_verdict([flag("sanctions"), ok("identity"), ok("track_record")])
        self.assertEqual(result.verdict, Verdict.RED_FLAG)
        self.assertEqual(result.trust_score, 45)  # 85 - 40

    def test_non_sanctions_flag_alone_is_hold(self):
        result = assemble_verdict([ok("sanctions"), flag("track_record")])
        self.assertEqual(result.verdict, Verdict.HOLD)
        self.assertEqual(result.trust_score, 70)  # 85 - 15

    def test_sanctions_flag_outranks_other_flags(self):
        result = assemble_verdict([flag("sanctions"), flag("document_scan")])
        self.assertEqual(result.verdict, Verdict.RED_FLAG)
        self.assertEqual(result.trust_score, 30)  # 85 - 40 - 15

    def test_trust_score_never_goes_below_zero(self):
        findings = [flag("sanctions")] + [flag("document_scan") for _ in range(5)]
        result = assemble_verdict(findings, base_trust_score=50)
        self.assertEqual(result.trust_score, 0)

    def test_trust_score_never_exceeds_base(self):
        result = assemble_verdict([ok("identity")], base_trust_score=100)
        self.assertEqual(result.trust_score, 100)

    def test_findings_are_preserved_on_the_result(self):
        findings = [ok("identity"), flag("sanctions")]
        result = assemble_verdict(findings)
        self.assertEqual(result.findings, tuple(findings))


if __name__ == "__main__":
    unittest.main()
