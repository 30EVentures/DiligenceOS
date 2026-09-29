import unittest

from diligenceos.engine import assemble_verdict
from diligenceos.gate import EscrowGate, apply_verdict, release_if_allowed
from diligenceos.policy import Outcome, Policy
from diligenceos.receipt import digest, issue_receipt
from diligenceos.types import CheckStatus, Finding, Money, Verdict, VerdictResult


def result(verdict, trust_score=85):
    return VerdictResult(verdict=verdict, trust_score=trust_score)


class ApplyVerdictTest(unittest.TestCase):
    def setUp(self):
        self.gate = EscrowGate(subject="Meridian Robotics Ltd.", held=Money(24000000, "USD"))

    def test_proceed_releases_a_held_gate(self):
        released = apply_verdict(self.gate, result(Verdict.PROCEED))
        self.assertTrue(released.released)
        self.assertEqual(released.held, Money(24000000, "USD"))

    def test_hold_keeps_the_gate_held(self):
        still_held = apply_verdict(self.gate, result(Verdict.HOLD, trust_score=95))
        self.assertFalse(still_held.released)

    def test_red_flag_keeps_the_gate_held_even_at_high_trust_score(self):
        still_held = apply_verdict(self.gate, result(Verdict.RED_FLAG, trust_score=100))
        self.assertFalse(still_held.released)

    def test_original_gate_is_never_mutated(self):
        apply_verdict(self.gate, result(Verdict.PROCEED))
        self.assertFalse(self.gate.released)  # the original instance is untouched

    def test_applying_proceed_again_after_release_is_a_no_op(self):
        released = apply_verdict(self.gate, result(Verdict.PROCEED))
        released_again = apply_verdict(released, result(Verdict.PROCEED))
        self.assertTrue(released_again.released)
        self.assertEqual(released_again.held, released.held)


NOW = "2026-09-29T12:00:00+00:00"
HELD = Money(24_000_000, "USD")


def policy(cap=50_000_000, floor=70, verdicts=("PROCEED",)):
    return Policy(Money(cap, "USD"), frozenset(Verdict(v) for v in verdicts), floor)


def receipt(findings=None, subject="Meridian Robotics Ltd.", tx=HELD, expires=None):
    findings = findings or [Finding("sanctions", CheckStatus.PASS)]
    r = issue_receipt(
        subject={"name": subject}, inputs={}, result=assemble_verdict(findings),
        transaction=tx.to_dict() if tx else None, issued_at=NOW,
    )
    if expires:
        body = {k: v for k, v in r.items() if k != "id"}
        body["expires"] = expires
        r = {**body, "id": digest(body)}
    return r


class ReleaseIfAllowedTest(unittest.TestCase):
    def setUp(self):
        self.gate = EscrowGate(subject="Meridian Robotics Ltd.", held=HELD)

    def out(self, r, p=None):
        return release_if_allowed(self.gate, r, p or policy(), now=NOW)

    def test_clean_matching_receipt_within_policy_releases(self):
        o = self.out(receipt())
        self.assertTrue(o.gate.released)
        self.assertEqual(o.decision.outcome, Outcome.ALLOW)

    def test_every_refusal_leaves_the_gate_held(self):
        forged = receipt()
        forged["trust_score"] = 100
        flag = [Finding("document_scan", CheckStatus.FLAG, detail="d")]
        red = [Finding("sanctions", CheckStatus.FLAG, detail="hit")]
        cases = {
            "over cap": (receipt(), policy(cap=1000)),
            "hold verdict": (receipt(flag), policy()),
            "forged": (forged, policy()),
            "red flag": (receipt(red), policy(floor=0)),
            "wrong subject": (receipt(subject="Other Ltd."), policy()),
            "wrong amount": (receipt(tx=Money(1, "USD")), policy()),
            "wrong currency": (receipt(tx=Money(24_000_000, "EUR")), policy()),
            "expired": (receipt(expires="2026-09-29T00:00:00+00:00"), policy()),
        }
        for label, (r, p) in cases.items():
            o = self.out(r, p)
            self.assertFalse(o.gate.released, label)
            self.assertNotEqual(o.decision.outcome, Outcome.ALLOW, label)

    def test_binding_mismatch_is_a_deny_with_reasons(self):
        o = self.out(receipt(subject="Other Ltd.", tx=Money(1, "USD")))
        self.assertEqual(o.decision.outcome, Outcome.DENY)
        self.assertEqual(len(o.decision.reasons), 2)

    def test_input_gate_never_mutated_and_release_is_one_way(self):
        o = self.out(receipt())
        self.assertFalse(self.gate.released)
        again = release_if_allowed(o.gate, receipt(tx=Money(1, "USD")), policy(), now=NOW)
        self.assertTrue(again.gate.released)  # already released; stays so
        self.assertEqual(again.decision.outcome, Outcome.DENY)

    def test_non_dict_receipt_denies_without_raising(self):
        self.assertEqual(self.out("nonsense").decision.outcome, Outcome.DENY)


if __name__ == "__main__":
    unittest.main()
