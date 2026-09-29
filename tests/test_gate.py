import unittest

from diligenceos.gate import EscrowGate, apply_verdict
from diligenceos.types import Money, Verdict, VerdictResult


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


if __name__ == "__main__":
    unittest.main()
