import json
import unittest

from diligenceos import api
from diligenceos.engine import assemble_verdict
from diligenceos.policy import Outcome, Policy, WideningError, decide, effective_policy, narrow
from diligenceos.receipt import issue_receipt
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Finding, Money, Verdict

NOW = "2026-09-29T12:00:00+00:00"


def policy(cap=50_000_000, cur="USD", verdicts=("PROCEED",), floor=70):
    return Policy(Money(cap, cur), frozenset(Verdict(v) for v in verdicts), floor)


def receipt(findings=(), amount=24_000_000, cur="USD", expires=None):
    findings = list(findings) or [Finding("sanctions", CheckStatus.PASS)]
    r = issue_receipt(
        subject={"name": "X"}, inputs={}, result=assemble_verdict(findings),
        transaction=None if amount is None else {"amount_minor": amount, "currency": cur},
        issued_at=NOW,
    )
    return r


class PolicyTypeTest(unittest.TestCase):
    def test_red_flag_can_never_be_acceptable(self):
        with self.assertRaises(ValueError):
            Policy(Money(1, "USD"), frozenset({Verdict.RED_FLAG}), 0)

    def test_round_trip_and_malformed(self):
        p = policy(verdicts=("PROCEED", "HOLD"))
        self.assertEqual(Policy.from_dict(p.to_dict()), p)
        for bad in (None, {}, {**p.to_dict(), "min_trust_score": 1.5},
                    {**p.to_dict(), "max_amount": {"amount_minor": 1.5, "currency": "USD"}},
                    {**p.to_dict(), "acceptable_verdicts": ["RED_FLAG"]},
                    {**p.to_dict(), "acceptable_verdicts": "PROCEED"}):
            with self.assertRaises(ValueError, msg=bad):
                Policy.from_dict(bad)


class NarrowTest(unittest.TestCase):
    def test_only_narrower_or_equal_is_accepted(self):
        parent = policy(verdicts=("PROCEED", "HOLD"))
        self.assertEqual(narrow(parent, parent), parent)
        tighter = policy(cap=1000, verdicts=("PROCEED",), floor=90)
        self.assertEqual(narrow(parent, tighter), tighter)

    def test_each_widening_axis_is_refused(self):
        parent = policy()
        for child, axis in (
            (policy(cap=parent.max_amount.amount_minor + 1), "max_amount.amount_minor"),
            (policy(cur="EUR"), "max_amount.currency"),
            (policy(verdicts=("PROCEED", "HOLD")), "acceptable_verdicts"),
            (policy(floor=69), "min_trust_score"),
        ):
            with self.assertRaises(WideningError) as cm:
                narrow(parent, child)
            self.assertEqual(cm.exception.axis, axis)

    def test_chain_cannot_re_widen_after_narrowing(self):
        a, b, c = policy(cap=100), policy(cap=50), policy(cap=80)
        with self.assertRaises(WideningError) as cm:
            effective_policy([a, b, c])
        self.assertEqual(cm.exception.link, 2)
        self.assertEqual(effective_policy([a, b]).max_amount.amount_minor, 50)


class DecideTest(unittest.TestCase):
    def test_clean_receipt_within_limits_allows(self):
        d = decide(receipt(), policy(), now=NOW)
        self.assertEqual((d.outcome, d.reasons), (Outcome.ALLOW, ()))

    def test_each_breach_escalates_with_a_reason(self):
        cases = [
            (receipt(amount=60_000_000), policy(), "exceeds the cap"),
            (receipt(cur="EUR"), policy(), "currency"),
            (receipt(amount=None), policy(), "no transaction"),
            (receipt(), policy(floor=100), "below the minimum"),
            (receipt([Finding("document_scan", CheckStatus.FLAG, detail="d")]), policy(), "not acceptable"),
        ]
        for r, p, needle in cases:
            d = decide(r, p, now=NOW)
            self.assertEqual(d.outcome, Outcome.ESCALATE, needle)
            self.assertTrue(any(needle in x for x in d.reasons), (needle, d.reasons))

    def test_hold_is_allowed_only_if_policy_says_so(self):
        r = receipt([Finding("document_scan", CheckStatus.FLAG, detail="d")])
        loose = policy(verdicts=("PROCEED", "HOLD"), floor=0)
        self.assertEqual(decide(r, loose, now=NOW).outcome, Outcome.ALLOW)

    def test_red_flag_and_forged_receipts_deny(self):
        red = receipt([Finding("sanctions", CheckStatus.FLAG, detail="hit")])
        self.assertEqual(decide(red, policy(floor=0), now=NOW).outcome, Outcome.DENY)
        forged = receipt()
        forged["verdict"] = "HOLD"
        self.assertEqual(decide(forged, policy(), now=NOW).outcome, Outcome.DENY)
        self.assertEqual(decide("nonsense", policy(), now=NOW).outcome, Outcome.DENY)

    def test_multiple_reasons_are_all_listed(self):
        d = decide(receipt(amount=60_000_000), policy(floor=100), now=NOW)
        self.assertEqual(len(d.reasons), 2)


class ApiDecideTest(unittest.TestCase):
    def setUp(self):
        self.store = Store.seeded_from_sample()
        req = {"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"},
               "transaction": {"amount_minor": 24_000_000, "currency": "USD"}}
        _, _, out = api.handle("POST", "/v1/verdict", json.dumps(req).encode(), self.store)
        self.receipt = json.loads(out)

    def decide(self, body):
        status, _, out = api.handle("POST", "/v1/decide", json.dumps(body).encode(), self.store)
        return status, json.loads(out)

    def test_allow_and_escalate(self):
        p = policy().to_dict()
        status, out = self.decide({"receipt": self.receipt, "policy": p})
        self.assertEqual((status, out["decision"]), (200, "ALLOW"))
        tight = policy(cap=1000).to_dict()
        chain = self.decide({"receipt": self.receipt, "policy_chain": [p, tight]})[1]
        self.assertEqual(chain["decision"], "ESCALATE")
        self.assertEqual(chain["effective_policy"]["max_amount"]["amount_minor"], 1000)

    def test_widening_chain_is_a_400_naming_the_link(self):
        wide = policy(cap=99_000_000).to_dict()
        status, out = self.decide({"receipt": self.receipt, "policy_chain": [policy().to_dict(), wide]})
        self.assertEqual(status, 400)
        self.assertEqual(out["error"]["code"], "policy_widening")
        self.assertEqual(out["error"]["field"], "policy_chain[1].max_amount.amount_minor")

    def test_bad_requests(self):
        for body in ({}, {"receipt": self.receipt}, {"receipt": self.receipt, "policy": {}},
                     {"receipt": self.receipt, "policy": policy().to_dict(), "policy_chain": []},
                     {"receipt": self.receipt, "policy_chain": []}):
            self.assertEqual(self.decide(body)[0], 400, body)

    def test_forged_receipt_denies(self):
        self.receipt["trust_score"] = 100
        self.assertEqual(self.decide({"receipt": self.receipt, "policy": policy().to_dict()})[1]["decision"], "DENY")


if __name__ == "__main__":
    unittest.main()
