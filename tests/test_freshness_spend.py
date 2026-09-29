import json
import os
import tempfile
import unittest
from pathlib import Path

from diligenceos import api
from diligenceos.engine import assemble_verdict
from diligenceos.gate import EscrowGate, release_if_allowed
from diligenceos.policy import Outcome, Policy, decide
from diligenceos.receipt import issue_receipt, verify_receipt
from diligenceos.spend import try_spend
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Finding, Money, Verdict

T0 = "2026-09-29T12:00:00+00:00"
CLEAN = [Finding("sanctions", CheckStatus.PASS)]


def policy(cap=100, floor=70):
    return Policy(Money(cap, "USD"), frozenset({Verdict.PROCEED}), floor)


def receipt(amount=60, subject="S", ttl=None, issued_at=T0):
    return issue_receipt(
        subject={"name": subject}, inputs={"n": amount, "s": subject},
        result=assemble_verdict(CLEAN),
        transaction={"amount_minor": amount, "currency": "USD"},
        issued_at=issued_at, ttl_seconds=ttl,
    )


class FreshnessTest(unittest.TestCase):
    def test_ttl_sets_expires_from_issued_at(self):
        self.assertEqual(receipt(ttl=3600)["expires"], "2026-09-29T13:00:00+00:00")
        self.assertIsNone(receipt()["expires"])

    def test_expired_receipt_escalates(self):
        r = receipt(ttl=60)
        self.assertEqual(decide(r, policy(), now="2026-09-29T12:00:30+00:00").outcome, Outcome.ALLOW)
        d = decide(r, policy(), now="2026-09-29T12:05:00+00:00")
        self.assertEqual(d.outcome, Outcome.ESCALATE)
        self.assertTrue(any("expired" in x for x in d.reasons))


class RevocationTest(unittest.TestCase):
    def test_revoked_is_valid_but_denied(self):
        r = receipt()
        revs = {r["id"]: {"reason": "subject re-listed", "revoked_at": T0}}
        check = verify_receipt(r, revocations=revs)
        self.assertTrue(check.valid)
        self.assertTrue(check.revoked)
        self.assertEqual(check.revoked_reason, "subject re-listed")
        d = decide(r, policy(), now=T0, revocations=revs)
        self.assertEqual(d.outcome, Outcome.DENY)
        self.assertIn("subject re-listed", d.reasons[0])

    def test_gate_refuses_a_revoked_receipt(self):
        r = receipt(amount=60)
        gate = EscrowGate("S", Money(60, "USD"))
        revs = {r["id"]: {"reason": "x"}}
        self.assertFalse(release_if_allowed(gate, r, policy(), now=T0, revocations=revs).gate.released)
        self.assertTrue(release_if_allowed(gate, r, policy(), now=T0).gate.released)

    def test_store_revoke_is_idempotent_and_persists_without_changing_data_digest(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.json"
            s = Store.load_or_seed(path)
            before = s.to_dict()
            first = s.revoke("sha256:" + "a" * 64, "first")
            again = s.revoke("sha256:" + "a" * 64, "second")
            self.assertEqual(first, again)
            self.assertEqual(s.to_dict(), before)
            reloaded = Store.load_or_seed(path)
            self.assertEqual(reloaded.revocations["sha256:" + "a" * 64]["reason"], "first")


class SpendTest(unittest.TestCase):
    def setUp(self):
        self.store = Store()

    def spend(self, r, budget="b1", p=None):
        return try_spend(self.store, budget, r, p or policy(), now=T0)

    def test_budget_accumulates_and_second_payment_escalates(self):
        a, b = receipt(60, subject="A"), receipt(60, subject="B")
        first = self.spend(a)
        self.assertEqual((first.decision.outcome, first.spent_minor, first.remaining_minor),
                         (Outcome.ALLOW, 60, 40))
        second = self.spend(b)
        self.assertEqual(second.decision.outcome, Outcome.ESCALATE)
        self.assertIn("cumulative", second.decision.reasons[0])
        self.assertEqual((second.spent_minor, second.remaining_minor), (60, 40))  # nothing committed

    def test_same_receipt_twice_spends_once(self):
        a = receipt(60)
        self.spend(a)
        again = self.spend(a)
        self.assertTrue(again.already_committed)
        self.assertEqual(again.decision.outcome, Outcome.ALLOW)
        self.assertEqual(self.store.spent("b1", "USD"), 60)

    def test_budgets_are_independent(self):
        self.spend(receipt(60, subject="A"))
        other = self.spend(receipt(60, subject="B"), budget="b2")
        self.assertEqual(other.decision.outcome, Outcome.ALLOW)

    def test_non_allow_never_commits(self):
        r = receipt(60)
        revs_store = self.store
        revs_store.revoke(r["id"], "nope")
        res = self.spend(r)
        self.assertEqual(res.decision.outcome, Outcome.DENY)
        self.assertEqual(self.store.spent("b1", "USD"), 0)
        self.assertEqual(self.spend(receipt(500, subject="big")).decision.outcome, Outcome.ESCALATE)
        self.assertEqual(self.store.spent("b1", "USD"), 0)

    def test_spend_persists_across_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.json"
            s = Store.load_or_seed(path)
            try_spend(s, "b1", receipt(60), policy(), now=T0)
            self.assertEqual(Store.load_or_seed(path).spent("b1", "USD"), 60)


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.store = Store.seeded_from_sample()
        self.pol = policy(cap=50_000_000).to_dict()

    def call(self, method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else b""
        status, _, out = api.handle(method, path, body, self.store)
        return status, json.loads(out)

    def verdict(self, name="Meridian Robotics Ltd.", amount=24_000_000):
        req = {"subject": {"name": name, "registration_id": "UK09456213"},
               "transaction": {"amount_minor": amount, "currency": "USD"}}
        return self.call("POST", "/v1/verdict", req)[1]

    def test_default_ttl_is_24h_and_env_overrides(self):
        r = self.verdict()
        from datetime import datetime
        delta = datetime.fromisoformat(r["expires"]) - datetime.fromisoformat(r["issued_at"])
        self.assertEqual(delta.total_seconds(), 86400)
        os.environ["DILIGENCEOS_RECEIPT_TTL_SECONDS"] = "60"
        try:
            r2 = self.verdict()
            self.assertEqual(
                (datetime.fromisoformat(r2["expires"]) - datetime.fromisoformat(r2["issued_at"])).total_seconds(), 60)
        finally:
            del os.environ["DILIGENCEOS_RECEIPT_TTL_SECONDS"]

    def test_revoke_flow_shows_in_verify_decide_and_list(self):
        r = self.verdict()
        self.assertFalse(self.call("POST", "/v1/verify", r)[1]["revoked"])
        status, out = self.call("POST", "/v1/revoke", {"receipt_id": r["id"], "reason": "counterparty flagged"})
        self.assertEqual((status, out["reason"]), (200, "counterparty flagged"))
        v = self.call("POST", "/v1/verify", r)[1]
        self.assertEqual((v["valid"], v["revoked"], v["revoked_reason"]), (True, True, "counterparty flagged"))
        self.assertEqual(self.call("POST", "/v1/decide", {"receipt": r, "policy": self.pol})[1]["decision"], "DENY")
        self.assertIn(r["id"], self.call("GET", "/v1/revocations")[1]["revocations"])

    def test_revoke_validation(self):
        for body in ({}, {"receipt_id": "abc", "reason": "x"}, {"receipt_id": "sha256:" + "a" * 64},
                     {"receipt_id": "sha256:" + "a" * 64, "reason": "  "}):
            self.assertEqual(self.call("POST", "/v1/revoke", body)[0], 400, body)

    def test_spend_flow(self):
        pol = policy(cap=30_000_000).to_dict()
        a = self.verdict(amount=20_000_000)
        b = self.verdict(name="Meridian Robotics Ltd.", amount=20_000_001)
        s1 = self.call("POST", "/v1/spend", {"budget_id": "q4", "receipt": a, "policy": pol})[1]
        self.assertEqual((s1["decision"], s1["spent_minor"], s1["remaining_minor"]), ("ALLOW", 20_000_000, 10_000_000))
        s2 = self.call("POST", "/v1/spend", {"budget_id": "q4", "receipt": b, "policy": pol})[1]
        self.assertEqual(s2["decision"], "ESCALATE")
        s3 = self.call("POST", "/v1/spend", {"budget_id": "q4", "receipt": a, "policy": pol})[1]
        self.assertTrue(s3["already_committed"])
        self.assertEqual(s3["spent_minor"], 20_000_000)

    def test_spend_validation(self):
        r = self.verdict()
        for body in ({"receipt": r, "policy": self.pol}, {"budget_id": "", "receipt": r, "policy": self.pol},
                     {"budget_id": "b", "receipt": r}, {"budget_id": "b", "policy": self.pol}):
            self.assertEqual(self.call("POST", "/v1/spend", body)[0], 400, body)

    def test_capabilities_lists_new_endpoints(self):
        eps = self.call("GET", "/v1/capabilities")[1]["endpoints"]
        for name in ("POST /v1/revoke", "GET /v1/revocations", "POST /v1/spend"):
            self.assertIn(name, eps)


if __name__ == "__main__":
    unittest.main()
