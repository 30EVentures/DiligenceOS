import json
import os
import tempfile
import unittest
from pathlib import Path

from auth_helpers import as_operator
from diligenceos import api
from diligenceos.engine import assemble_verdict
from diligenceos.gate import EscrowGate, release_if_allowed
from diligenceos.policy import Outcome, Policy, decide
from diligenceos.receipt import issue_receipt, verify_receipt
from diligenceos.receipt_log import LogCorruptError
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

    def test_ttl_zero_expires_immediately_rather_than_disabling_expiry(self):
        # Fixed 2026-10-02: `if expires is None and ttl_seconds:` treated 0 the
        # same as "no TTL given" (both falsy), so DILIGENCEOS_RECEIPT_TTL_SECONDS=0
        # silently produced a receipt that never expires. 0 is a real TTL value
        # (expire at issuance), not an absent one.
        r = receipt(ttl=0)
        self.assertEqual(r["expires"], r["issued_at"])
        self.assertIsNotNone(r["expires"])
        # exactly at issuance it has not yet passed its expiry instant...
        self.assertEqual(decide(r, policy(), now=T0).outcome, Outcome.ALLOW)
        # ...but one second later it has, same as any other TTL would behave.
        d = decide(r, policy(), now="2026-09-29T12:00:01+00:00")
        self.assertEqual(d.outcome, Outcome.ESCALATE)
        self.assertTrue(any("expired" in x for x in d.reasons))

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


class RevocationCrashWindowTest(unittest.TestCase):
    """revoke() appends to the signed log first and saves the index second. A crash
    between the two used to leave a revocation that was logged but, after the
    restart, not enforced (fixed 2026-10-02: the index is reconciled with the log)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "store.json"
        self.store = Store.load_or_seed(self.path)
        self.r = issue_receipt(
            subject={"name": "S"}, inputs={}, result=assemble_verdict(CLEAN),
            transaction={"amount_minor": 60, "currency": "USD"}, issued_at=T0, signer=self.store.signer,
        )
        self.store.log.append(self.r, signer=self.store.signer)

    def crash_after_log_append(self, target=None, reason="compromised"):
        """What a process killed inside revoke() leaves behind: the signed log entry
        is on disk, the index in store.json never heard about it."""
        self.store.log.append_revocation(target or self.r["id"], reason, "ed25519:op", signer=self.store.signer)
        return Store.load_or_seed(self.path)  # the restarted server

    def test_without_reconciliation_the_gap_is_real(self):
        restarted = self.crash_after_log_append()
        self.assertIn(self.r["id"], {e["target_id"] for e in restarted.log.revocation_entries()})
        self.assertNotIn(self.r["id"], restarted._revocations)  # the raw index really lacks it

    def test_a_logged_revocation_is_enforced_after_the_restart(self):
        restarted = self.crash_after_log_append()
        self.assertEqual(restarted.revocations[self.r["id"]]["reason"], "compromised")
        self.assertEqual(restarted.revocations[self.r["id"]]["revoked_by"], "ed25519:op")
        d = decide(self.r, policy(), now=T0, revocations=restarted.revocations,
                   trusted_issuers=[restarted.signer.issuer_id])
        self.assertEqual(d.outcome, Outcome.DENY)

    def test_a_revoked_receipt_cannot_be_spent_after_the_restart(self):
        restarted = self.crash_after_log_append()
        body = as_operator(restarted, "/v1/spend", {"budget_id": "b", "receipt": self.r, "policy": policy().to_dict()})
        status, _, out = api.handle("POST", "/v1/spend", json.dumps(body).encode(), restarted)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(out)["decision"], "DENY")
        self.assertIn("revoked", json.loads(out)["reasons"][0])

    def test_a_logged_delegation_revocation_cuts_off_the_chain_after_the_restart(self):
        from diligenceos.delegation import extend_chain
        from diligenceos.signing import Signer
        agent = Signer.generate()
        chain = extend_chain([], self.store.signer, delegate=agent.issuer_id, scopes=["spend"],
                             expires="2099-01-01T00:00:00+00:00")
        restarted = self.crash_after_log_append(target=chain[0]["id"])
        from diligenceos.delegation import verify_chain
        checked = verify_chain(chain, root_issuers=[restarted.signer.issuer_id], now=T0,
                               revocations=restarted.revocations)
        self.assertFalse(checked.valid)
        self.assertTrue(any("revoked" in e for e in checked.errors))

    def test_the_index_on_disk_is_repaired(self):
        restarted = self.crash_after_log_append()
        restarted.revocations  # reconciles and saves
        on_disk = json.loads(self.path.read_text())
        self.assertIn(self.r["id"], on_disk["revocations"])

    def test_revoking_again_after_the_crash_does_not_log_a_second_entry(self):
        restarted = self.crash_after_log_append()
        before = len(restarted.log.entries)
        again = restarted.revoke(self.r["id"], "second attempt")
        self.assertEqual(again["reason"], "compromised")  # the first reason stands
        self.assertEqual(len(restarted.log.entries), before)

    def test_index_only_entries_are_kept_not_dropped(self):
        # a union, never a replacement: an entry the log never saw stays enforced
        self.store._revocations["sha256:" + "b" * 64] = {"reason": "legacy", "revoked_at": T0}
        self.store._maybe_save()
        restarted = Store.load_or_seed(self.path)
        self.assertEqual(restarted.revocations["sha256:" + "b" * 64]["reason"], "legacy")

    def test_a_normal_revoke_is_unchanged(self):
        self.store.revoke(self.r["id"], "normal")
        entries = self.store.log.revocation_entries()
        self.assertEqual([e["target_id"] for e in entries], [self.r["id"]])
        self.assertEqual(Store.load_or_seed(self.path).revocations[self.r["id"]]["reason"], "normal")

    def test_a_corrupt_log_falls_back_to_the_index_and_revoke_fails_closed(self):
        self.store.revoke("sha256:" + "c" * 64, "already indexed")
        log_file = self.path.with_name("receipts.jsonl")
        log_file.write_text(log_file.read_text() + "this is not json\n")
        restarted = Store.load_or_seed(self.path)
        self.assertIn("sha256:" + "c" * 64, restarted.revocations)  # no raise; the index still enforces
        with self.assertRaises(LogCorruptError):  # but nothing new is recorded without a usable log
            restarted.revoke("sha256:" + "d" * 64, "x")


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
        payload = as_operator(self.store, path, payload)
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

    def test_env_ttl_zero_does_not_disable_expiry(self):
        os.environ["DILIGENCEOS_RECEIPT_TTL_SECONDS"] = "0"
        try:
            r = self.verdict()
            self.assertIsNotNone(r["expires"])
            self.assertEqual(r["expires"], r["issued_at"])
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
