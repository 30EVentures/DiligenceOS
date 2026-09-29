import copy
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from diligenceos import api
from diligenceos.engine import assemble_verdict
from diligenceos.gate import EscrowGate, release_if_allowed
from diligenceos.policy import Outcome, Policy, decide
from diligenceos.receipt import digest, issue_receipt, verify_receipt
from diligenceos.signing import (
    LOG_HEAD_DOMAIN, Signer, SignerError, head_message, verify_head, verify_signature,
)
from diligenceos.spend import try_spend
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Finding, Money, Verdict

T = "2026-09-29T12:00:00+00:00"
CLEAN = [Finding("sanctions", CheckStatus.PASS)]


def signed(signer, amount=60, subject="S"):
    return issue_receipt(
        subject={"name": subject}, inputs={"a": amount}, result=assemble_verdict(CLEAN),
        transaction={"amount_minor": amount, "currency": "USD"}, issued_at=T, signer=signer,
    )


def policy():
    return Policy(Money(100, "USD"), frozenset({Verdict.PROCEED}), 70)


class SignatureTest(unittest.TestCase):
    def test_round_trip_and_binding(self):
        s = Signer.generate()
        sig = s.sign("d", "m")
        self.assertTrue(verify_signature(s.issuer_id, "d", "m", sig))
        self.assertFalse(verify_signature(s.issuer_id, "d", "other", sig))
        self.assertFalse(verify_signature(s.issuer_id, "other-domain", "m", sig))
        self.assertFalse(verify_signature(Signer.generate().issuer_id, "d", "m", sig))

    def test_garbage_is_false_never_an_exception(self):
        s = Signer.generate()
        for args in ((None, "d", "m", "x"), ("nope", "d", "m", "nope"),
                     (s.issuer_id, "d", "m", None), (s.issuer_id, "d", "m", "ed25519:zz"),
                     ("ed25519:00", "d", "m", "ed25519:00")):
            self.assertFalse(verify_signature(*args), args)


class KeyFileTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "issuer.key"

    def tearDown(self):
        self._tmp.cleanup()

    def test_created_0600_and_stable_across_loads(self):
        first = Signer.load_or_create(self.path)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(Signer.load_or_create(self.path).issuer_id, first.issuer_id)

    def test_corrupt_key_file_raises_and_is_never_replaced(self):
        self.path.write_text("not a key")
        with self.assertRaises(SignerError):
            Signer.load_or_create(self.path)
        self.assertEqual(self.path.read_text(), "not a key")

    def test_store_signer_is_persistent_with_a_path_and_ephemeral_without(self):
        store_path = Path(self._tmp.name) / "store.json"
        a = Store.load_or_seed(store_path).signer.issuer_id
        self.assertEqual(Store.load_or_seed(store_path).signer.issuer_id, a)
        self.assertNotEqual(Store().signer.issuer_id, Store().signer.issuer_id)


class SignedReceiptTest(unittest.TestCase):
    def setUp(self):
        self.key = Signer.generate()
        self.r = signed(self.key)

    def test_signed_receipt_verifies_and_is_trusted_only_if_listed(self):
        c = verify_receipt(self.r, trusted_issuers=[self.key.issuer_id])
        self.assertTrue(c.valid, c.errors)
        self.assertEqual((c.signed, c.issuer, c.trusted), (True, self.key.issuer_id, True))
        self.assertIsNone(verify_receipt(self.r).trusted)
        self.assertFalse(verify_receipt(self.r, trusted_issuers=[]).trusted)

    def test_unsigned_receipt_is_valid_but_never_trusted(self):
        r = signed(None)
        c = verify_receipt(r, trusted_issuers=[self.key.issuer_id])
        self.assertEqual((c.valid, c.signed, c.trusted), (True, False, False))

    def test_edit_fails_id_and_resealed_edit_fails_signature(self):
        forged = copy.deepcopy(self.r)
        forged["trust_score"] = 1
        self.assertFalse(verify_receipt(forged).valid)
        body = {k: v for k, v in forged.items() if k not in ("id", "signature")}
        resealed = {**body, "id": digest(body), "signature": self.r["signature"]}
        c = verify_receipt(resealed)
        self.assertTrue(any("signature" in e for e in c.errors), c.errors)

    def test_issuer_swap_fails(self):
        other = Signer.generate()
        forged = {**self.r, "issuer": other.issuer_id}
        self.assertFalse(verify_receipt(forged).valid)  # id no longer matches
        body = {k: v for k, v in forged.items() if k not in ("id", "signature")}
        resealed = {**body, "id": digest(body), "signature": self.r["signature"]}
        self.assertFalse(verify_receipt(resealed).valid)  # signature is not other's

    def test_issuer_without_signature_is_an_error(self):
        stripped = {k: v for k, v in self.r.items() if k != "signature"}
        c = verify_receipt(stripped)
        self.assertFalse(c.valid)
        self.assertTrue(any("no signature" in e for e in c.errors))

    def test_receipt_signed_by_someone_else_is_valid_but_untrusted_and_denied(self):
        attacker = Signer.generate()
        r = signed(attacker)
        self.assertTrue(verify_receipt(r, trusted_issuers=[self.key.issuer_id]).valid)
        d = decide(r, policy(), now=T, trusted_issuers=[self.key.issuer_id])
        self.assertEqual(d.outcome, Outcome.DENY)
        self.assertIn("trusted issuer", d.reasons[0])
        self.assertEqual(decide(r, policy(), now=T).outcome, Outcome.ALLOW)  # no list: library default

    def test_gate_and_spend_enforce_trust_lists(self):
        attacker_receipt = signed(Signer.generate(), amount=60)
        trust = [self.key.issuer_id]
        gate = EscrowGate("S", Money(60, "USD"))
        self.assertFalse(release_if_allowed(gate, attacker_receipt, policy(), now=T,
                                            trusted_issuers=trust).gate.released)
        self.assertTrue(release_if_allowed(gate, signed(self.key, 60), policy(), now=T,
                                           trusted_issuers=trust).gate.released)
        store = Store()
        self.assertEqual(try_spend(store, "b", attacker_receipt, policy(), now=T,
                                   trusted_issuers=trust).decision.outcome, Outcome.DENY)
        self.assertEqual(store.spent("b", "USD"), 0)


class ApiSigningTest(unittest.TestCase):
    REQ = {"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"},
           "transaction": {"amount_minor": 24_000_000, "currency": "USD"}}
    POL = {"max_amount": {"amount_minor": 50_000_000, "currency": "USD"},
           "acceptable_verdicts": ["PROCEED"], "min_trust_score": 70}

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "store.json"
        self.store = Store.load_or_seed(self.path)

    def tearDown(self):
        self._tmp.cleanup()

    def call(self, method, path, payload=None, store=None):
        body = json.dumps(payload).encode() if payload is not None else b""
        status, _, out = api.handle(method, path, body, store or self.store)
        return status, json.loads(out)

    def test_verdict_is_signed_by_the_advertised_issuer(self):
        issuer = self.call("GET", "/v1/issuer")[1]["issuer"]
        r = self.call("POST", "/v1/verdict", self.REQ)[1]
        self.assertEqual(r["issuer"], issuer)
        v = self.call("POST", "/v1/verify", r)[1]
        self.assertEqual((v["valid"], v["signed"], v["trusted"], v["issuer"]), (True, True, True, issuer))

    def test_verify_with_a_foreign_trust_list_says_untrusted_not_invalid(self):
        r = self.call("POST", "/v1/verdict", self.REQ)[1]
        other = Signer.generate().issuer_id
        v = self.call("POST", "/v1/verify", {"receipt": r, "trusted_issuers": [other]})[1]
        self.assertEqual((v["valid"], v["signed"], v["trusted"]), (True, True, False))
        self.assertEqual(self.call("POST", "/v1/decide",
                                   {"receipt": r, "policy": self.POL, "trusted_issuers": [other]})[1]["decision"], "DENY")
        self.assertEqual(self.call("POST", "/v1/decide", {"receipt": r, "policy": self.POL})[1]["decision"], "ALLOW")

    def test_foreign_signed_receipt_is_denied_by_default_trust(self):
        foreign = signed(Signer.generate(), amount=24_000_000, subject="Meridian Robotics Ltd.")
        out = self.call("POST", "/v1/decide", {"receipt": foreign, "policy": self.POL})[1]
        self.assertEqual(out["decision"], "DENY")
        spend = self.call("POST", "/v1/spend", {"budget_id": "b", "receipt": foreign, "policy": self.POL})[1]
        self.assertEqual((spend["decision"], spend["spent_minor"]), ("DENY", 0))

    def test_bad_trusted_issuers_is_a_400(self):
        r = self.call("POST", "/v1/verdict", self.REQ)[1]
        for bad in ("x", [1], {"a": 1}):
            self.assertEqual(self.call("POST", "/v1/verify", {"receipt": r, "trusted_issuers": bad})[0], 400)

    def test_log_head_is_signed_and_verifiable_offline(self):
        self.call("POST", "/v1/verdict", self.REQ)
        head = self.call("GET", "/v1/log/head")[1]
        self.assertTrue(verify_head(head))
        for field, value in (("length", 99), ("head_hash", "sha256:" + "1" * 64)):
            self.assertFalse(verify_head({**head, field: value}), field)
        self.assertFalse(verify_head({}))
        self.assertTrue(verify_signature(head["issuer"], LOG_HEAD_DOMAIN,
                                         head_message(head["length"], head["head_hash"]), head["signature"]))

    def test_issuer_survives_a_restart(self):
        a = self.call("GET", "/v1/issuer")[1]["issuer"]
        b = self.call("GET", "/v1/issuer", store=Store.load_or_seed(self.path))[1]["issuer"]
        self.assertEqual(a, b)

    def test_corrupt_key_file_is_503_and_issues_nothing(self):
        self.call("GET", "/v1/issuer")
        self.path.with_name("issuer.key").write_text("garbage")
        fresh = Store.load_or_seed(self.path)
        for method, path, payload in (("POST", "/v1/verdict", self.REQ), ("GET", "/v1/issuer", None),
                                      ("GET", "/v1/log/head", None)):
            status, body = self.call(method, path, payload, store=fresh)
            self.assertEqual((status, body["error"]["code"]), (503, "signer_unavailable"), path)
        self.assertEqual(len(fresh.log.entries), 0)


if __name__ == "__main__":
    unittest.main()
