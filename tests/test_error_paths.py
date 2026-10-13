"""Round 6 of the overnight review: error branches the suite never reached, found with the
stdlib line tracer (python -m trace --count --missing)."""

import contextlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from auth_helpers import as_operator
from diligenceos import api, tools
from diligenceos.conformance import answer, test_signer
from diligenceos.engine import assemble_verdict
from diligenceos.payment_check import Reason, verify_receipt_for_payment
from diligenceos.policy import Outcome, Policy, effective_policy
from diligenceos.receipt import issue_receipt
from diligenceos.store import Store
from diligenceos.types import CheckStatus, Finding, Money, Verdict

SUBJECT = {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"}
POLICY = Policy(Money(50_000_000, "USD"), frozenset({Verdict.PROCEED}), 70)


def call(store, method, path, payload=None, raw=None, auth=True):
    if raw is None and payload is not None:
        payload = as_operator(store, path, payload) if auth else payload
        raw = json.dumps(payload).encode()
    status, _, out = api.handle(method, path, raw or b"", store)
    return status, json.loads(out)


class ReceiptTtlConfigTest(unittest.TestCase):
    def issue(self, value):
        with mock.patch.dict(os.environ, {"DILIGENCEOS_RECEIPT_TTL_SECONDS": value}):
            status, body = call(Store(), "POST", "/v1/verdict", {"subject": SUBJECT}, auth=False)
        self.assertEqual(status, 200, (value, body))
        issued = api.datetime.fromisoformat(body["issued_at"])
        return (api.datetime.fromisoformat(body["expires"]) - issued).total_seconds()

    def test_a_sane_value_is_used(self):
        self.assertEqual(self.issue("3600"), 3600)
        self.assertEqual(self.issue("0"), 0)

    def test_nonsense_overflow_negative_and_centuries_fall_back_to_the_default(self):
        for value in ("abc", "", "-5", "99999999999999999999999", "99999999999", str(api.MAX_TTL_SECONDS + 1)):
            self.assertEqual(self.issue(value), api.DEFAULT_TTL_SECONDS, value)
        self.assertEqual(self.issue(str(api.MAX_TTL_SECONDS)), api.MAX_TTL_SECONDS)


class ApiBranchesTest(unittest.TestCase):
    def setUp(self):
        self.store = Store.seeded_from_sample()
        _, self.receipt = call(self.store, "POST", "/v1/verdict",
                               {"subject": SUBJECT, "transaction": {"amount_minor": 5, "currency": "USD"}}, auth=False)

    def test_unparseable_bodies_are_400_on_every_post_route(self):
        for path in ("/v1/verify", "/v1/decide", "/v1/revoke", "/v1/spend", "/v1/log/lookup", "/v1/log/cosign", "/v1/verdict"):
            status, body = call(self.store, "POST", path, raw=b"{nope")
            self.assertEqual((status, body["error"]["code"]), (400, "invalid_json"), path)

    def test_authenticated_routes_want_an_object_before_anything_else(self):
        for path in ("/v1/revoke", "/v1/spend"):
            for raw in (b"[]", b"5", b'"x"', b"null"):
                status, body = call(self.store, "POST", path, raw=raw)
                self.assertEqual((status, body["error"]["code"]), (400, "invalid_request"), (path, raw))

    def test_sources_must_map_names_to_text(self):
        for sources in ([], {"a": 1}, {"a": None}, "x", 5):
            status, body = call(self.store, "POST", "/v1/verify", {"receipt": self.receipt, "sources": sources}, auth=False)
            self.assertEqual((status, body["error"]["field"]), (400, "sources"), sources)
            status, body = call(self.store, "POST", "/v1/decide",
                                {"receipt": self.receipt, "policy": POLICY.to_dict(), "sources": sources}, auth=False)
            self.assertEqual((status, body["error"]["field"]), (400, "sources"), sources)

    def test_revoke_validates_its_delegation_arguments(self):
        status, body = call(self.store, "POST", "/v1/revoke", {"reason": "x", "delegation": "not an object"})
        self.assertEqual((status, body["error"]["field"]), (400, "delegation"))
        for bad in ("", "sha256:abc", 5, None, "sha256:" + "A" * 64, "sha256:" + "a" * 64 + "\n"):
            status, body = call(self.store, "POST", "/v1/revoke", {"reason": "x", "delegation_id": bad})
            self.assertEqual((status, body["error"]["field"]), (400, "delegation_id"), bad)
            status, body = call(self.store, "POST", "/v1/revoke", {"reason": "x", "receipt_id": bad})
            self.assertEqual((status, body["error"]["field"]), (400, "receipt_id"), bad)

    def test_a_broken_key_file_is_503_on_every_route_that_needs_the_signer(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "store.json"
            store = Store.load_or_seed(path)
            receipt = call(store, "POST", "/v1/verdict", {"subject": SUBJECT, "transaction": {"amount_minor": 5, "currency": "USD"}}, auth=False)[1]
            path.with_name("issuer.key").write_text("garbage")
            broken = Store.load_or_seed(path)
            for method, route, payload in (
                ("POST", "/v1/verify", {"receipt": receipt}),
                ("POST", "/v1/decide", {"receipt": receipt, "policy": POLICY.to_dict()}),
                ("POST", "/v1/revoke", {"receipt_id": receipt["id"], "reason": "x", "auth": {"signer": "s"}}),
                ("POST", "/v1/spend", {"budget_id": "b", "receipt": receipt, "policy": POLICY.to_dict(), "auth": {"signer": "s"}}),
                ("POST", "/v1/log/cosign", {"issuer": "x"}),
                ("GET", "/v1/manifest", None),
            ):
                raw = json.dumps(payload).encode() if payload is not None else b""
                with mock.patch.dict(os.environ, {"DILIGENCEOS_WITNESSES": "w"}):
                    status, _, out = api.handle(method, route, raw, broken)
                self.assertEqual(status, 503, (route, out[:100]))
                self.assertEqual(json.loads(out)["error"]["code"], "signer_unavailable", route)


class PaymentCheckBranchesTest(unittest.TestCase):
    def test_a_trusted_issuer_who_signs_nonsense_money_is_still_refused(self):
        signer = test_signer(5)
        for transaction in ({"amount_minor": -1, "currency": "USD"}, {"amount_minor": 1.5, "currency": "USD"},
                            {"amount_minor": 5, "currency": "usd"}, {"currency": "USD"}, {"amount_minor": 2**53, "currency": "USD"}):
            receipt = issue_receipt(subject={"name": "A", "registration_id": "R"}, inputs={},
                                    result=assemble_verdict([Finding("sanctions", CheckStatus.PASS)]), transaction=transaction,
                                    issued_at="2026-10-13T11:00:00+00:00", ttl_seconds=7200, signer=signer)
            got = verify_receipt_for_payment(
                receipt, {"name": "A", "registration_id": "R"}, 5, "T@c", 7200, now="2026-10-13T12:00:00+00:00",
                trusted_issuers=[signer.issuer_id], revocations={}, policy=POLICY, assets={"T@c": "USD"})
            self.assertEqual((got.outcome, got.reason), (Outcome.DENY, Reason.RECEIPT_INVALID), transaction)


class SmallBranchesTest(unittest.TestCase):
    def test_an_empty_policy_chain_has_no_effective_policy(self):
        with self.assertRaises(ValueError):
            effective_policy([])

    def test_a_policy_built_in_code_refuses_non_verdict_members(self):
        with self.assertRaises(ValueError):
            Policy(Money(1, "USD"), frozenset({"PROCEED"}), 0)

    def test_the_conformance_adapter_answers_an_unknown_set_and_a_malformed_case(self):
        self.assertIn("error", answer({"id": "x", "set": "no-such-set", "input": None}))
        self.assertIn("crash", answer({"id": "y"}))   # reported as a crash, which the runner scores as unreadable

    def test_cosign_submission_reports_a_refusal_in_the_servers_words(self):
        body = io.BytesIO(json.dumps({"error": {"message": "witness is not listed"}}).encode())
        refusal = urllib.error.HTTPError("http://x/v1/log/cosign", 400, "Bad Request", {}, body)
        with mock.patch("urllib.request.urlopen", side_effect=refusal):
            args = mock.Mock(url="http://x", issuer="i", key="k", state="s", submit=True)
            captured = {}

            def fake_run(fetch, state, signer, issuer, submit=None):
                captured["note"] = submit({"cosignature": 1})
                return 0, "ok", None

            with mock.patch("diligenceos.witness.run_witness", fake_run), \
                    mock.patch("diligenceos.tools.Signer.load_or_create", return_value=test_signer(7)):
                with contextlib.redirect_stdout(io.StringIO()):
                    tools._witness(args)
        self.assertIn("400", captured["note"])
        self.assertIn("witness is not listed", captured["note"])


class MachineReadableClaimsAreNotLargerThanTheCodeTest(unittest.TestCase):
    """The manifest is signed and meant to be read by software that will not read the source."""

    def test_request_replay_protection_is_described_as_it_is(self):
        status, manifest = call(Store(), "GET", "/v1/manifest")
        self.assertEqual(status, 200)
        doc = manifest["manifest"]["documents"]["request_auth"]
        self.assertIn("memory only", doc["freshness"])
        self.assertIn("restart", doc["freshness"])
        self.assertIn("credential chain", doc["not_covered"])
        self.assertIn("audience", doc["not_covered"])
        self.assertNotIn("single-use", json.dumps(call(Store(), "GET", "/v1/capabilities")[1]))

    def test_the_description_is_still_true(self):
        # A nonce is refused the second time within a process ...
        store = Store.seeded_from_sample()
        body = {"budget_id": "b", "receipt": {}, "policy": POLICY.to_dict()}
        signed = as_operator(store, "/v1/spend", body)
        first = api.handle("POST", "/v1/spend", json.dumps(signed).encode(), store)[0]
        again = api.handle("POST", "/v1/spend", json.dumps(signed).encode(), store)
        self.assertNotEqual(first, 401)
        self.assertEqual(again[0], 401)
        self.assertIn("replay", json.loads(again[2])["error"]["message"])
        # ... and not across a restart (the limit the manifest now states; proposal P-3 in STATE.md).
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "store.json"
            a = Store.load_or_seed(path)
            signed = as_operator(a, "/v1/spend", body)
            api.handle("POST", "/v1/spend", json.dumps(signed).encode(), a)
            b = Store.load_or_seed(path)
            self.assertNotEqual(api.handle("POST", "/v1/spend", json.dumps(signed).encode(), b)[0], 401)


if __name__ == "__main__":
    unittest.main()
