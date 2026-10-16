"""The verdict API as an agent meets it: closed request schema, optional-but-enforceable signed callers,
refusal by default, and nothing that needs a human once a credential exists."""

import json
import os
import unittest
from unittest import mock

from diligenceos import api
from diligenceos.auth import sign_request
from diligenceos.conformance import test_signer
from diligenceos.delegation import issue_delegation
from diligenceos.receipt import verify_receipt
from diligenceos.store import Store

SUBJECT = {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"}
GOOD = {"subject": SUBJECT, "transaction": {"amount_minor": 24_000_000, "currency": "USD"}, "document_text": "Termination. Liability Cap. Indemnification."}
AGENT = test_signer(11)


def call(store, payload=None, *, raw=None, method="POST", path="/v1/verdict"):
    body = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else b"")
    status, headers, out = api.handle(method, path, body, store)
    return status, json.loads(out), dict(headers)


def signed(store, body, *, signer=None, chain=(), path="/v1/verdict", **kw):
    signer = signer or store.signer
    return {**body, "auth": sign_request(signer, list(chain), path, body, **kw)}


def credential(store, scopes=("verdict",), **kw):
    kw.setdefault("expires", "2999-01-01T00:00:00+00:00")
    return [issue_delegation(store.signer, delegate=AGENT.issuer_id, scopes=list(scopes), **kw)]


def with_mode(value):
    return mock.patch.dict(os.environ, {"DILIGENCEOS_VERDICT_AUTH": value} if value is not None else {}, clear=False)


class ClosedSchema(unittest.TestCase):
    def setUp(self):
        self.store = Store.seeded_from_sample()
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("DILIGENCEOS_VERDICT_AUTH", None)

    def refused(self, payload, field=None, code="invalid_request"):
        status, body, _ = call(self.store, payload)
        self.assertEqual((status, body["error"]["code"]), (400, code), (payload, body))
        if field:
            self.assertEqual(body["error"].get("field"), field, body)
        self.assertEqual([e for e in self.store.log.entries if e["kind"] == "receipt"], [], "a refused request must leave no log entry")

    def test_unknown_top_level_fields_are_refused_not_ignored(self):
        for key in ("transction", "extra", "Subject", "policy", "receipt", "budget_id", "trusted_issuers", "__proto__", "", "x-note"):
            self.refused({**GOOD, key: 1}, field=key)

    def test_a_misspelt_transaction_cannot_silently_become_no_transaction(self):
        self.refused({"subject": SUBJECT, "transction": GOOD["transaction"]}, field="transction")

    def test_unknown_fields_inside_subject_and_transaction_are_refused(self):
        self.refused({**GOOD, "subject": {**SUBJECT, "alias": "x"}}, field="subject.alias")
        self.refused({**GOOD, "transaction": {**GOOD["transaction"], "memo": "x"}}, field="transaction.memo")
        self.refused({**GOOD, "transaction": {**GOOD["transaction"], "amount": 5}}, field="transaction.amount")

    def test_wrong_types_are_refused_at_every_field(self):
        cases = [
            ({"subject": "Meridian"}, "subject"), ({"subject": [SUBJECT]}, "subject"), ({"subject": None}, "subject"), ({}, "subject"),
            ({"subject": {**SUBJECT, "name": ["a"]}}, "subject.name"), ({"subject": {**SUBJECT, "name": ""}}, "subject.name"),
            ({"subject": {**SUBJECT, "name": "   "}}, "subject.name"), ({"subject": {**SUBJECT, "registration_id": 7}}, "subject.registration_id"),
            ({"subject": {"name": "A"}}, "subject.registration_id"),
            ({"subject": SUBJECT, "document_text": 5}, "document_text"), ({"subject": SUBJECT, "document_text": ["x"]}, "document_text"),
            ({"subject": SUBJECT, "transaction": "24000000 USD"}, "transaction"), ({"subject": SUBJECT, "transaction": []}, "transaction"),
            ({"subject": SUBJECT, "transaction": {"amount_minor": 1.5, "currency": "USD"}}, "transaction.amount_minor"),
            ({"subject": SUBJECT, "transaction": {"amount_minor": True, "currency": "USD"}}, "transaction.amount_minor"),
            ({"subject": SUBJECT, "transaction": {"amount_minor": "5", "currency": "USD"}}, "transaction.amount_minor"),
            ({"subject": SUBJECT, "transaction": {"amount_minor": -1, "currency": "USD"}}, "transaction.amount_minor"),
            ({"subject": SUBJECT, "transaction": {"amount_minor": 2**53, "currency": "USD"}}, "transaction.amount_minor"),
            ({"subject": SUBJECT, "transaction": {"amount_minor": 1, "currency": "usd"}}, "transaction.currency"),
            ({"subject": SUBJECT, "transaction": {"amount_minor": 1}}, "transaction.currency"),
        ]
        for payload, field in cases:
            with self.subTest(payload=payload):
                status, body, _ = call(self.store, payload)
                self.assertEqual((status, body["error"]["code"]), (400, "invalid_request"))
                self.assertEqual(body["error"].get("field"), field)

    def test_non_object_and_unparseable_bodies_are_refused(self):
        for raw in (b"[]", b"5", b'"x"', b"null", b"{nope", b"", b"\xff\xfe"):
            status, body, _ = call(self.store, raw=raw)
            self.assertEqual(status, 400, raw)
            self.assertIn(body["error"]["code"], ("invalid_json", "invalid_request"), raw)

    def test_every_refusal_has_the_same_stable_shape(self):
        for payload in ({}, {**GOOD, "x": 1}, {"subject": 5}):
            status, body, headers = call(self.store, payload)
            self.assertEqual(set(body), {"error"})
            self.assertTrue({"code", "message"} <= set(body["error"]) <= {"code", "message", "field"})
            self.assertEqual(headers["Content-Type"], "application/json")

    def test_valid_requests_still_work_with_and_without_the_optional_fields(self):
        for payload in (GOOD, {"subject": SUBJECT}, {"subject": SUBJECT, "document_text": "x"}, {"subject": SUBJECT, "transaction": GOOD["transaction"]}):
            status, body, headers = call(self.store, payload)
            self.assertEqual(status, 200, payload)
            self.assertEqual(body["schema"], "diligenceos.receipt/1")
            self.assertIn("X-DiligenceOS-Log-Seq", headers)


class RefusesByDefault(unittest.TestCase):
    def setUp(self):
        self.store = Store.seeded_from_sample()

    def test_wrong_methods_and_unknown_routes_are_refused(self):
        self.assertEqual(call(self.store, method="GET")[0], 405)
        self.assertEqual(call(self.store, method="DELETE")[0], 405)
        self.assertEqual(call(self.store, GOOD, path="/v1/verdicts")[0], 404)
        self.assertEqual(call(self.store, GOOD, path="/v2/verdict")[0], 404)
        self.assertEqual(call(self.store, GOOD, path="/v1/verdict/")[0], 404)

    def test_the_allow_header_names_the_one_method(self):
        _, _, headers = call(self.store, method="PUT")
        self.assertEqual(headers.get("Allow"), "POST")

    def test_an_unrecognised_mode_value_means_signed_never_open(self):
        for value in ("", "off", "OPEN ", "none", "0", "false", "required"):
            with with_mode(value):
                status, body, _ = call(self.store, GOOD)
            expected = 200 if value.strip().lower() == "open" else 401
            self.assertEqual(status, expected, repr(value))


class SignedMode(unittest.TestCase):
    def setUp(self):
        self.store = Store.seeded_from_sample()

    def call(self, payload, **kw):
        with with_mode("signed"):
            return call(self.store, payload, **kw)

    def refused(self, payload, status, code):
        got, body, _ = self.call(payload)
        self.assertEqual((got, body["error"]["code"]), (status, code), body)
        self.assertEqual([e for e in self.store.log.entries if e["kind"] == "receipt"], [], "a refused request must leave no receipt")

    def test_an_unsigned_request_is_refused(self):
        self.refused(GOOD, 401, "unauthenticated")

    def test_a_bad_envelope_is_refused(self):
        for auth in (None, [], "x", {}, {"signer": "x"}, {"signer": 5, "chain": [], "issued_at": "t", "nonce": "n", "signature": "s"}):
            self.refused({**GOOD, "auth": auth}, 401, "unauthenticated")

    def test_a_request_signed_for_another_route_is_refused(self):
        self.refused(signed(self.store, GOOD, path="/v1/spend"), 401, "unauthenticated")

    def test_a_body_changed_after_signing_is_refused(self):
        request = signed(self.store, GOOD)
        request["subject"] = {**SUBJECT, "name": "Someone Else Ltd."}
        self.refused(request, 401, "unauthenticated")
        request = signed(self.store, GOOD)
        request["transaction"] = {"amount_minor": 1, "currency": "USD"}
        self.refused(request, 401, "unauthenticated")

    def test_a_stale_or_future_request_is_refused(self):
        for when in ("2020-01-01T00:00:00+00:00", "2999-01-01T00:00:00+00:00", "yesterday"):
            self.refused(signed(self.store, GOOD, now=when), 401, "unauthenticated")

    def test_a_replayed_request_is_refused(self):
        request = signed(self.store, GOOD)
        self.assertEqual(self.call(request)[0], 200)
        status, body, _ = self.call(request)
        self.assertEqual((status, body["error"]["code"]), (401, "unauthenticated"))
        self.assertIn("replay", body["error"]["message"])

    def test_a_key_with_no_credential_is_not_the_operator(self):
        self.refused(signed(self.store, GOOD, signer=AGENT), 401, "unauthenticated")

    def test_a_credential_without_the_verdict_scope_is_forbidden(self):
        for scopes in (["spend"], ["revoke"], ["spend", "revoke"]):
            self.refused(signed(self.store, GOOD, signer=AGENT, chain=credential(self.store, scopes)), 403, "forbidden")

    def test_an_expired_or_revoked_credential_is_refused(self):
        self.refused(signed(self.store, GOOD, signer=AGENT, chain=credential(self.store, expires="2020-01-01T00:00:00+00:00")), 401, "unauthenticated")
        chain = credential(self.store)
        self.store.revoke(chain[0]["id"], "withdrawn", by=self.store.signer.issuer_id)
        self.refused(signed(self.store, GOOD, signer=AGENT, chain=chain), 401, "unauthenticated")

    def test_a_credential_someone_else_issued_is_refused(self):
        stranger = test_signer(12)
        forged = [issue_delegation(stranger, delegate=AGENT.issuer_id, scopes=["verdict"], expires="2999-01-01T00:00:00+00:00")]
        self.refused(signed(self.store, GOOD, signer=AGENT, chain=forged), 401, "unauthenticated")

    def test_the_schema_is_still_closed_after_authentication(self):
        got, body, _ = self.call(signed(self.store, {**GOOD, "extra": 1}))
        self.assertEqual((got, body["error"]["code"], body["error"]["field"]), (400, "invalid_request", "extra"))

    def test_the_operator_may_call_it(self):
        got, body, _ = self.call(signed(self.store, GOOD))
        self.assertEqual(got, 200, body)

    def test_an_agent_with_a_verdict_credential_needs_no_human(self):
        chain = credential(self.store)
        got, receipt, headers = self.call(signed(self.store, GOOD, signer=AGENT, chain=chain))
        self.assertEqual(got, 200, receipt)
        # the caller can check the answer offline against the key it pinned, without trusting the server
        check = verify_receipt(receipt, now="2026-10-14T12:00:00+00:00", trusted_issuers=[self.store.signer.issuer_id])
        self.assertTrue(check.valid and check.trusted and not check.revoked, check)
        entry = self.store.log.lookup(receipt["id"])
        self.assertEqual(str(entry["seq"]), headers["X-DiligenceOS-Log-Seq"])

    def test_a_delegate_cannot_widen_into_the_verdict_scope(self):
        parent = credential(self.store, ["spend"])
        child = issue_delegation(AGENT, delegate=test_signer(13).issuer_id, scopes=["verdict"], expires="2999-01-01T00:00:00+00:00", parent=parent[0]["id"])
        self.refused(signed(self.store, GOOD, signer=test_signer(13), chain=[*parent, child]), 401, "unauthenticated")

    def test_an_open_server_still_checks_an_envelope_it_is_given(self):
        with with_mode("open"):
            status, body, _ = call(self.store, {**GOOD, "auth": {"signer": "x"}})
        self.assertEqual((status, body["error"]["code"]), (401, "unauthenticated"))
        with with_mode("open"):
            self.assertEqual(call(self.store, signed(self.store, GOOD))[0], 200)


class AdvertisedHonestly(unittest.TestCase):
    def test_capabilities_and_manifest_state_the_mode(self):
        store = Store.seeded_from_sample()
        for mode, listed in (("open", False), ("signed", True)):
            with with_mode(mode):
                _, caps, _ = call(store, method="GET", path="/v1/capabilities")
                _, manifest, _ = call(store, method="GET", path="/v1/manifest")
            self.assertEqual(caps["verdict_auth"], mode)
            routes = {(r["method"], r["path"]): r for r in manifest["manifest"]["api"]["routes"]}
            self.assertEqual(routes[("POST", "/v1/verdict")]["authenticated"], listed)
            self.assertTrue(routes[("POST", "/v1/spend")]["authenticated"])           # unchanged

    def test_unset_means_open_and_says_so(self):
        store = Store.seeded_from_sample()
        with mock.patch.dict(os.environ):
            os.environ.pop("DILIGENCEOS_VERDICT_AUTH", None)
            self.assertEqual(call(store, method="GET", path="/v1/capabilities")[1]["verdict_auth"], "open")


if __name__ == "__main__":
    unittest.main()
