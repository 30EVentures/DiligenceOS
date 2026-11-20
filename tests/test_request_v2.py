import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from diligenceos import api
from diligenceos.auth import REQUEST_DOMAIN, authenticate, sign_request
from diligenceos.delegation import issue_delegation
from diligenceos.signing import Signer
from diligenceos.store import Store

NOW = "2026-11-18T12:00:00+00:00"
LATER = "2026-11-19T12:00:00+00:00"
BODY = {"budget_id": "b", "n": 1}


class RequestV2Test(unittest.TestCase):
    def setUp(self):
        self.op, self.agent, self.other = Signer.generate(), Signer.generate(), Signer.generate()
        self.narrow = [issue_delegation(self.op, delegate=self.agent.issuer_id, scopes=["spend"], expires=LATER, issued_at=NOW,
                                        budget_id="small")]
        self.wide = [issue_delegation(self.op, delegate=self.agent.issuer_id, scopes=["spend", "revoke"], expires=LATER, issued_at=NOW)]

    def sign(self, signer=None, chain=(), audience=None, body=None, **kw):
        return sign_request(signer or self.op, list(chain), "/v1/spend", body or BODY, now=NOW,
                            audience=audience or self.op.issuer_id, **kw)

    def check(self, auth, audience=None, body=None, seen=None):
        return authenticate("/v1/spend", body or BODY, auth, audience=audience or self.op.issuer_id,
                            root_issuers=[self.op.issuer_id], now=NOW, remember_nonce=seen)

    def test_the_domain_is_request_2(self):
        self.assertEqual(REQUEST_DOMAIN, "diligenceos.request/2")

    def test_a_request_for_the_right_audience_is_accepted(self):
        self.assertTrue(self.check(self.sign()).ok)
        self.assertTrue(self.check(self.sign(self.agent, self.narrow)).ok)

    def test_a_request_for_another_server_is_refused(self):
        other_server = self.other.issuer_id
        auth = self.sign(audience=other_server)
        r = self.check(auth)
        self.assertFalse(r.ok)
        self.assertIn("different server", r.errors[0])

    def test_relabelling_the_audience_breaks_the_signature(self):
        auth = self.sign(audience=self.other.issuer_id)
        auth["audience"] = self.op.issuer_id  # claim it was for this server
        r = self.check(auth)
        self.assertFalse(r.ok)
        self.assertIn("signature does not verify", r.errors[0])

    def test_a_request_without_an_audience_or_with_a_bad_one_is_refused_and_never_raises(self):
        base = self.sign()
        for label, change in (("missing", lambda a: a.pop("audience")), ("number", lambda a: a.update(audience=5)),
                              ("null", lambda a: a.update(audience=None)), ("list", lambda a: a.update(audience=[]))):
            with self.subTest(label):
                auth = copy.deepcopy(base)
                change(auth)
                self.assertFalse(self.check(auth).ok)

    def test_a_request_1_envelope_is_refused(self):
        auth = self.sign()
        legacy = {k: v for k, v in auth.items() if k != "audience"}
        self.assertFalse(self.check(legacy).ok)

    def test_a_captured_request_cannot_be_re_presented_with_a_wider_credential(self):
        auth = self.sign(self.agent, self.narrow)
        self.assertTrue(self.check(auth).ok)
        swapped = {**auth, "chain": self.wide}
        r = self.check(swapped)
        self.assertFalse(r.ok)
        self.assertIn("signature does not verify", r.errors[0])

    def test_a_nonce_that_cannot_be_recorded_refuses_the_request(self):
        def broken(nonce, now):
            raise OSError("disk full")
        r = self.check(self.sign(), seen=broken)
        self.assertFalse(r.ok)
        self.assertIn("could not record the nonce", r.errors[0])


class StoreNonceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "store.json"

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_nonce_survives_a_restart(self):
        a = Store(persist_path=self.path)
        self.assertFalse(a.remember_nonce("n1", NOW))
        b = Store(persist_path=self.path)
        self.assertTrue(b.remember_nonce("n1", "2026-11-18T12:05:00+00:00"))
        self.assertFalse(b.remember_nonce("n2", "2026-11-18T12:05:00+00:00"))

    def test_nonces_outside_the_window_are_forgotten_and_the_file_is_pruned(self):
        a = Store(persist_path=self.path)
        a.remember_nonce("old", NOW)
        b = Store(persist_path=self.path)
        self.assertFalse(b.remember_nonce("old", "2026-11-18T13:00:00+00:00"))
        lines = (self.path.with_name("nonces.jsonl")).read_text().splitlines()
        self.assertEqual([json.loads(x)["nonce"] for x in lines], ["old"])  # only the fresh re-record

    def test_a_crash_damaged_last_line_does_not_stop_the_server_or_lose_earlier_nonces(self):
        a = Store(persist_path=self.path)
        a.remember_nonce("kept", NOW)
        with open(self.path.with_name("nonces.jsonl"), "a", encoding="utf-8") as fh:
            fh.write('{"nonce": "half')
        b = Store(persist_path=self.path)
        self.assertTrue(b.remember_nonce("kept", NOW))

    def test_an_unwritable_nonce_file_fails_closed_through_the_api(self):
        store = Store.load_or_seed(self.path)
        self.path.with_name("nonces.jsonl").mkdir()  # cannot be opened for append
        from tests.auth_helpers import as_operator
        body = as_operator(store, "/v1/spend", {"budget_id": "b", "receipt": {}, "policy": {}})
        status, _, out = api.handle("POST", "/v1/spend", json.dumps(body).encode(), store)
        self.assertEqual(status, 401)
        self.assertIn("could not record the nonce", json.loads(out)["error"]["message"])

    def test_an_in_memory_store_still_works(self):
        s = Store()
        self.assertFalse(s.remember_nonce("x", NOW))
        self.assertTrue(s.remember_nonce("x", NOW))


class DeploymentAudienceTest(unittest.TestCase):
    """Two deployments that share an issuer key (staging cloned from production) are told apart only by DILIGENCEOS_AUDIENCE."""

    def setUp(self):
        self.prior = os.environ.get(api.AUDIENCE_VAR)

    def tearDown(self):
        if self.prior is None:
            os.environ.pop(api.AUDIENCE_VAR, None)
        else:
            os.environ[api.AUDIENCE_VAR] = self.prior

    def spend(self, store, audience):
        body = {"budget_id": "b", "receipt": {}, "policy": {}}
        auth = sign_request(store.signer, [], "/v1/spend", body, audience=audience)
        return api.handle("POST", "/v1/spend", json.dumps({**body, "auth": auth}).encode(), store)

    def test_a_request_for_staging_is_refused_by_production_with_the_same_key(self):
        store = Store()
        os.environ[api.AUDIENCE_VAR] = "production"
        self.assertEqual(self.spend(store, "staging")[0], 401)
        self.assertNotEqual(self.spend(store, "production")[0], 401)

    def test_the_issuer_id_is_the_audience_when_nothing_is_set(self):
        os.environ.pop(api.AUDIENCE_VAR, None)
        store = Store()
        self.assertNotEqual(self.spend(store, store.signer.issuer_id)[0], 401)
        self.assertEqual(self.spend(store, "production")[0], 401)


if __name__ == "__main__":
    unittest.main()
