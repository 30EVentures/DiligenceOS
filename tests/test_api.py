import copy
import json
import unittest

from diligenceos import api
from diligenceos.store import Store

GOOD = {
    "subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"},
    "document_text": "Section 3: Termination. Liability Cap applies.",
}


def call(method, path, payload=None, raw=None):
    body = raw if raw is not None else (json.dumps(payload).encode() if payload is not None else b"")
    status, headers, out = api.handle(method, path, body, STORE)
    return status, dict(headers), json.loads(out)


STORE = Store.seeded_from_sample()


class VerdictTest(unittest.TestCase):
    def test_verdict_returns_a_receipt_that_verifies(self):
        status, _, receipt = call("POST", "/v1/verdict", GOOD)
        self.assertEqual(status, 200)
        self.assertEqual(receipt["schema"], "diligenceos.receipt/1")
        self.assertIn(receipt["verdict"], ("PROCEED", "HOLD", "RED_FLAG"))
        status, _, check = call("POST", "/v1/verify", receipt)
        self.assertEqual((status, check["valid"]), (200, True))

    def test_tampered_receipt_fails_verification_but_call_succeeds(self):
        _, _, receipt = call("POST", "/v1/verdict", GOOD)
        forged = copy.deepcopy(receipt)
        forged["verdict"] = "PROCEED" if receipt["verdict"] != "PROCEED" else "HOLD"
        status, _, check = call("POST", "/v1/verify", forged)
        self.assertEqual(status, 200)
        self.assertFalse(check["valid"])
        self.assertTrue(check["errors"])

    def test_changed_store_data_changes_inputs_digest(self):
        store = Store.seeded_from_sample()
        _, _, out1 = api.handle("POST", "/v1/verdict", json.dumps(GOOD).encode(), store)
        store.add_sanctions_entry(name="Somebody Else", program="X", aliases=[])
        _, _, out2 = api.handle("POST", "/v1/verdict", json.dumps(GOOD).encode(), store)
        self.assertNotEqual(json.loads(out1)["inputs_digest"], json.loads(out2)["inputs_digest"])

    def test_sanctioned_subject_is_red_flag(self):
        store = Store.seeded_from_sample()
        store.add_sanctions_entry(name="Meridian Robotics Ltd.", program="TEST", aliases=[])
        _, _, out = api.handle("POST", "/v1/verdict", json.dumps(GOOD).encode(), store)
        self.assertEqual(json.loads(out)["verdict"], "RED_FLAG")


class ErrorShapeTest(unittest.TestCase):
    def assert_error(self, resp, status, code, field=None):
        got_status, _, body = resp
        self.assertEqual(got_status, status)
        self.assertEqual(body["error"]["code"], code)
        self.assertTrue(body["error"]["message"])
        if field:
            self.assertEqual(body["error"]["field"], field)

    def test_invalid_json(self):
        self.assert_error(call("POST", "/v1/verdict", raw=b"{nope"), 400, "invalid_json")

    def test_non_object_body(self):
        self.assert_error(call("POST", "/v1/verdict", payload=[1]), 400, "invalid_request")

    def test_missing_subject_fields(self):
        self.assert_error(call("POST", "/v1/verdict", {"subject": {"name": "x"}}), 400,
                          "invalid_request", "subject.registration_id")
        self.assert_error(call("POST", "/v1/verdict", {}), 400, "invalid_request", "subject")

    def test_wrong_document_text_type(self):
        bad = {**GOOD, "document_text": 5}
        self.assert_error(call("POST", "/v1/verdict", bad), 400, "invalid_request", "document_text")

    def test_unknown_path_and_wrong_method(self):
        self.assert_error(call("GET", "/v1/nope"), 404, "not_found")
        status, headers, body = call("GET", "/v1/verdict")
        self.assertEqual((status, headers["Allow"], body["error"]["code"]),
                         (405, "POST", "method_not_allowed"))

    def test_body_too_large(self):
        self.assert_error(call("POST", "/v1/verify", raw=b" " * (api.MAX_BODY_BYTES + 1)),
                          413, "body_too_large")

    def test_verify_non_json(self):
        self.assert_error(call("POST", "/v1/verify", raw=b"x"), 400, "invalid_json")


class CapabilitiesTest(unittest.TestCase):
    def test_capabilities_lists_the_contract(self):
        status, _, caps = call("GET", "/v1/capabilities")
        self.assertEqual(status, 200)
        self.assertEqual(caps["verdicts"], ["PROCEED", "HOLD", "RED_FLAG"])
        self.assertIn("POST /v1/verdict", caps["endpoints"])


if __name__ == "__main__":
    unittest.main()
