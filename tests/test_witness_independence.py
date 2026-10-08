"""A log cannot witness itself: a cosignature whose witness is the log's own
issuer proves nothing (the operator holds that key), so it is refused where
accepted, ignored where counted, and refused in configuration."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from diligenceos import api, tools, webapp
from diligenceos.signing import Signer
from diligenceos.store import Store
from diligenceos.witness import (
    SelfWitnessError, check_witness_config, cosign_head, run_witness, verify_cosignature,
)

from test_witness import head_doc, signed_log


class SelfWitnessTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "store.json"
        self.store = Store.load_or_seed(self.path)
        self.op = self.store.signer
        self.third = Signer.generate()
        self._old = os.environ.pop("DILIGENCEOS_WITNESSES", None)
        api.handle("POST", "/v1/verdict", json.dumps(
            {"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"}}).encode(), self.store)

    def tearDown(self):
        os.environ.pop("DILIGENCEOS_WITNESSES", None)
        if self._old is not None:
            os.environ["DILIGENCEOS_WITNESSES"] = self._old
        self._tmp.cleanup()

    def call(self, method, path, payload=None, store=None):
        body = json.dumps(payload).encode() if payload is not None else b""
        status, _, out = api.handle(method, path, body, store or self.store)
        return status, json.loads(out)

    def self_cosig(self):
        head = self.call("GET", "/v1/log/head")[1]
        # Bypass the creation guard: this is what a hostile operator would hand-build.
        from diligenceos.witness import COSIGN_DOMAIN, cosign_message
        return {"issuer": head["issuer"], "length": head["length"], "head_hash": head["head_hash"],
                "witness": self.op.issuer_id,
                "signature": self.op.sign(COSIGN_DOMAIN, cosign_message(
                    head["issuer"], head["length"], head["head_hash"]))}

    def test_a_self_cosignature_does_not_verify(self):
        self.assertFalse(verify_cosignature(self.self_cosig()))

    def test_a_third_party_cosignature_still_verifies(self):
        head = self.call("GET", "/v1/log/head")[1]
        self.assertTrue(verify_cosignature(
            cosign_head(self.third, head["issuer"], head["length"], head["head_hash"])))

    def test_cosign_head_refuses_to_make_one(self):
        with self.assertRaises(SelfWitnessError):
            cosign_head(self.op, self.op.issuer_id, 1, "sha256:" + "a" * 64)

    def test_the_server_refuses_it_even_when_listed(self):
        os.environ["DILIGENCEOS_WITNESSES"] = f"{self.op.issuer_id},{self.third.issuer_id}"
        status, out = self.call("POST", "/v1/log/cosign", self.self_cosig())
        self.assertEqual((status, out["error"]["code"], out["error"]["field"]), (403, "forbidden", "witness"))
        self.assertIn("own issuer", out["error"]["message"])
        self.assertEqual(self.call("GET", "/v1/log/head")[1]["cosignatures"], [])

    def test_a_stored_self_cosignature_is_ignored_in_the_head(self):
        # e.g. persisted by a build that predates this check
        c = self.self_cosig()
        self.store._cosignatures.setdefault(c["head_hash"], {})[c["witness"]] = c
        self.assertEqual(self.call("GET", "/v1/log/head")[1]["cosignatures"], [])
        os.environ["DILIGENCEOS_WITNESSES"] = self.third.issuer_id
        head = self.call("GET", "/v1/log/head")[1]
        good = cosign_head(self.third, head["issuer"], head["length"], head["head_hash"])
        self.assertEqual(self.call("POST", "/v1/log/cosign", good), (200, {"accepted": True}))
        self.assertEqual(self.call("GET", "/v1/log/head")[1]["cosignatures"], [good])

    def test_the_manifest_never_lists_the_issuer_as_a_witness(self):
        os.environ["DILIGENCEOS_WITNESSES"] = f"{self.op.issuer_id},{self.third.issuer_id}"
        m = self.call("GET", "/v1/manifest")[1]["manifest"]
        self.assertEqual(m["witnesses"], [self.third.issuer_id])

    def test_configuration_naming_the_issuer_is_refused(self):
        with self.assertRaises(SelfWitnessError) as ctx:
            check_witness_config([self.third.issuer_id, self.op.issuer_id], self.op.issuer_id)
        self.assertIn("DILIGENCEOS_WITNESSES", str(ctx.exception))
        check_witness_config([self.third.issuer_id], self.op.issuer_id)  # fine
        check_witness_config([], self.op.issuer_id)  # fine

    def test_serving_refuses_to_start_with_the_issuer_in_the_list(self):
        old = os.environ.get("DILIGENCEOS_DATA_PATH")
        os.environ["DILIGENCEOS_DATA_PATH"] = str(self.path)
        webapp._store = None
        try:
            os.environ["DILIGENCEOS_WITNESSES"] = self.op.issuer_id
            with self.assertRaises(SelfWitnessError):
                webapp.serve(host="127.0.0.1", port=0)
        finally:
            webapp._store = None
            if old is None:
                os.environ.pop("DILIGENCEOS_DATA_PATH", None)
            else:
                os.environ["DILIGENCEOS_DATA_PATH"] = old

    def test_the_witness_tool_refuses_to_witness_its_own_log(self):
        log = signed_log(self.op, 2)
        docs = {"/v1/log/head": head_doc(self.op, log), "/v1/log/entries": {"entries": log.entries}}
        state = Path(self._tmp.name) / "w.json"
        with self.assertRaises(SelfWitnessError):
            run_witness(lambda p: docs[p], state, self.op, self.op.issuer_id)
        self.assertFalse(state.exists())

    def test_the_witness_cli_reports_it_as_an_error(self):
        keyfile = Path(self._tmp.name) / "same.key"
        Signer.load_or_create(keyfile)
        me = Signer.load_or_create(keyfile).issuer_id
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = tools.main(["witness", "--url", "http://127.0.0.1:1", "--issuer", me,
                               "--key", str(keyfile), "--state", str(Path(self._tmp.name) / "s.json")])
        self.assertEqual(code, 2)
        self.assertIn("own issuer", err.getvalue())


if __name__ == "__main__":
    unittest.main()
