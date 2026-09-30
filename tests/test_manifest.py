import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from diligenceos import api, auth, delegation, engine, manifest, receipt_log, signing, witness
from diligenceos.delegation import issue_delegation
from diligenceos.signing import Signer
from diligenceos.store import Store


class ServedManifestTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "store.json"
        self.store = Store.load_or_seed(self.path)
        self._env = {k: os.environ.pop(k, None) for k in ("DILIGENCEOS_WITNESSES", "DILIGENCEOS_OPERATOR_NAME")}

    def tearDown(self):
        for k, v in self._env.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v
        self._tmp.cleanup()

    def get(self, store=None):
        status, headers, body = api.handle("GET", "/v1/manifest", b"", store or self.store)
        return status, json.loads(body)

    def test_served_signed_and_verifiable_against_the_pinned_issuer(self):
        status, doc = self.get()
        self.assertEqual(status, 200)
        issuer = json.loads(api.handle("GET", "/v1/issuer", b"", self.store)[2])["issuer"]
        self.assertEqual(doc["issuer"], issuer)
        self.assertEqual(manifest.verify_manifest(doc, pinned_issuer=issuer), [])
        self.assertTrue(manifest.verify_manifest(doc, pinned_issuer=Signer.generate().issuer_id))

    def test_any_edit_or_swap_fails(self):
        doc = self.get()[1]
        for mutate in (
            lambda d: d["manifest"]["operator"].update(name="Somebody Else"),
            lambda d: d["manifest"]["limits"].update(max_delegation_chain=99),
            lambda d: d["manifest"]["documents"]["receipt"]["signature"].update(domain="x"),
            lambda d: d.update(signature="ed25519:" + "0" * 128),
        ):
            forged = copy.deepcopy(doc)
            mutate(forged)
            self.assertTrue(manifest.verify_manifest(forged))
        other = Signer.generate()
        swapped = {"manifest": {**doc["manifest"], "issuer": {**doc["manifest"]["issuer"], "id": other.issuer_id}},
                   "issuer": other.issuer_id, "signature": doc["signature"]}
        self.assertTrue(manifest.verify_manifest(swapped))
        for bad in (None, {}, [], {"manifest": 1}, {"manifest": {}, "issuer": "x", "signature": "y"}):
            self.assertTrue(manifest.verify_manifest(bad), bad)

    def test_it_states_the_code_s_constants(self):
        m = self.get()[1]["manifest"]
        d = m["documents"]
        self.assertEqual(d["receipt"]["signature"]["domain"], signing.RECEIPT_DOMAIN)
        self.assertEqual(d["receipt"]["schema"], "diligenceos.receipt/1")
        self.assertEqual(d["delegation"]["signature"]["domain"], delegation.DOMAIN)
        self.assertEqual(d["request_auth"]["domain"], auth.REQUEST_DOMAIN)
        self.assertEqual(d["log_entry"]["signature"]["domain"], receipt_log.LOG_ENTRY_DOMAIN)
        self.assertEqual(d["log_head"]["signature"]["domain"], signing.LOG_HEAD_DOMAIN)
        self.assertEqual(d["cosignature"]["signature"]["domain"], witness.COSIGN_DOMAIN)
        self.assertEqual(d["delegation"]["scopes"], ["revoke", "spend"])
        replay = d["receipt"]["replay"]
        self.assertEqual((replay["base_trust_score"], replay["sanctions_penalty"], replay["other_penalty"]),
                         (engine.DEFAULT_BASE_TRUST_SCORE, engine.SANCTIONS_PENALTY, engine.OTHER_PENALTY))
        self.assertEqual(m["limits"]["max_body_bytes"], api.MAX_BODY_BYTES)
        self.assertEqual(m["limits"]["max_delegation_chain"], delegation.MAX_CHAIN)
        self.assertEqual(m["limits"]["request_clock_skew_seconds"], auth.MAX_SKEW_SECONDS)

    def test_routes_match_the_router_and_flag_authenticated_ones(self):
        routes = {r["path"]: r for r in self.get()[1]["manifest"]["api"]["routes"]}
        self.assertEqual({p: r["method"] for p, r in routes.items()}, api._ROUTES)
        self.assertEqual({p for p, r in routes.items() if r["authenticated"]}, {"/v1/revoke", "/v1/spend"})
        self.assertIn("/v1/manifest", routes)

    def test_witnesses_and_operator_name_come_from_configuration(self):
        m = self.get()[1]["manifest"]
        self.assertEqual((m["witnesses"], m["operator"]), ([], {"name": "30E Ventures"}))
        os.environ["DILIGENCEOS_WITNESSES"] = "ed25519:bb, ed25519:aa"
        os.environ["DILIGENCEOS_OPERATOR_NAME"] = "Example Operator"
        m = self.get()[1]["manifest"]
        self.assertEqual((m["witnesses"], m["operator"]["name"]), (["ed25519:aa", "ed25519:bb"], "Example Operator"))

    def test_only_the_operator_is_named_and_no_personal_identifiers_leak(self):
        text = json.dumps(self.get()[1]).lower()
        for needle in ("solway", "caleb", "gmail", "@", "analystos", "depositx", "concord", "kpmg"):
            self.assertNotIn(needle, text, needle)

    def test_method_and_key_failures(self):
        self.assertEqual(api.handle("POST", "/v1/manifest", b"", self.store)[0], 405)
        self.path.with_name("issuer.key").write_text("garbage")
        status, body = self.get(Store.load_or_seed(self.path))
        self.assertEqual((status, body["error"]["code"]), (503, "signer_unavailable"))

    def test_capabilities_lists_it(self):
        caps = json.loads(api.handle("GET", "/v1/capabilities", b"", self.store)[2])
        self.assertIn("GET /v1/manifest", caps["endpoints"])


# ---- an independent verifier: no diligenceos imports below this line are used to VERIFY.
def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(obj) -> str:
    return "sha256:" + hashlib.sha256(canon(obj)).hexdigest()


def ed_verify(issuer: str, domain: str, message: str, signature: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(issuer.removeprefix("ed25519:")))
        key.verify(bytes.fromhex(signature.removeprefix("ed25519:")), f"{domain}\n{message}".encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


class ReferenceVerifier:
    """Verifies documents using ONLY what a fetched manifest says."""

    def __init__(self, signed_manifest: dict, pinned_issuer: str):
        assert ed_verify(pinned_issuer, signed_manifest["manifest"]["documents"]["manifest"]["signature"]["domain"],
                         sha(signed_manifest["manifest"]), signed_manifest["signature"]), "manifest not signed by pinned issuer"
        self.m = signed_manifest["manifest"]
        self.issuer = pinned_issuer
        (vec,) = self.m["vectors"]["canonical_json"]
        assert canon(vec["input"]).decode() == vec["canonical"] and sha(vec["input"]) == vec["sha256"], "encoding rules disagree"

    def receipt_ok(self, r: dict) -> bool:
        spec = self.m["documents"]["receipt"]
        body = {k: v for k, v in r.items() if k not in ("id", "signature")}
        if sha(body) != r["id"] or r["issuer"] != self.issuer:
            return False
        if not ed_verify(r["issuer"], spec["signature"]["domain"], r["id"], r["signature"]):
            return False
        rp = spec["replay"]
        flagged = [f for f in r["findings"] if f["status"] == "flag"]
        score = rp["base_trust_score"] - sum(
            rp["sanctions_penalty"] if f["category"] == "sanctions" else rp["other_penalty"] for f in flagged)
        score = max(0, min(100, score))
        verdict = ("RED_FLAG" if any(f["category"] == "sanctions" for f in flagged)
                   else "HOLD" if flagged else "PROCEED")
        return (verdict, score) == (r["verdict"], r["trust_score"])

    def log_entry_ok(self, e: dict, prev_hash: str) -> bool:
        spec = self.m["documents"]["log_entry"]
        body = {k: v for k, v in e.items() if k not in ("entry_hash", "signature")}
        return (e["prev_hash"] == prev_hash and sha(body) == e["entry_hash"] and e["issuer"] == self.issuer
                and ed_verify(e["issuer"], spec["signature"]["domain"], e["entry_hash"], e["signature"]))

    def head_ok(self, h: dict) -> bool:
        dom = self.m["documents"]["log_head"]["signature"]["domain"]
        return ed_verify(h["issuer"], dom, f"{h['length']}:{h['head_hash']}", h["signature"]) and h["issuer"] == self.issuer

    def delegation_ok(self, d: dict) -> bool:
        spec = self.m["documents"]["delegation"]
        body = {k: v for k, v in d.items() if k not in ("id", "signature")}
        return sha(body) == d["id"] and ed_verify(d["delegator"], spec["signature"]["domain"], d["id"], d["signature"])


class ManifestIsSufficientTest(unittest.TestCase):
    """If a verifier written from the manifest alone can verify real documents, the
    manifest says enough. This is the test that keeps it honest."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = Store.load_or_seed(Path(self._tmp.name) / "store.json")

    def tearDown(self):
        self._tmp.cleanup()

    def call(self, method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else b""
        return json.loads(api.handle(method, path, body, self.store)[2])

    def test_reference_verifier_accepts_real_documents_and_rejects_tampered_ones(self):
        issuer = self.call("GET", "/v1/issuer")["issuer"]
        verifier = ReferenceVerifier(self.call("GET", "/v1/manifest"), issuer)

        clean = self.call("POST", "/v1/verdict", {"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"}})
        held = self.call("POST", "/v1/verdict", {"subject": {"name": "Meridian Robotics Ltd.", "registration_id": "UK09456213"},
                                                 "document_text": "just a termination clause"})
        self.store.add_sanctions_entry(name="Nova Freight Co.", program="TEST", aliases=[])
        red = self.call("POST", "/v1/verdict", {"subject": {"name": "Nova Freight Co.", "registration_id": "X"}})
        self.assertEqual([clean["verdict"], held["verdict"], red["verdict"]], ["PROCEED", "HOLD", "RED_FLAG"])
        for r in (clean, held, red):
            self.assertTrue(verifier.receipt_ok(r), r["verdict"])

        for mutate in (lambda r: r.update(trust_score=100),
                       lambda r: r.update(verdict="PROCEED"),
                       lambda r: r["subject"].update(name="x"),
                       lambda r: r.update(signature="ed25519:" + "0" * 128)):
            forged = copy.deepcopy(held)
            mutate(forged)
            self.assertFalse(verifier.receipt_ok(forged))
        # a re-sealed forgery (fresh id, old signature) fails on the signature
        forged = copy.deepcopy(held)
        forged["verdict"], forged["trust_score"] = "PROCEED", 85
        forged["id"] = sha({k: v for k, v in forged.items() if k not in ("id", "signature")})
        self.assertFalse(verifier.receipt_ok(forged))

        prev = "sha256:" + "0" * 64
        for e in self.call("GET", "/v1/log/entries")["entries"]:
            self.assertTrue(verifier.log_entry_ok(e, prev))
            prev = e["entry_hash"]
        bad = copy.deepcopy(e)
        bad["logged_at"] = "1999-01-01T00:00:00+00:00"
        self.assertFalse(verifier.log_entry_ok(bad, bad["prev_hash"]))
        self.assertTrue(verifier.head_ok(self.call("GET", "/v1/log/head")))

        chain = [issue_delegation(self.store.signer, delegate=Signer.generate().issuer_id,
                                  scopes=["spend"], expires="2099-01-01T00:00:00+00:00")]
        self.assertTrue(verifier.delegation_ok(chain[0]))
        self.assertFalse(verifier.delegation_ok({**chain[0], "scopes": ["spend", "revoke"]}))

    def test_verifier_refuses_a_manifest_from_a_key_that_was_not_pinned(self):
        with self.assertRaises(AssertionError):
            ReferenceVerifier(self.call("GET", "/v1/manifest"), Signer.generate().issuer_id)


if __name__ == "__main__":
    unittest.main()
