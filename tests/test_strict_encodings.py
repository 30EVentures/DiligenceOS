"""Round 1 of the overnight review: one encoding per signature, no non-JSON tokens,
no ambiguous or unbounded request JSON, no universal-signature keys."""

import json
import unittest

from diligenceos import api
from diligenceos.conformance import test_signer
from diligenceos.receipt import canonical_json, digest
from diligenceos.signing import RECEIPT_DOMAIN, Signer, verify_signature
from diligenceos.store import Store

MSG = "sha256:" + "ab" * 32
P = 2**255 - 19
D = (-121665 * pow(121666, -1, P)) % P


def _add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = D * x1 * x2 * y1 * y2 % P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, -1, P) % P, (y1 * y2 + x1 * x2) * pow(1 - t, -1, P) % P)


def _mul(k, pt):
    out = (0, 1)
    while k:
        if k & 1:
            out = _add(out, pt)
        pt, k = _add(pt, pt), k >> 1
    return out


def _decode(raw):
    """(x, y) for a canonical encoding, or None if it is not a point on the curve."""
    n = int.from_bytes(raw, "little")
    sign, y = n >> 255, n & (2**255 - 1)
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * pow(2, (P - 1) // 4, P) % P
    if (x * x - x2) % P or (x == 0 and sign):
        return None
    return (P - x if x & 1 != sign else x, y)


class SignatureEncodingTest(unittest.TestCase):
    def setUp(self):
        self.signer = test_signer(9)                # fixed, so no run depends on which hex digits a random key has
        self.sig = self.signer.sign(RECEIPT_DOMAIN, MSG)
        self.hex = self.sig[len("ed25519:"):]

    def ok(self, issuer=None, sig=None):
        return verify_signature(issuer or self.signer.issuer_id, RECEIPT_DOMAIN, MSG, sig or self.sig)

    def test_the_canonical_encoding_verifies(self):
        self.assertTrue(self.ok())

    def test_only_one_string_per_signature(self):
        spaced = " ".join(self.hex[i:i + 2] for i in range(0, len(self.hex), 2))
        for variant in (self.hex.upper(), self.hex[:10].upper() + self.hex[10:], spaced, " " + self.hex,
                        self.hex + "\n", "\t" + self.hex + " ", self.hex[:64] + " " + self.hex[64:]):
            self.assertNotEqual(variant, self.hex)
            self.assertFalse(self.ok(sig="ed25519:" + variant), repr(variant))

    def test_only_one_string_per_issuer_id(self):
        raw = self.signer.issuer_id[len("ed25519:"):]
        for variant in (raw.upper(), " " + raw, raw + "\n", raw[:2].upper() + raw[2:]):
            self.assertNotEqual(variant, raw)
            self.assertFalse(self.ok(issuer="ed25519:" + variant), repr(variant))

    def test_wrong_lengths_and_non_hex(self):
        for bad in ("ed25519:", "ed25519:" + self.hex[:-2], "ed25519:" + self.hex + "00", "ed25519:" + "zz" * 64,
                    "ED25519:" + self.hex, self.hex, "ed25519:0x" + self.hex):
            self.assertFalse(self.ok(sig=bad), bad)

    def test_a_scalar_plus_group_order_is_refused(self):
        order = 2**252 + 27742317777372353535851937790883648493
        raw = bytes.fromhex(self.hex)
        s = int.from_bytes(raw[32:], "little")
        self.assertFalse(self.ok(sig="ed25519:" + (raw[:32] + (s + order).to_bytes(32, "little")).hex()))


class SmallOrderKeyTest(unittest.TestCase):
    """A public key of small order accepts a signature that is valid for every message."""

    def test_the_identity_key_cannot_sign_anything(self):
        identity = "ed25519:" + "01" + "00" * 31
        universal = "ed25519:" + "01" + "00" * 31 + "00" * 32          # R = identity, S = 0
        for message in ("a", "anything at all", MSG, ""):
            self.assertFalse(verify_signature(identity, RECEIPT_DOMAIN, message, universal))

    def test_every_small_order_point_is_refused_as_a_key(self):
        # Computed here from the curve equation, not copied from the module's list.
        found = 0
        ys = {0, 1, P - 1,
              2707385501144840649318225287225658788936804267575313519463743609750303402022,
              55188659117513257062467267217118295137698188065244968500265048394206261417927}
        for y in ys:
            for sign in (0, 1):
                raw = (y | (sign << 255)).to_bytes(32, "little")
                point = _decode(raw)
                if point is None:
                    continue
                self.assertEqual(_mul(8, point), (0, 1), "not small order: " + raw.hex())
                found += 1
                self.assertFalse(
                    verify_signature("ed25519:" + raw.hex(), RECEIPT_DOMAIN, MSG, "ed25519:" + raw.hex() + "00" * 32),
                    raw.hex())
        self.assertGreaterEqual(found, 8)          # the eight points of order dividing 8

    def test_non_canonical_encodings_of_small_order_points_are_refused_too(self):
        for y in (P, P + 1):                      # 0 and 1, written with y >= p
            for sign in (0, 1):
                raw = (y | (sign << 255)).to_bytes(32, "little")
                self.assertFalse(
                    verify_signature("ed25519:" + raw.hex(), RECEIPT_DOMAIN, MSG, "ed25519:" + raw.hex() + "00" * 32))

    def test_an_ordinary_key_still_works(self):
        s = Signer.generate()
        self.assertTrue(verify_signature(s.issuer_id, RECEIPT_DOMAIN, MSG, s.sign(RECEIPT_DOMAIN, MSG)))


class CanonicalJsonTest(unittest.TestCase):
    def test_non_finite_numbers_are_not_canonical_json(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                canonical_json({"x": value})
            with self.assertRaises(ValueError):
                digest([value])

    def test_ordinary_documents_are_unchanged(self):
        self.assertEqual(canonical_json({"b": 1, "a": ["é", None, True]}), '{"a":["é",null,true],"b":1}'.encode())


class RequestJsonTest(unittest.TestCase):
    def call(self, path, raw):
        status, _, body = api.handle("POST", path, raw, Store())
        return status, json.loads(body)

    def test_duplicate_keys_are_refused_not_last_wins(self):
        dup = b'{"subject":{"name":"A","registration_id":"X"},"subject":{"name":"B","registration_id":"Y"}}'
        status, body = self.call("/v1/verdict", dup)
        self.assertEqual((status, body["error"]["code"]), (400, "invalid_json"))
        nested = b'{"subject":{"name":"A","name":"B","registration_id":"X"}}'
        self.assertEqual(self.call("/v1/verdict", nested)[0], 400)

    def test_non_json_number_tokens_are_refused(self):
        for token in (b"NaN", b"Infinity", b"-Infinity"):
            raw = b'{"subject":{"name":"A","registration_id":"X"},"extra":' + token + b"}"
            status, body = self.call("/v1/verdict", raw)
            self.assertEqual((status, body["error"]["code"]), (400, "invalid_json"), token)

    def test_absurd_nesting_is_a_400_not_an_exception(self):
        for raw in (b"[" * 300_000 + b"]" * 300_000, b'{"a":' * 150_000 + b"1" + b"}" * 150_000):
            status, body = self.call("/v1/verify", raw)
            self.assertEqual((status, body["error"]["code"]), (400, "invalid_json"))

    def test_ordinary_requests_still_work(self):
        status, body = self.call("/v1/verdict", b'{"subject":{"name":"A","registration_id":"X"}}')
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
