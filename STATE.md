# Overnight review state (branch overnight/diligenceos-bugs)

Base: origin/main @ ebb67da. Baseline: 399 tests, OK (`python -m unittest discover -s tests`), conformance corpus 249 cases.

## Found / fixed / deferred / BLOCKED

### Round 1: receipts and signatures
- FIXED R1-1 [RAN] Signature and issuer strings had many valid spellings (uppercase hex, embedded or surrounding whitespace). `bytes.fromhex` is lenient; `verify_signature` now requires lowercase hex of exact length. Tests: `tests/test_strict_encodings.py::SignatureEncodingTest`; corpus case `rc-signature-uppercase-hex`.
- FIXED R1-2 [RAN] A small-order public key (the identity point, and the other points of order dividing 8) accepts a signature valid for every message: `verify_signature("ed25519:01 00..00", d, anything, "ed25519:01 00..00 00..00")` returned True. Such a key is now never a signer. Tests: `SmallOrderKeyTest` (cross-checks the blocklist with curve arithmetic); corpus case `rc-small-order-issuer-key`.
- FIXED R1-3 [RAN] `canonical_json` emitted `NaN` / `Infinity` (not JSON; other languages refuse them). Now `allow_nan=False`.
- FIXED R1-4 [RAN] The API took the last value of a duplicated JSON key silently, accepted `NaN`/`Infinity` literals, and let `RecursionError` escape `api.handle` for very deep nesting (200k levels, under the 1 MB body cap). All three are now `400 invalid_json`.
- NOT FIXED (proposal) floats in signed documents: Python writes `1.0` and `1e+16`, JavaScript writes `1` and `10000000000000000`. No issued document contains a float today (every field is typed), but a verifier in another language would disagree on a document that did. Proposal: refuse floats in `canonical_json`.
- MY MISTAKE: my first version of `test_only_one_string_per_issuer_id` used a random key and, 39% of the time, "uppercased" two digits and got the original string back, so the suite failed 7 of 25 runs. Fixed by using a fixed signer and asserting each variant differs. Caught by repeating the suite.

## Test count
Before: 399. After round 1: 414 (+15 tests, +2 corpus cases = 251).
