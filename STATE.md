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

### Round 2: signed log and witness
- FIXED R2-1 [RAN] A damaged witness baseline reset the witness. `check_consistency` used `if previous:`, so a baseline of `{}`, `[]`, `""`, `0`, `false` or JSON `null` was "first sight" and any rewritten history was cosigned; a baseline with a string, negative or missing length crashed with TypeError/IndexError/KeyError. Now `previous is None` is the only first sight, anything present-but-unreadable is exit 3 with the state file untouched, and an unreadable state file is a refusal, not a traceback. Tests: `DamagedBaselineTest`.
- FIXED R2-2 [RAN] The witness wrote its state with `write_text` straight onto the real file (the bug class already fixed in `Store._save`): a crash mid-write truncated the baseline. Now temp file + `os.replace`. Test patches `write_text` to die half way.
- FIXED R2-3 [RAN] A hash-valid log entry that lacked `receipt_id`/`inputs_digest`/`outcome_digest` made `ReceiptLog(path)` raise `KeyError`, so the API answered 500 instead of 503 `log_unavailable` and `Store.revocations` (which catches only `LogCorruptError`) crashed. Now `LogCorruptError`.
- FIXED R2-4 [RAN] `^...$` regexes accept a trailing newline: `limit=5%0A`, and a `/v1/revoke` target id of `sha256:<hex>\n` (recorded in the signed log forever, matching no receipt). Now `fullmatch`.
- DEFERRED (PROPOSAL P-1) The server's own log load (`ReceiptLog(path)`) checks the hash chain but not who signed: entries signed by a foreign key, or unsigned entries after signed ones, load, are covered by the next head the server signs, and revocation entries among them are enforced (PR #32 union). Someone who can write `receipts.jsonl` but not `issuer.key` can therefore get the server to vouch for forged entries and to enforce forged revocations. Fix needs an owner decision (it changes what a valid log is; legacy unsigned logs exist): load with `trusted_issuers=[own key]` and refuse entries that are not own-signed after the first signed one.
- NOTE There is no Merkle tree, so no inclusion/consistency proof and no id-sorted-leaves class of bug: the log is a linear hash chain, a verifier needs the whole prefix. A head carries no timestamp (already noted in the design note).

## Test count
Before: 399. After round 1: 414 (+15 tests, +2 corpus cases = 251). After round 2: 425.
