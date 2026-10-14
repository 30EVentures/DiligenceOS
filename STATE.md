# Overnight review: summary (read this first)

Branch `overnight/diligenceos-bugs`, base `origin/main` @ ebb67da. Nothing merged, no PR, nothing deployed; `main` untouched; only this branch was pushed (plain pushes). Every commit is authored `30E Ventures <30eventures@gmail.com>`.

## Bad news first
**My mistakes**
1. I introduced two new 500s that the fresh-context review caught, now fixed and tested: `webapp._read_body` raised `ValueError` on a `Content-Length` of more than 4300 digits (round 5), and the delegation `issued_at` arithmetic could raise `OverflowError` near year 1 / 9999 (round 4).
2. My round-1 test `test_only_one_string_per_issuer_id` was flaky (39% of random keys made a "variant" equal to the original): the suite failed 7 of 25 runs until I used a fixed signer. Found by repeating the suite.
3. My round-5 atomic witness-state write silently changed file mode (0600 -> 0644) and replaced a symlinked `--state`; fixed after review.
4. Several of my tests were weaker than they looked (single message for the small-order test, a locale test that also passes on the base, a clock-dependent `issued_at` case); strengthened or removed (see the review section).
5. A review subagent reports it may have deleted a file named `/tmp/x` (its own draft script ran `unlink(missing_ok=True)`). No repository was touched.

**Bugs found and NOT fixed (need your decision; none is a regression)**
- P-1 The server's own log load accepts entries signed by a foreign key and unsigned entries; anyone who can write `receipts.jsonl` (not `issuer.key`) can get forged entries, including forged revocations, vouched for and enforced. Decision: what is a valid log.
- P-3 The signed request does not cover the credential chain or an audience (a captured request can be re-presented with the signer's wider credential); nonces are memory-only. Needs `request/2` (breaking; already in `docs/proposals`).
- (b) Known owner decision: a lone surrogate in an authenticated body is still a 500 before the signature check. Reproduced again by fuzzing; left alone as instructed.
- P-4/P-4b `decide`, `release_if_allowed`, `verify_receipt` treat missing `now` as "do not check expiry" and missing `trusted_issuers` as "trust any signer". Every HTTP path passes both; this is a library foot-gun.
- P-6 `POST /v1/verdict` is unauthenticated and appends to the log for every distinct input (unbounded growth).
- P-2 Homoglyphs (Cyrillic `a` in a Latin name) are not folded; screening can be evaded with them.
- P-5 / P-7 No socket timeout on the single-threaded server (needs the reverse proxy the README already requires); two servers on one data directory fork the log.

**BLOCKED**: nothing needed a human during the run. Items above are decisions, not blocks.

## Fixes, each proven by a test that failed first (details per round below)
1. Signatures/keys had many spellings (uppercase, whitespace); a small-order public key accepted a universal signature; NaN was canonical JSON; request JSON accepted duplicate keys / NaN / absurd nesting (RecursionError escaped). (round 1)
2. A blank or damaged witness baseline reset the witness to "first sight"; other bad baselines crashed it; state write not atomic; a hash-valid odd log entry gave a 500 not a 503; trailing-newline regex leaks. (round 2)
3. Sanctions screening was spelling-dependent (NFD accents, full-width, zero-width space, no-break space all passed a listed name); output depended on the machine's locale. (round 3)
4. One receipt could pay under many budgets; a delegation's `issued_at` was never read. (round 4)
5. Unbounded form bodies (200 MB), negative Content-Length hanging the single-threaded server, invalid UTF-8 -> 500, unbounded witness reads. (round 5)
6. A receipt whose `id` is a JSON array/object -> 500 on `/v1/verify` and `/v1/decide`; a huge TTL setting -> every verdict 500; the signed manifest called nonces "single-use". (round 6)
7. A signed head with `length: "3"` verified; an empty evidence quote was a vacuous citation. (round 7)
8. Non-ASCII admin token -> unauthenticated 500 on `/data/*` (pre-existing, found by review).

## Ranked improvement proposals
1. P-3 `request/2`: bind chain leaf + audience, persist nonces (closes the one place a signature does not say under which authority it was made).
2. P-1 sign-checked log load (own key only) + refuse foreign/unsigned entries after the first signed one.
3. P-4/P-4b make `now` and `trusted_issuers` required in `decide`/`release_if_allowed`/`verify_receipt` (the payer function already does).
4. P-6 a quota or token on `/v1/verdict`.
5. The spend-auth gate from `docs/design/proceed-gate-and-mcp.md` (payee, audience, single use, expiry bound in one signed document).
6. Refuse floats in `canonical_json` (cross-language digests).
7. P-2 confusable folding (UTS #39 skeleton), with an owner decision on false positives.
8. P-7 advisory lock on the data directory.

## Numbers
Tests: 399 before, 499 after (all OK; 10 consecutive runs, 5 hash seeds, 3 locales, 2 time zones, each module alone). Conformance corpus: 249 -> 260 cases, regenerated by `conformance/build_diligenceos_1.py` (byte-identical on re-run). Mutation checks: 11 breakages of `payment_check` + 8 of log/witness, all caught after one added test.

---

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

### Round 3: determinism
Checked [RAN]: the suite is green under PYTHONHASHSEED 0/1/4242, TZ Pacific/Auckland and America/Los_Angeles, LC_ALL tr_TR.UTF-8 and C; the corpus builder output is byte-identical under three hash seeds; a signed receipt, `Policy.to_dict`, `narrow` and `effective_policy` are byte-identical across four hash seeds (test `SameBytesOnEveryRunTest`).
- FIXED R3-1 [RAN] Screening was spelling-dependent, in the dangerous direction. `SanctionsList.match` did `strip().casefold()`: a listed name typed with decomposed accents (NFD), full-width letters, a zero-width space, a soft hyphen, a no-break space, a tab, or a BOM got `PASS`. `check_identity` used a different normaliser, and `Ledger.for_subject` compared exact strings (a subject with 3 late deliveries lost its record by changing the case or adding a space). All three now use one `normalize_name` (NFKC, drop invisible format characters, casefold, collapse whitespace), used for comparing only. Tests: `OneSubjectOneSpellingTest`.
- FIXED R3-2 [RAN] Output depended on the machine's locale: JSON files supplied by the user (sanctions list, batch request, CLI bodies) and the store/log/witness state were read and written with the locale encoding. Under `LC_ALL=C` a Cyrillic sanctions list raised UnicodeDecodeError, and on a cp1252 machine it would silently turn into mojibake, so the real name never matched. All are explicit UTF-8 now. Tests: `FilesAreUtf8OnEveryMachineTest` (subprocess under a C locale vs UTF-8 mode, same bytes).
- NOT FIXED (PROPOSAL P-2) Homoglyphs: a Cyrillic `а` in a Latin name is not folded to Latin `a` by NFKC, so `Bаnk` (Cyrillic a) does not match a listed `Bank`. Screening against confusables needs a mapping table (UTS #39 skeleton) and an owner decision on false-positive cost; I have not added one.
- NOT FIXED (note) `check_track_record` divides with floats (`late / total > 0.4`). It is correct for every ratio I tried (2/5 equals 0.4 exactly), but `late * 5 > total * 2` would remove the question.

### Round 4: money, payment, delegation
- FIXED R4-1 [RAN] One receipt could pay under many budgets. `try_spend` made a receipt idempotent per (budget, receipt id) only, so the same receipt submitted under budgets `b1` and `b2` committed its amount twice (24,000,000 each; found on 2026-10-11 and recorded in the design note, fixed now). A receipt now pays once, whichever budget is asked; the same budget stays idempotent; a refusal (over the cap, escalation) consumes nothing; holds across a restart; the refusal does not name the other budget. Tests: `OneReceiptPaysOnceTest`. Behaviour change: a second budget now gets `DENY` where it got `ALLOW`.
- FIXED R4-2 [RAN] A delegation's `issued_at` was never read by `verify_chain`: `"never"`, `5`, `""`, a naive timestamp, a date five years ahead, and a date after the link's own expiry all verified. A delegation meant to start later therefore started immediately. Now: must be a timezone-aware timestamp, not after its own expiry, not more than 300 s ahead of the verifier's clock, and not dated before its parent (300 s tolerance). Tests: `DelegationClockTest`; five new corpus cases (`dg-issued-at-unreadable`, `-naive`, `dg-issued-in-the-future`, `dg-issued-after-expiry`, `dg-child-dated-before-parent`), three new error codes in the adapter.
- NOT FIXED (PROPOSAL P-3, already proposed in docs/proposals) the signed request does not cover the credential chain (confirmed again 2026-10-11: swapping in a wider credential authenticated with 90,000,000 instead of 1,000,000). Needs `request/2`; breaking.
- NOT FIXED (PROPOSAL P-4) `decide`, `release_if_allowed`, `verify_receipt` still treat `now=None` as "do not check expiry". Every HTTP path passes a clock, so this is a library foot-gun (it is the DL-6 finding in someone else's format, here as an optional argument). Making `now` required is an API break; `payment_check` already requires it.
- CHECKED, no bug: scope, expiry, budget and policy narrowing in `verify_chain` (including the parent id, 2026-10-11); the credential's budget binding in `/v1/spend`; revocation is read from the reconciled index at enforcement time; amounts are `int`s bounded by 2^53-1 everywhere `Money` is built.

### Round 5: input handling
- FIXED R5-1 [RAN] The HTML form routes (`POST /verdict` and the three `/data/*` writes) read `CONTENT_LENGTH` bytes with no cap: a declared 200,000,000 bytes was read in one call, before the admin-token check. Now refused unread with 413 above `api.MAX_BODY_BYTES` (1 MiB). Tests: `BodySizeTest`.
- FIXED R5-2 [RAN] A negative `Content-Length` became `read(-1)` on both the form routes and `/v1/*` (the cap was `min(length, MAX+1)`, and `min(-1, ...)` is -1). `read(-1)` on a real socket waits until the client closes, and the server is single-threaded `wsgiref`, so one connection with `Content-Length: -1` stops all service. Now any value that is not ASCII digits is 400 and never reaches `read`. (Non-ASCII digits, `+5`, `1e3`, `0x10`, ` -1` are all refused.)
- FIXED R5-3 [RAN] Invalid UTF-8 in a form body raised `UnicodeDecodeError` (a 500 with a traceback); now 400. Forms are limited to 64 fields.
- FIXED R5-4 [VERIFIED by reading, RAN with a fake reply] The `witness` command read the server's replies with `json.load(resp)`, unbounded; the witness is the party that distrusts that server. Replies are now capped at 16 MiB (a full page is under 1 MiB).
- NOT FIXED (PROPOSAL P-5) The server is single-threaded stdlib `wsgiref` with no socket timeout: a client that opens a connection and sends nothing (or a declared body it never finishes) holds it. That is a property of `wsgiref`, not of this code; the README already says a reverse proxy must front it. A proxy with a read timeout closes it; the code alone cannot.
- NOT FIXED (PROPOSAL P-6) `POST /v1/verdict` is unauthenticated and appends a signed entry to the log for every distinct input, so anyone who can reach it can grow `receipts.jsonl` and `store.json` without bound. Needs an owner decision (a quota, a token, or accepting it behind a proxy).
- CHECKED, no bug: every value shown in the HTML pages goes through `html.escape`; no route serves files or takes a path; `/v1/log/*` paging is strict; the lone-surrogate case on `/v1/verdict` is handled (the authenticated-route case is the known `known_failure`).

### Round 6: corpora and tests
Method [RAN]: a deterministic mutation fuzz of every verifier and every POST endpoint (replace, delete or add one node of a valid receipt, delegation chain, auth envelope, log, head, cosignature or request body; 7 targets x 1500 rounds x 5 seed blocks); the stdlib line tracer (`python -m trace --count --missing`; `coverage` is not installed) to find branches no test reaches; each test module alone; the suite 10 times in a row; the suite with an empty `HOME`.
- FIXED R6-1 [RAN] Unauthenticated 500: a receipt-shaped body whose `id` is a JSON array or object made `verify_receipt` do `revocations.get(<list>)` and raise `TypeError` (`/v1/verify`, `/v1/decide`; `/v1/spend` after auth). Now the receipt is simply invalid. Tests: `HostileDocumentsTest` (a fixed-seed mutation net kept in the suite) and two corpus cases (`rc-id-is-an-object`, `rc-id-is-a-list`).
- FIXED R6-2 [RAN] `DILIGENCEOS_RECEIPT_TTL_SECONDS=99999999999999999999999` made every `/v1/verdict` raise OverflowError; `99999999999` issued receipts valid for 3,000 years; a negative value issued receipts that were born expired. Outside 0..1 year it is now the 24 h default. Tests: `ReceiptTtlConfigTest`.
- FIXED R6-3 (overclaim) The signed manifest said request nonces are "single-use" and `/v1/capabilities` said the same. They are held in memory for the process lifetime only (a replay after a restart passes) and the signed message covers neither the credential chain nor an audience. Both documents now say so (`request_auth.freshness`, new `request_auth.not_covered`). Tests: `MachineReadableClaimsAreNotLargerThanTheCodeTest` pins the wording AND demonstrates both behaviours.
- FIXED R6-4 `delegation.verify_chain` raised TypeError for a non-string `now`; now "no".
- ADDED tests for branches nothing reached: unparseable bodies on every POST route, non-object bodies on the authenticated routes, `sources` validation, revoke's delegation arguments, 503 `signer_unavailable` on verify/decide/revoke/spend/cosign/manifest, signed-but-nonsense money in `payment_check` (an untested branch of my own earlier module), `effective_policy([])`, the cosign-submission refusal message, the adapter's malformed-case answer.
- NOT FIXED, known (owner decision (b), `decisions.md` 2026-10-07): a lone surrogate in an authenticated body still raises before the signature check. The fuzz reproduces it as `UnicodeEncodeError` at `receipt.py` `canonical_json` called from `auth._message`. I left it alone as instructed and excluded that one case from the HTTP net.
- Flake check: the only flaky test in the suite was my own round-1 test (see MY MISTAKES); nothing else failed in 10 repeated runs, 8 hash seeds, 3 locales, 2 timezones, or in isolation.

### Round 7: receipts and signatures, second pass
- FIXED R7-1 [RAN] A signed log head or cosignature had a second valid spelling: the signed message is `f"{length}:{head_hash}"`, so `{"length": "3", ...}` verified with the signature made for the integer 3 (`verify_head`, `verify_cosignature`; floats, bools and negatives already failed by accident of formatting). Both now require `length` to be an `int` >= 0 and strings where strings belong. Tests: `SignedDocumentFieldTypesTest`.
- FIXED R7-2 [RAN] Evidence could be vacuous. `verify_citation("")` is True for every source (`"" in text`), so a receipt whose evidence quoted `""` passed `verify_evidence`, and `absent=""` would have passed the absence check once the quote case was fixed. Empty and whitespace-only quotes/absences are now errors ("proves nothing"). Tests: `EvidenceIsNeverVacuousTest`; corpus cases `rc-evidence-empty-quote`, `rc-evidence-empty-absence` (260 cases).
- CHECKED, no bug: domain separation (`domain + "\n" + message`; no domain contains a newline, so no two documents can produce the same signed bytes); trust comes only from the verifier's list, never from the receipt; `/v1/verify` takes `trusted_issuers` only from the caller's envelope.
- NOT FIXED (PROPOSAL P-4b) `decide()` / `release_if_allowed()` called without `trusted_issuers` accept a receipt signed by any key, including one the attacker made. Every HTTP path supplies the server's key; the library default is the foot-gun (same family as P-4).

### Round 8: signed log and witness, second pass
Property tests over random logs (`tests/test_log_witness_properties.py`, seeds fixed): every honest append-only history is accepted from every earlier point; truncation below the seen point, a different history of equal or greater length, one entry replaced and everything after it re-hashed and re-signed by the operator's own key, swapped/duplicated/dropped/re-sequenced entries, any single-field edit of any signed entry, entries signed by another key, and a head that describes a different log are all refused. No new bug found. Mutation check [RAN]: seven deliberate breakages of `check_consistency` and `verify_chain` are each caught; an eighth (skipping the head signature check) was NOT caught until I added `test_a_head_whose_signature_is_not_the_pinned_issuers_is_refused`.
- NOT FIXED (PROPOSAL P-7) Two servers pointed at one data directory would both append to `receipts.jsonl` from their own in-memory head, forking the chain (both then refuse to start), and `store.json` is last-writer-wins, which could drop a revocation. An advisory lock on the data directory would prevent it; the test suite creates several `Store`s on one path in one process, so the lock needs a deliberate design.
- NOT FIXED (note) log entries' `logged_at` is never checked for monotonicity; it is not an integrity property, only a signal.

### Fresh-context review (3 subagents) and what it changed
Reviewers: A (crypto/parsing diff), B (behaviour-change diff), C (tests and corpus; also reproduced every [RAN] claim above on origin/main: all reproduce). All 489 tests passed for all three. Findings acted on:
- FIXED [RAN, reviewer A] my `webapp._read_body` raised `ValueError` for a Content-Length of more than 4300 digits (Python's int-conversion limit): a new 500 on every route, which origin/main answered 400/200. Capped at 15 digits.
- FIXED [RAN, reviewer B] my delegation clock arithmetic could raise `OverflowError` near year 1 / year 9999 (a 500 on `/v1/spend` with a self-made key). Caught.
- FIXED [RAN, reviewer A] the witness state file lost its permissions (0600 became 0644) and a symlinked `--state` was replaced by a regular file; both kept now.
- FIXED [RAN, reviewer A] `_json_from_response` let `RecursionError` through on a deeply nested reply.
- FIXED [RAN, reviewer A; pre-existing, not from this branch] a non-ASCII `admin_token` made `hmac.compare_digest` raise TypeError: an unauthenticated 500 on every `/data/*` POST. Compared as bytes now.
- FIXED manifest wording: nonces are kept for 600 s, not 300 s.
- TESTS STRENGTHENED [reviewer C]: the small-order test used one message (an order-4 key signs 14 of 64 messages with a universal signature, so one message proved little) and left the y=0, order-8 and sign-bit entries unpinned: now every encoding x 64 messages; each required log-entry field is tested on its own; the oversize-reply test now uses valid JSON so only the size check can fail it; the `issued_at` test no longer passes by accident of the wall clock for `""`/`None`; casefold/final-sigma/compatibility-form name cases pinned. REMOVED `test_the_store_round_trips_non_ascii_under_any_locale`: it passes on the base too (all on-disk JSON is ASCII-escaped), so it proved nothing about locale.
- NOT CHANGED (reviewer C, survivors judged equivalent or cosmetic): 44 of 114 hand mutations survived; many are equivalent mutants (e.g. the second NFKC pass in `normalize_name`, the temp-file `unlink` in `finally`). The list is in the reviewer's notes, which live in the session scratchpad and are not committed.
- NOTED (reviewer B, LOW) `Ledger.for_subject` now pools records across spellings, so a subject's late deliveries can be diluted by a lookalike's on-time ones; records are operator-entered. A budget id is client-chosen for unbound credentials, so a receipt holder can block another budget by spending first (a consequence of "a receipt pays once", worth knowing).
- NOTED (reviewer B, LOW) a verifier clock more than 300 s behind the issuer's now rejects a fresh delegation as "not valid yet"; 300 s is `delegation.CLOCK_SKEW_SECONDS`.
- NOTED (reviewer A) `GET`s with a malformed `Content-Length` header now get 400 (they were served before); browser forms over 1 MiB or with more than 64 fields are refused.
- REVIEWER MISTAKE: reviewer A reports that a draft script of its own ran `unlink(missing_ok=True)` on `/tmp/x`; if a file named `/tmp/x` existed it is gone. No repository was touched. I did not use `/tmp/x`.

## Test count
Before: 399. After round 1: 414 (+15 tests, +2 corpus cases = 251). After round 2: 425. After round 3: 435. After round 4: 444 (corpus 256 cases). After round 5: 455. After round 6: 476 (corpus 258 cases). After rounds 7-8: 489 (corpus 260 cases). After review follow-ups: 499.
