# Decisions log

Dated, one entry per real decision. Not a changelog — the code and commit
history already say what changed; this says why, where "why" isn't obvious
from reading the diff.

## 2026-10-01 — Security hardening: four auth/authority gaps closed

An external audit of this code found four real gaps. All four are fixed in
one pass; none change what a well-behaved caller can already do.

**1. `/v1/spend` no longer accepts `trusted_issuers` from the request body.**
A delegate holding only the `spend` scope could submit a receipt it signed
itself and list its own key in `trusted_issuers` — the server honored that
and allowed the spend. `_server_trusted_issuers(store)` now always returns
the operator's own issuer id, full stop; the field is ignored on this
endpoint. This is the same principle already stated below for the
credential's policy: the trust root is the operator's, not the caller's,
for anything that commits real spend.

**2. `/v1/verify` no longer reads `trusted_issuers` out of the receipt being
verified.** Posted bare (no envelope), the whole body *is* the receipt —
`trusted_source` used to default to that same object, so a forged receipt
could carry its own `trusted_issuers` field naming itself trusted and get
back `trusted: true` for itself (even though `valid: false`, a caller
checking only `trusted` would be fooled). `trusted_source` is now `{}` for
a bare receipt and only ever the wrapping envelope's own fields
(`{"receipt", "sources"?, "trusted_issuers"?}`) otherwise — never the
object under test.

**3. `/data/*` writes now require `DILIGENCEOS_ADMIN_TOKEN`.** These HTML
routes directly rewrite the sanctions/registry/delivery dataset every
verdict is checked against, and had no auth of any kind. The full
Ed25519 signed-request scheme (`auth.py`) doesn't fit a plain HTML
`<form>` without inventing client-side crypto or a session layer, so this
took the documented "at minimum" option: a shared operator token, compared
with `hmac.compare_digest`, required on all three write routes. **Fails
closed** — with no token configured, every write is refused outright,
there is no "no auth configured, allow everyone" fallback, since an open
default would be the same bug with extra steps. `GET /data` (viewing) and
`/verdict` (checking) are unaffected; this is about writes only.

**4. `/v1/revoke` now scopes a delegate's authority to what it actually
created.** Any delegate holding `revoke` could revoke *any* receipt or
delegation — including ones it never issued, siblings, or its own parent.
`specs/slice-26/spec.md` admitted this gap outright ("no per-delegate
revocation of only their own issuances"); `docs/decisions.md`'s own
2026-09-29 entry claimed "only the operator can revoke one," which the
code didn't actually enforce. Now: a **receipt** can only be revoked by the
operator (receipts are always issued with this server's own key, never a
delegate's, so no delegate ever "issued" one). A **delegation** can be
revoked by the operator by id alone, or by the delegate that issued it —
but only by submitting the signed delegation object itself, not just its
id, since the server never stores delegations and has no other way to
check who its `delegator` really is. The object's `id` and `signature` are
re-verified server-side before the authorship check runs, so a forged or
edited delegation is refused (400), not silently trusted.

**Why fix these together, as a patch rather than a slice.** None of the
four change the documented, intended behavior for a well-behaved caller —
they close gaps between what the docs already claimed and what the code
actually did. That's a bug-fix pass, the same shape as the 2026-09-29
"`/v1/spend` authenticates before validating the body" fix, not a new
capability — so it isn't a numbered slice.

## 2026-09-28 — Persistence lives outside the repo entirely, not in a fixture

Slice 13 made `Store` durable: `~/.diligenceos/store.json` by default,
overridable via `DILIGENCEOS_DATA_PATH`. It's a real file now, but
deliberately still not inside `~/DiligenceOS` at all — the concern from
Slice 12's original "stay in-memory" decision (below) was never really
about persistence itself, it was about a checked-in fixture silently
becoming mutable state. Writing to a path outside the repo keeps that
concern resolved while still giving real, felt persistence across
restarts, which stopped being optional the moment this became a tool
someone actually restarts and expects to still work.

One test-isolation bug this caused and fixed in the same slice: the real
subprocess test in `tests/test_cli.py` (`ServeModeTest`) launches an actual
`python3 -m diligenceos` process, which reads real environment variables —
without also overriding `DILIGENCEOS_DATA_PATH` there, that test was
silently reading and writing the real `~/.diligenceos/store.json` on every
run. Caught by noticing the file existed with fresh sample-seed content
right after a test run that should have touched nothing outside temp
directories. Fixed by giving that test its own temp path too.

## 2026-09-28 — Editable data stays in-memory, not written to a file

Slice 12 made the sanctions list, registry, and delivery ledger editable
through the web UI. Additions still don't survive a process restart.
Reason: writing back to `fixtures/golden/sample_request.json` (or a new
file) would quietly turn a checked-in fixture into mutable runtime state —
the next `git status` would show uncommitted changes nobody remembers
making, and the "sample dataset" stops being a reliable, reviewable
starting point. A real durable store (its own file format, or a database)
is a decision worth making deliberately, once there's an actual reason
in-memory-per-process isn't enough — not a side effect of adding a form.

## 2026-09-28 — `Store` reuses `Ledger` directly, only adds what was missing

`Store` doesn't wrap or reimplement Slice 7's `Ledger` — it holds one and
calls its existing `record()` method. The only change made to
`track_record.py` was adding `Ledger.all_records()`, because the `/data`
page is the first caller that ever needed every record instead of one
subject's. Reusing what already worked, and extending it by exactly the
one method a real caller needed, beat writing a parallel structure that
could drift from the checked, tested one.

## 2026-09-28 — Web front end is stdlib `wsgiref`, not Flask

Slice 11 added a real, always-on local web UI, by explicit request ("a
front end at all times going forward, not just a sample"). It's built on
`wsgiref.simple_server`, part of the standard library, not a new
dependency. Reason: `CLAUDE.md`'s dependency rule asks that a new one be
added only when a slice's explicit point is adding it, and for a single
form + result page, stdlib WSGI is enough — no templating engine, no
routing library, nothing Flask would give beyond what a ~15-line dispatch
function already does here. Revisit if the UI's needs actually outgrow
this (sessions, multiple routes with path parameters, file uploads).

## 2026-09-28 — No argument now means "serve", not "usage error"

Before Slice 11, `python3 -m diligenceos` with no arguments printed a
usage error. Now it starts the web server (blocking) instead, and the old
one-argument batch mode is unchanged. This is a deliberate, backward-
compatible-except-for-that-one-case behavior change: the front end is
meant to be the default way to use this repo going forward, so its own
command should be the one that starts it, not a flag or subcommand nobody
remembers.

## 2026-09-28 — Repo identity kept separate from the personal GitHub account

Local git config in this repo is `30E Ventures
<233154122+30EVentures@users.noreply.github.com>`, not the machine's global
identity. Reason: an earlier project (the seal/verifier work under 30E
Ventures) leaked a personal email into commit history before anyone
noticed, and had to be caught and fixed before the repo could go public.
Setting it correctly from commit #1 here avoids repeating that.

## 2026-09-28 — Capabilities reimplemented fresh, not shared/imported

DiligenceOS's citation-verification (`evidence.py`) and release-gating
(`gate.py`) ideas both have working equivalents elsewhere under 30E
Ventures. Neither is imported, vendored, or copy-pasted here. Reason:
DiligenceOS's branding rule requires no dependency-graph link back to those
projects, even privately — a shared package name or a copied file header
would be a real (if quiet) link. Each implementation here is DiligenceOS's
own, informed by the design, independent in code.

## 2026-09-28 — Sanctions is the one hard-stop category; everything else is a hold

`assemble_verdict` (Slice 5) treats a flagged sanctions finding as an
automatic `RED_FLAG`, overriding every other finding, while every other
category only produces `HOLD`. Reason: a sanctions match has real legal
weight (OFAC exposure) that a track-record flag or a missing contract
clause doesn't carry the same way; collapsing them to the same severity
would understate the one that actually matters most. The penalty weights
(40 vs. 15 points off `trust_score`) are a first, adjustable guess, not a
calibrated figure — Phase 2's audited methodology is where these get
justified against real outcomes, not here.

## 2026-09-28 — Evidence discipline built, not yet enforced at assembly time

Slice 6 built `require_citable()` but didn't wire it into
`assemble_verdict()` or the pipeline. Reason: it wasn't clear yet whether
the discipline belongs per-check (each check calls it on its own findings
before returning), at assembly time (once, over the whole list), or both —
and Phase 0's real checks (fixture-based sanctions, an injected identity
lookup) don't have real citable evidence to enforce yet anyway. Deferred
until there's a real caller whose needs can settle the question, instead of
guessing.

## 2026-09-28 — OFAC SDN ingestion split into two slices (3 and 3b)

Slice 3 proved the matching mechanism against a small fixture list; Slice
3b added a parser for the real published CSV format, tested against a
fixture written in that format rather than real government data or a live
fetch. Reason: debugging string-matching logic and debugging a real-world
CSV's format quirks (headerless, fixed columns, inconsistent `a.k.a.`
punctuation) are different kinds of problems; solving them in the same
slice risks not being sure which one broke when a test fails. `fetch_sdn_list()`
exists and is real, but stays untested by the automated suite — a live
network call in `unittest discover` is a flaky test waiting to happen, and
the published URL can move without this repo knowing.

## 2026-09-29 — North star: infrastructure for the agentic internet

Reason: the product's value to an agent is a verdict it can act on without
a human in the loop, which only works if the verdict is structured,
independently re-checkable, and bounded (money in integer minor units,
authority that can narrow but never widen). Building the human UI first and
bolting an API on later would bake in human-shaped assumptions, so Track A
in `ROADMAP.md` puts the machine-verifiable core (receipts, API, evidence)
ahead of more human-facing features. This is a design stance, not a
commitment to adopt any particular external spec; formats here are our own,
open and versioned so that interoperability stays possible later.

## 2026-09-29 — Receipts are hash-sealed but unsigned, and verification replays the rules

Slice 15's receipt id is a sha256 over canonical JSON. That alone is
forgeable by anyone who can recompute a hash, so `verify_receipt` also
replays `assemble_verdict` over the receipt's own findings and rejects a
verdict or score that doesn't follow. The result: a stranger can confirm
internal consistency and rule-compliance offline, but not *who* issued it.
Signing is deferred rather than faked: the stdlib has no asymmetric
signatures and HMAC would need a shared secret, which defeats third-party
verification. It gets its own slice with a deliberately chosen, pinned
dependency. `RULES = "verdict-rules/1"` is in every receipt so a future
change to penalty weights doesn't silently invalidate old ones.

## 2026-09-29 — The machine API is a pure handler; a failed verification is a 200

`api.handle()` takes and returns plain values and knows nothing about WSGI,
so the whole contract is unit-tested without a server; `webapp.app` only
delegates `/v1/*` to it. `/v1/verify` answers `200 {"valid": false, ...}`
for a forged receipt: the call succeeded, the *document* failed, and an
agent should branch on `valid`, not on HTTP status. Errors use one JSON
shape with stable `code`s (and a `field` when one input is at fault) so a
caller can handle them without parsing prose. The receipt's `inputs_digest`
covers a digest of the store's data as well as the request, since the same
request against different data legitimately yields a different verdict.

## 2026-09-29 — Evidence enforced in the pipeline, per-claim, verified by the holder of the source

Settles the Slice 6 open question. Enforcement lives in `run_diligence`
(once, over all findings, before assembly) rather than inside each check:
a check can't forget to police itself, and the exemption list
(`identity`, `track_record`) sits in one visible constant. Evidence is a
per-claim structure — a `quote` that must appear or a phrase that must be
`absent`, pinned to a `source_digest` — because "this clause is missing"
is the main document finding and an absence can't be quoted. Verification
is done by whoever holds the source text (`verify_receipt(sources=...)`),
so the service is not the trusted party; sources it couldn't check are
reported in `unchecked`, never silently skipped. Limit, stated: a digest
shows which bytes were used, not that the source is authentic.

## 2026-09-29 — Money is `Money(amount_minor, currency)`; the demo gate's API changed

Floats can't hold most decimal amounts exactly, and anything an agent might
act on must not round silently. `Money` rejects floats, bools, negatives and
malformed currency codes at construction, so a bad amount fails at the edge
(a `400` naming the field) instead of deep in a calculation. This changed
Slice 10's `EscrowGate` (`held_amount: float` -> `held: Money`), the one
tested API touched by Track A; only its own tests used the field. The
transaction rides in the receipt, sealed by the id, so a verdict is bound to
the deal it was issued for; it doesn't influence scoring yet.

## 2026-09-29 — Delegated authority is checked axis by axis; RED_FLAG is not delegable

`narrow()` compares a child policy to its parent on each axis (currency,
cap, acceptable verdicts, trust floor) and raises naming the one that
widened, so a rejected delegation says exactly why. A chain is folded link
by link — comparing each link to its immediate parent is enough because
"at least as narrow as the previous" is transitive. `RED_FLAG` cannot appear
in `acceptable_verdicts` at all: a sanctions hit is the one outcome no
policy, at any level, may wave through (mirrors Slice 5). `decide()` uses
three outcomes rather than two so "a human should look" (ESCALATE) is
distinct from "never" (DENY): a limit breach is ESCALATE, an unverifiable
receipt or RED_FLAG is DENY. Stated limit: nothing yet proves who issued a
policy; signatures (Slice 21) close that.

## 2026-09-29 — The gate computes its own decision and binds the receipt to the deal

`release_if_allowed` takes a receipt and a policy, not a pre-made
`Decision`: if the caller supplied the decision, the gate would be trusting
the caller to have run the policy. It also refuses a genuine, in-policy
receipt issued for a *different* subject or amount, because a valid receipt
is a statement about one deal, not a bearer token. That mismatch is DENY
(not ESCALATE): a human re-reading it wouldn't change what it is. The old
`apply_verdict` stays, marked demo-only, rather than being deleted — it is
a tested API and removal is the owner's call.

## 2026-09-29 — Standing is separate from integrity; a policy cap is a budget

`verify_receipt` keeps *integrity* (`valid`) apart from *standing*
(`expired`, `revoked`): a revoked receipt is still an authentic document, and
collapsing the two would make "was this forged?" unanswerable once anything
is revoked. `decide()` is where standing bites (revoked -> DENY, expired ->
ESCALATE: a fresh check may well pass, so a human/agent should re-run, not
give up). Revocations and spend live in the persisted store file but *not*
in `Store.to_dict()`, which is what `data_digest` covers: revoking a receipt
must not change what any verdict was issued against. Spend is committed per
`budget_id`, idempotent per receipt id (presenting a receipt twice, or
replaying it, spends once), and only on ALLOW; a payment that would push
the budget past the cap is ESCALATE with the running total in the reason.
Stated limits: `/v1/revoke` and `/v1/spend` are unauthenticated and
budgets are caller-named, so this is safe on localhost only; revoking does
not claw back spend already committed. Both are what signed issuers and
delegated identities (Slice 21 onward) are for. The 24h default TTL is a
guess, adjustable with `DILIGENCEOS_RECEIPT_TTL_SECONDS`, not calibrated.

## 2026-09-29 — A hash-chained receipt log; conflicts are recorded, not blocked; the log fails closed

Every receipt `/v1/verdict` issues is appended to `receipts.jsonl` (beside
the store file), each entry hashing the one before it. A chain rather than
a Merkle tree: at this size the simplicity is worth more than logarithmic
proofs, and `verify_chain` is a dozen lines a stranger can reimplement.
Because receipts carry `issued_at`, re-issuing the same request legitimately
produces a different receipt id, so equivocation is defined on the
*outcome*: same `inputs_digest` (which already covers request, transaction
and a digest of the store data) but a different verdict/score/findings.
That is flagged inside the hashed entry (`conflict_with`) and cannot be
removed without breaking the chain. It is flagged, not refused, because
the log can't know whether the cause was a legitimate rules change or a
fault — it only guarantees the discrepancy stays visible. The log fails
closed: a file that fails verification stops `/v1/verdict` (503) instead of
extending a broken history. The receipt body is untouched; log position is
returned in response headers because any extra body field would break the
receipt's own id. Honest limit: an operator who controls the file can still
rewrite the whole chain, and a dropped tail is only detectable by someone
holding an earlier head. The log becomes evidence against the operator only
once heads are signed and witnessed elsewhere (Slice 21 onward).

## 2026-09-29 — Signed receipts; first dependency: `cryptography` (owner-approved)

**Why a dependency at all.** Third-party verifiability is the point of a
receipt, and the stdlib can't provide it: it has no asymmetric signatures,
and an HMAC needs a secret the verifier would also have to hold — which
makes the verifier able to forge. **Why `cryptography`, not hand-rolled
Ed25519 or a smaller lib.** Rolling our own signature code is the one thing
not to do in a trust product (timing side channels, subtle malleability);
`cryptography` is the maintained, widely audited standard binding and ships
wheels for our Python. Pinned exactly with its two transitive deps
(`cffi`, `pycparser`) in `requirements.txt`. The cost, accepted: the repo is
no longer stdlib-only, so tests and the server run from a venv, and the
always-on server on port 8000 must be started from `.venv/bin/python`.

**Design.** The issuer id *is* the public key (`ed25519:<hex>`), so a
receipt is self-describing and the check needs no directory. The signature
covers the receipt `id`, which already commits to every field including
`issuer`, so swapping the claimed issuer breaks the id and re-sealing the id
breaks the signature. Signatures are domain-separated (`receipt/1` vs
`log-head/1`) so one purpose can't be replayed as another. Keys live in a
0600 file beside the store (outside the repo); a bad key file is a `503`,
never silently regenerated — a new key would be a new, unannounced identity.

**The line that matters: valid vs. trusted.** A receipt signed by *any*
key is internally valid. It is *trusted* only if the verifier's own list
names that issuer. So `verify` reports `trusted` separately, `decide`/gate/
spend DENY untrusted receipts once given a list, and the API defaults the
list to the server's own key — so a stranger's perfectly valid receipt can't
release money here, while a caller can still pass `trusted_issuers` to
accept other issuers. The `issuer` field and `/v1/issuer` are claims; trust
has to be pinned out of band. **Not done, stated:** key rotation, key
revocation, a key directory, keychain/HSM storage, and authenticating the
*caller* of `/v1/revoke` and `/v1/spend` (Slice 25 — signatures identify the
issuer, not who is asking).

## 2026-09-29 — Callers authenticate with a signed request and a credential chain that only narrows

**Problem.** Slice 21 proved who *issued* a receipt; `/v1/revoke` and
`/v1/spend` were still open to anyone who could reach the server.

**Two separate proofs, on purpose.** (1) A *delegation chain* says what a
key is allowed to do: signed links from the operator down to the caller,
each of which may only narrow the one above it — scopes, expiry, the budget
it is bound to, and the Slice 19 `Policy` (verified with the same `narrow()`
that already existed, so there is one definition of "narrower" in the
codebase). (2) A *signed request* says the caller holds the key the last
link names. Without (2) a credential is a bearer token: anyone who copies
it, from a log or a shared file, is the agent. The request signature covers
the path, the body (minus `auth`), the time and a nonce, so a signed spend
can't be replayed as a revoke, against another body, or later than five
minutes; nonces are single-use.

**Operator is the empty chain.** A request signed by the server's own key
with no credential has all scopes and no policy limit. That keeps the model
to one mechanism instead of a separate admin path (a shared token would have
been the alternative; it can't be delegated, narrowed or attributed).

**A credential's policy *is* the policy for spend.** The request may carry a
policy only to narrow it. Letting the caller pick their own cap would make
the credential's cap decorative. The caller's id is recorded on each spend
entry so a budget can be audited by who drew on it.

**Revocation reuses the list from Slice 22.** Any delegation id in the
revocations list invalidates that link and, because a chain is verified end
to end, everything delegated below it, immediately. Ids are content hashes,
so receipt and delegation ids share one namespace without ambiguity;
`/v1/revoke` accepts `delegation_id` for clarity.

**Refused at creation.** `delegate` verifies the chain it is about to emit
and refuses a widening child, naming the axis, rather than minting a
credential that would only fail at use.

**Stated limits.** `/v1/decide`, `/v1/verify`, `/v1/verdict` and the log/
revocation reads stay open (they compute or expose no authority). The nonce
cache is in memory (replays of these two idempotent endpoints are harmless
if it is forgotten by a restart inside the window). Delegations are not
logged, and only the operator can revoke one. No key rotation or directory;
keys are plain files. The chain depth cap (4) and the five-minute skew are
guesses. Slice 26 (signing revocation/log entries, witnessing heads) is
what remains of the accountability story.

## 2026-09-29 — Signed entries, revocations in the log, and a witness; why the server can't audit itself

**Signed entries.** Each new log entry carries `kind` and `issuer` inside
its hashed body, plus a `signature` over `entry_hash` (excluded from the
hash, or it would sign itself). One entry plus its signature is now a
self-contained statement — "this issuer logged this at position n" —
that can be shown to someone without handing over the whole file. Logs
written before this slice load and verify unchanged; their entries are
simply unsigned (`require_signed` exists for verifiers who want to refuse
them), so no migration was needed.

**Revocations moved into the log.** They were a JSON field the operator
could quietly delete, which meant "revoked" was only as strong as the
operator's honesty on the day. Now `Store.revoke` appends a signed entry
naming the caller (Slice 25's authenticated identity) *before* touching
the index, and fails closed if the log or key is unusable — an unattested
revocation is worse than an error. The index stays as a fast lookup;
`/v1/revocations` returns the backing signed entries with it.

**The limit that motivates the witness.** Every check the server can run on
itself — chain, per-entry signatures, signed head — passes for an operator
who rewrites history and re-hashes and re-signs the whole file, because the
rewrite is internally consistent and signed by the real key. (Demonstrated
live: `/v1/log/verify` said valid after a rewrite.) The only thing that
distinguishes it from the truth is *memory held by someone else*. A witness
stores the last head it accepted and requires the new log to have the same
hash at the same position (never shorter). It writes state only on success,
so a bad round can't become the new baseline, and it exits 3 so it can sit
in cron or monitoring. It cosigns `(issuer, length, head_hash)` so a
verifier can hold the issuer's signature plus independent witnesses'
signatures on one head.

**Cosignatures are allow-listed.** `POST /v1/log/cosign` accepts only
witnesses named in `DILIGENCEOS_WITNESSES` (empty = none) and only for a head
the log really has. Open submission would let anyone fill the store with
throwaway keys; the allow-list costs the operator one env var and costs the
verifier nothing, since verifiers pin the witness ids they trust regardless.

**Stated limits.** A witness that first looks *after* a rewrite can't know
(shown in the tests); the guarantee starts at its first observation, and it
is only as independent as whoever runs it — a witness on the operator's own
machine proves the mechanism, not the independence. No gossip between
witnesses, no public log, no trusted timestamps. Delegation issuance is
still unlogged. Track A is otherwise complete apart from Slice 24 (a
discoverable manifest), deliberately last.

## 2026-09-30 — A signed manifest whose sufficiency is tested; at `/v1/manifest`, not `/.well-known/`

**What it is for.** `/v1/capabilities` says what the endpoints accept. The
manifest says what a stranger needs to *trust* the output: who operates the
service, which key to pin, and for every signed or hashed document how to
verify it — what the id covers, the exact domain string that separates one
signature purpose from another, the canonical-JSON and digest rules, and the
verdict-replay rules with their constants. It is signed by the issuer so
tampering in transit is detectable by anyone who has pinned the key.

**Nothing in it is typed twice.** Every schema id, domain string and limit is
read from the module that enforces it (and the verdict weights from the
engine), and a test asserts they agree, so the manifest cannot quietly drift
from the code. The one constant I had to extract to make that true was the
base trust score.

**Sufficiency is a test, not a claim.** A documentation-style manifest can
look complete and still omit the rule an implementer needs. So the test suite
contains a reference verifier that uses only `json`, `hashlib`, and the raw
Ed25519 primitive — none of this repo's verification code — and must verify
real receipts (PROCEED, HOLD and RED_FLAG, with the verdict replayed), log
entries with their chain links, a log head and a delegation, using only what
the manifest says, and must reject tampered ones. While writing it the
manifest said only "re-run the verdict rules"; that was not enough to
implement, so the weights and the decision rule were added. If someone changes
the receipt format and forgets the manifest, this test fails.

**Only the operator is named.** The operator is the entity name
(`30E Ventures`, overridable for a self-hosting operator via
`DILIGENCEOS_OPERATOR_NAME`); no person, no contact address. A test asserts
the served bytes contain none of the identifiers the brand-separation and
public-identity rules forbid.

**Path.** `/v1/manifest`, deliberately not `/.well-known/...`. Publishing at a
well-known location is a statement to the wider ecosystem, and whether to make
it — and in what format — is an explicit owner decision that has not been
made. Adding an alias later is one line.

**Limits, stated.** The manifest proves nothing to someone who hasn't pinned
the issuer key; it lets a holder of the key detect tampering and tells them
how to verify. No key rotation or manifest history. Schemas are prose plus
identifiers rather than JSON Schema files. It describes the format that
exists; it does not certify that a given operator's deployment is honest —
that is what witnesses are for.

## 2026-10-02 — The log is served in bounded pages; the witness follows them; a non-loopback bind warns about TLS

From the external audit's hardening list (D1). `GET /v1/log/entries` returned
the whole log in one response, so every request cost O(log) and the cost grew
with use.

**Pagination.** `?after_seq=N&limit=M`. `seq` is the entry's position, so the
cursor is stable while the log grows (nothing shifts under a client). Default
100, maximum 500; a `limit` outside 1..500, or a malformed, repeated, signed or
unknown parameter, is a `400 invalid_request` naming the field. Over-max is
rejected rather than clamped so a client never silently gets less than it asked
for. A cursor at or past the end is an empty last page, not an error. The
response adds `length`, `has_more` and `next_after_seq`; `head_hash` stays the
head of the whole log. Both page constants live in `api.py` and the signed
manifest's `limits` reads them from there (a test asserts they agree).
`/v1/log/head`, `/verify` and `/lookup` are unchanged. To carry the query string,
`api.handle` gained an optional `query` argument (default empty).

**The witness.** It follows pages until it holds as many entries as the *signed
head* says the log has, then checks them exactly as before. The head, not the
server's `has_more`, decides when to stop, so a lying server cannot loop it and a
server that stops early or drops entries yields a short list that
`check_consistency` refuses (exit 3). Entries beyond the signed length (the log
grew mid-download) are ignored; the witness cosigns the head it was shown. A
page that is malformed or does not continue at the right `seq` is now an exit 3
rather than an exception. The first request is the bare path, so a witness still
works against a server that predates pagination and returns everything at once.
The cost is deliberate: verifying a long log takes more requests; the check is
no weaker.

**TLS.** Not added to `wsgiref`; that is a deployment concern. `webapp.tls_warning`
(pure, unit-tested) returns a warning when the bind host is not loopback
(`127.0.0.0/8`, `::1`, `localhost`) and `DILIGENCEOS_BEHIND_TLS_PROXY` is not
exactly `1`; `serve()` prints it to stderr. It warns and does not refuse to start
(a refusal would just push people to set the flag without reading it), and the
flag is an acknowledgement the server cannot verify. README now states the
requirement.

## 2026-10-02 — Say plainly that signed receipt fields are not sanitized

From the external audit (D3). `subject.name` and `subject.registration_id` come
from the caller and go into the signed receipt unchanged, and finding details
quote them; revocation `reason` text is likewise caller-supplied. "Signed" is not
"sanitized": a hostile string is faithfully signed, and an LLM agent reading the
receipt may follow it as an instruction.

This is not fixable in the data model — a receipt that rewrote what it was
given would not be a faithful record, and changing the bytes would change what is
signed. So the fix is to be honest about it where a consumer looks. A single
notice and field list live in `receipt.py` (`UNSANITIZED_NOTICE`,
`CALLER_SUPPLIED_FIELDS`); `/v1/capabilities` serves them as `untrusted_fields`
and the signed manifest repeats them under `documents.receipt.untrusted_fields`,
so a consumer verifying via the manifest gets the statement from a pinned key. A
test asserts the two agree and a second that hostile text really is signed
verbatim, so the claim cannot go stale. README has a section on it. The web
front end already HTML-escapes these values; nothing about issuance changed.

## 2026-10-07 — A log cannot witness itself

An external audit ran a check and found that a cosignature whose `witness` equals
the log's own `issuer` verified True, was accepted by `POST /v1/log/cosign` when
the issuer key was listed in `DILIGENCEOS_WITNESSES`, and was then published in the
head's `cosignatures[]`. The operator holds that key, so such a "witness" attests
nothing: it defeats the reason for an external witness. Reproduced first
(`verify_cosignature` returned True; the cosign endpoint answered 200), then fixed.

Refused wherever one is accepted: `verify_cosignature` is False when `witness ==
issuer`; `cosign_head` and `run_witness` raise `SelfWitnessError` (a `ValueError`,
so the `witness` CLI exits 2 with `error: ...`); `Store.add_cosignature` raises it
before anything else, and the endpoint answers `403 forbidden`, field `witness`,
with a message saying why (no new error code). Ignored wherever counted: a
self-cosignature already in a persisted store is filtered out of `cosignatures_for`
(so out of `GET /v1/log/head`), and the manifest's `witnesses[]` omits the issuer.
Configuration: `webapp.serve()` calls `check_witness_config` and refuses to start,
naming `DILIGENCEOS_WITNESSES`, rather than silently dropping the entry. The
per-request paths (manifest, cosign) additionally never honour the issuer, in case
the environment changes after start-up. Legitimate third-party witnesses are
unaffected. This does not make a witness independent in any deeper sense (a second
key held by the same operator still passes); it removes only the case the code can
detect. Tests: `tests/test_witness_independence.py`.

## 2026-10-07 — decide() denies a receipt whose transaction is not real money

Found by the conformance corpus (`conformance/diligenceos-1.json`, `decide` set).
`decide()` read `receipt["transaction"]` without checking it. A receipt signed by an
issuer the *caller* trusts (`/v1/decide` takes the caller's own trust list) could
carry `{"amount_minor": -5, ...}`, a float, `true` or a string: negative and float
amounts compared as "within the cap" and were ALLOWed, a string or a list raised
`TypeError`/`KeyError` (a 500), and a lowercase or NUL currency merely escalated.
A negative amount would also have been committed against a budget by `/v1/spend`
had the issuer been trusted there. Operator-issued receipts were never affected
(`/v1/verdict` validates the transaction), which is why this stayed unseen.
Fix: a present transaction must parse as `Money` (integer `amount_minor >= 0`,
three-letter uppercase ASCII currency) or the decision is DENY, "receipt carries a
malformed transaction". A *missing* transaction still ESCALATEs. Nothing else in
`decide()` changed.

## 2026-10-07 — verify_chain refuses a log that is not a list, and a seq that is not an int

Found by the conformance corpus. `receipt_log.verify_chain` iterated whatever it
was given: `{}`, `""` and `()` looked like a valid empty log, and a number, `None` or
`true` raised `TypeError`. And `entry.get("seq") != i` let `false` stand for 0 and
`true` for 1 (`False == 0` in Python), so a self-consistent forged chain with boolean
seqs verified, where a verifier in any other language would refuse it. Now: a
non-list is the single error "entries must be a list", and `seq` must be exactly an
`int`. Real logs and the witness (which already checked for a list) are unaffected.
