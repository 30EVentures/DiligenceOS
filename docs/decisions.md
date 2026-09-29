# Decisions log

Dated, one entry per real decision. Not a changelog — the code and commit
history already say what changed; this says why, where "why" isn't obvious
from reading the diff.

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
