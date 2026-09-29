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
