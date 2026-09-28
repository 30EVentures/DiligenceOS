# Decisions log

Dated, one entry per real decision. Not a changelog — the code and commit
history already say what changed; this says why, where "why" isn't obvious
from reading the diff.

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
