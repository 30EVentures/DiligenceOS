# DiligenceOS — roadmap

Working, slice-level view. The full concept-to-Fortune-10 roadmap (data
licensing, liability posture, SOC 2, the Fortune-10 entry point) lives in a
private doc, not in this repo — ask the owner for the link. This file only
tracks the buildable slice of it: **Phase 0, prove the loop.**

## NOW — Phase 0: prove the loop

Wire a verdict engine to free/cheap data, demo a verdict actually gating a
release, on one real use case, with a few real pilot users. Nothing here is
ready for real regulatory or dollar stakes — that's Phase 1+, out of scope
for an unattended slice loop.

- [x] Slice 1 — repo skeleton + test harness
- [x] Slice 2 — core types: `Verdict`, `Finding`, `VerdictResult`
- [x] Slice 3 — first check: sanctions/watchlist screening, exact + alias
      matching against a local fixture list. **Deferred from this slice:**
      ingesting the real, published OFAC SDN list — its own item below.
- [x] Slice 3b — real OFAC SDN ingestion: parses the real SDN.CSV column
      format + best-effort a.k.a. extraction. `fetch_sdn_list()` exists for
      a human to run; deliberately not exercised by the test suite (network)
- [x] Slice 4 — identity/legitimacy check, against an injected
      `RegistryLookup` (no real Companies House/OpenCorporates client yet)
- [x] Slice 5 — verdict assembly: sanctions flag always wins as `RED_FLAG`,
      any other flag is `HOLD`, trust score docked per flag and clamped
- [x] Slice 6 — evidence discipline: `verify_citation` + `require_citable`,
      DiligenceOS's own implementation (see `CLAUDE.md` Boundaries on why
      this isn't shared code with anything else). Not yet wired into
      `assemble_verdict` — a deliberate open call, see the slice spec.
- [x] Slice 7 — track record: in-memory `Ledger` of `DeliveryRecord`s,
      flags when the late ratio exceeds a threshold (no durable storage yet)
- [x] Slice 8 — document red-flag scan: keyword-presence check for required
      clause phrases, stated-limits (not clause-quality review)
- [x] Slice 9 — glue: `python3 -m diligenceos <request.json>` runs all
      checks and prints a verdict; `serialize.py` added now that a real
      caller (the CLI) needs a wire format
- [x] Slice 10 — demo: `apply_verdict()` gates an `EscrowGate` on the
      verdict (`PROCEED` releases, `HOLD`/`RED_FLAG` hold, release is
      one-way) — small, local, illustrative, not a real payment rail

**Phase 0 build complete (11/11, including 3b).** 66 tests passing. The
loop is provably real: `python3 -m diligenceos fixtures/golden/sample_request.json`
runs all four checks and prints a verdict; wiring that verdict into
`apply_verdict()` demonstrates the release-gating pattern end to end.

**Milestone still open:** none of this has been run by a real pilot user
yet. "One real use case works end to end, with 3–5 real pilot users, on
free/cheap data only" is a usage milestone, not a code milestone — it needs
a real person outside this loop trying it on a real (if low-stakes)
subject. That's the actual next step, not another slice.

## Frontend (added 2026-09-28, by request — outside Phase 0's original scope)

- [x] Slice 11 — a persistent local web front end. `python3 -m diligenceos`
      (no arguments) now starts it — the default way to use this repo going
      forward, not a one-off demo. Stdlib `wsgiref`, no new dependency; runs
      against the bundled sample dataset (see `docs/decisions.md`). The old
      batch mode (`python3 -m diligenceos <request.json>`) is unchanged.
- [x] Slice 12 — `/data` lists and adds sanctions entries, registry records,
      and delivery records through a shared `Store`; an addition is
      checkable through `/verdict` immediately, in the same running
      process. Still in-memory only — nothing survives a restart (see
      `docs/decisions.md`).
- [x] Slice 13 — `Store` is durable: `~/.diligenceos/store.json` by
      default (`DILIGENCEOS_DATA_PATH` to override), outside this repo
      entirely. Verified by hand: added a record, killed the server, started
      a fresh process, checked that record — still resolved correctly.

## North star (added 2026-09-29): infrastructure for the agentic internet

DiligenceOS is not a human product that also happens to have an API. The
caller is as likely an agent gating its own next action as a person reading
a page. Every slice from here is checked against four questions:

1. Does it work if the caller is an agent (structured in, structured out,
   stable error shapes, no screen-scraping)?
2. Is trust machine-verifiable — can a stranger re-check a verdict offline,
   without trusting this server?
3. Is money integer minor units, and does delegated authority only narrow,
   never widen?
4. Could it interoperate with neighbouring agent infrastructure (open,
   versioned, schema'd documents rather than bespoke formats)?

## Track A — agent-native (in order; each slice is one PR)

- [x] Slice 14 — this roadmap + the decision log entry (docs only)
- [x] Slice 15 — verdict receipt: canonical JSON, input digest, content-hash
      id, and an offline `verify_receipt` that also recomputes the verdict
      from the findings. Tamper-evident; not yet signed (see spec).
- [x] Slice 16 — machine API: `POST /v1/verdict`, `POST /v1/verify`,
      `GET /v1/capabilities`, structured errors. Same server, same store.
- [x] Slice 17 — evidence wired in: findings carry re-checkable evidence
      (quote + source digest); assembly refuses uncited flags except for
      explicitly exempted categories.
- [x] Slice 18 — money hygiene: `EscrowGate` moves from float to integer
      minor units; requests carry `amount_minor` + currency.
- [x] Slice 19 — authority that only narrows: a caller policy envelope
      (max amount, acceptable verdicts) and `narrow()`, checked against the
      receipt to yield an allow / escalate / deny decision.

**Track A, part 2 — proposed, not started (needs the owner's call where noted):**

- [x] Slice 20 — `EscrowGate` consumes a `Decision` (ALLOW releases;
      ESCALATE/DENY hold), so the release path can't bypass the policy.
- [ ] Slice 21 — signed receipts. Needs a deliberate, pinned crypto
      dependency (Ed25519) — **owner's call**, per `CLAUDE.md` Boundaries.
- [ ] Slice 22 — freshness and revocation: default `expires` on receipts,
      a revocation list a verifier can consult, spend accumulation against
      a policy cap across calls.
- [ ] Slice 23 — an append-only, hash-chained log of issued receipts, so an
      issuer can't quietly reissue a different verdict for the same inputs.
- [ ] Slice 24 — a discoverable capability manifest at a stable path, once
      the formats above have settled enough to publish.

## Later (not started, not scoped)

Phase 1 (real data licensing, liability posture, SMB customers) and beyond —
see the private roadmap doc.
