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

## Later (not started, not scoped)

Phase 1 (real data licensing, liability posture, SMB customers) and beyond —
see the private roadmap doc.
