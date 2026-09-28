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
- [ ] Slice 10 — demo: a verdict actually gates a release (small, local,
      illustrative — not a real payment rail)

**Milestone done when:** one real use case works end to end, with 3–5 real
pilot users, on free/cheap data only.

## Later (not started, not scoped)

Phase 1 (real data licensing, liability posture, SMB customers) and beyond —
see the private roadmap doc.
