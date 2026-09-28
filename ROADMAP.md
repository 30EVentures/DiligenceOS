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
- [ ] Slice 4 — identity/legitimacy check against a free registry lookup
- [ ] Slice 5 — combine checks into one verdict (`PROCEED`/`HOLD`/`RED_FLAG`)
      with a trust score
- [ ] Slice 6 — evidence discipline: every `Finding` carries a re-checkable
      citation, not a bare claim (DiligenceOS's own implementation — see
      `CLAUDE.md` Boundaries on why this isn't shared code with anything else)
- [ ] Slice 7 — track record: a self-hosted ledger of past verdicts a
      counterparty can be scored against
- [ ] Slice 8 — document red-flag scan on a supplied contract/terms file
- [ ] Slice 9 — glue: one command runs a subject + transaction through all
      checks and returns a verdict
- [ ] Slice 10 — demo: a verdict actually gates a release (small, local,
      illustrative — not a real payment rail)

**Milestone done when:** one real use case works end to end, with 3–5 real
pilot users, on free/cheap data only.

## Later (not started, not scoped)

Phase 1 (real data licensing, liability posture, SMB customers) and beyond —
see the private roadmap doc.
