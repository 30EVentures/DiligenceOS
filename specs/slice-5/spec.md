# Slice 5 — Verdict assembly

## Goal

Turn a list of `Finding`s from however many checks ran into one
`VerdictResult` — the actual point of this whole project: one number, not a
report someone has to read and interpret themselves.

## Included

- `diligenceos/engine.py`:
  - `SANCTIONS_CATEGORY = "sanctions"` (imported from `diligenceos.sanctions.CATEGORY`,
    not restated as a bare string, so the two modules can't drift apart).
  - `assemble_verdict(findings, *, base_trust_score=85) -> VerdictResult`:
    - A flagged **sanctions** finding always produces `RED_FLAG`, regardless
      of anything else — this is the one category Phase 0 treats as a hard
      stop, not a matter of degree.
    - Any other flagged finding, with no sanctions flag, produces `HOLD`.
    - No flagged findings at all produces `PROCEED`.
    - `trust_score` starts at `base_trust_score`, loses 40 points for a
      flagged sanctions finding and 15 for every other flagged finding,
      clamped to `[0, 100]`. Stated as a simple, adjustable rule — not a
      claim that these weights are calibrated against real outcomes yet
      (Phase 2's job, per the roadmap).
- `tests/test_engine.py`.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. All-`PASS` findings assemble to `PROCEED` with `trust_score == base_trust_score`.
3. A flagged sanctions finding assembles to `RED_FLAG` even alongside other
   passing findings.
4. A flagged non-sanctions finding, no sanctions flag, assembles to `HOLD`.
5. `trust_score` never goes below 0 or above 100 regardless of how many
   findings are flagged.
6. An empty findings list assembles to `PROCEED` at `base_trust_score` —
   "nothing was checked" is not treated as "something was found".

## Not in this slice

- No weighting by finding severity beyond the flat sanctions/other split.
- No persistence — `assemble_verdict` is a pure function, in and out. The
  ledger (Slice 7) records verdicts; it doesn't compute them.
