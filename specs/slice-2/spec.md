# Slice 2 — Core types: `Verdict`, `Finding`, `VerdictResult`

## Goal

Give every later slice one shared vocabulary for what a check produces and
what a verdict looks like, before any check exists to produce one.

## Included

- `diligenceos/types.py`:
  - `Verdict` — an enum of exactly `PROCEED`, `HOLD`, `RED_FLAG`.
  - `CheckStatus` — an enum of exactly `PASS`, `FLAG` (what one check found).
  - `Finding` — a frozen dataclass: `category: str`, `status: CheckStatus`,
    `detail: str | None`, `evidence_url: str | None`. A `FLAG` finding must
    carry a `detail`; a bare flag with no explanation is refused at
    construction (`__post_init__`), because "flagged, no reason given" is
    the failure mode this whole project exists to prevent.
  - `VerdictResult` — a frozen dataclass: `verdict: Verdict`,
    `trust_score: int` (0–100 inclusive, validated), `findings: tuple[Finding, ...]`,
    `expires: str | None` (an ISO 8601 string; not parsed or validated as a
    real date yet — that's a later slice's job if it turns out to matter).
- `tests/test_types.py` covering: valid construction of each type, the
  `FLAG`-needs-`detail` rule, and the `trust_score` range check.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK` with the new
   tests included.
2. Constructing a `Finding(status=CheckStatus.FLAG, detail=None, ...)` raises
   `ValueError`.
3. Constructing a `VerdictResult(trust_score=101, ...)` or `-1` raises
   `ValueError`.
4. All four types are importable as `from diligenceos.types import Verdict,
   CheckStatus, Finding, VerdictResult`.

## Not in this slice

- No check produces a real `Finding` yet — Slice 3 does that.
- No verdict-assembly logic (turning several `Finding`s into one `Verdict`)
  — Slice 5.
- No serialization (JSON in/out) — added when something actually needs to
  cross a process boundary (an API, a CLI). Guessing the wire format now
  before there's a caller is exactly the kind of premature abstraction this
  project's own conventions warn against.
