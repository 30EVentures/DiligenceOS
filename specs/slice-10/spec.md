# Slice 10 — Demo: a verdict actually gates a release

## Goal

Close out Phase 0's own definition of done: a verdict doesn't just get
printed, it gates a release, illustrating the difference between "a report
someone reads and then releases the funds anyway" and "the verdict is the
release condition." Small, local, and explicitly illustrative — not a real
payment rail.

## Included

- `diligenceos/gate.py`:
  - `EscrowGate` — frozen dataclass: `subject: str`, `held_amount: float`,
    `released: bool = False`.
  - `apply_verdict(gate, verdict_result) -> EscrowGate` — returns a *new*
    gate (immutable, like everything else in this project so far).
    `PROCEED` releases it (`released=True`); `HOLD` and `RED_FLAG` leave it
    held. Once released, applying another verdict is a no-op — release is
    one-way, the same way a real escrow release would be; this function
    does not model reversal.
- `tests/test_gate.py`.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. A `PROCEED` verdict releases a held gate.
3. `HOLD` and `RED_FLAG` verdicts both leave the gate held, regardless of
   `trust_score`.
4. Applying a `PROCEED` verdict to an already-released gate is a no-op — it
   does not raise, and the gate that comes back is unchanged (`released`
   stays `True`, nothing about `held_amount` moves twice).

## Not in this slice

- No real money movement, no ledger, no persistence, no atomicity
  guarantees. This is a small, pure, in-memory illustration of "verdict
  gates release" — the actual hard infrastructure that pattern would need
  in production is a separate, later, and much bigger piece of work, not
  assumed to be free here.
- No integration with any real escrow or payment system.

This closes Phase 0. See `ROADMAP.md` for what "prove the loop" required
and what's genuinely still missing before Phase 1.
