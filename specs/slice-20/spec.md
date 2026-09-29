# Slice 20 — The gate consumes a decision

## Goal

`apply_verdict` (Slice 10) releases on a bare `PROCEED`: it ignores the
amount, the policy, whether the receipt is genuine, and whether it was even
issued for this deal. Track A built all of those checks; the release path
must not be able to skip them. `release_if_allowed` makes the gate compute
the decision itself from a receipt and a policy, and bind the receipt to
the exact subject and amount held.

## Included

- `gate.release_if_allowed(gate, receipt, policy, *, now=None, sources=None)
  -> GateOutcome` with `gate` and `decision`:
  - Runs `policy.decide` on the receipt.
  - **Binding:** even an otherwise-ALLOW receipt is refused (DENY) if its
    `subject.name` differs from `gate.subject` or its `transaction` differs
    from `gate.held` (amount or currency). A genuine receipt for a
    different deal must not release this one.
  - Releases only on ALLOW; ESCALATE and DENY leave the gate held. Release
    stays one-way; the input gate is never mutated.
- `apply_verdict` is kept for backward compatibility and its docstring now
  says it is demo-only and bypasses policy. Removing it is left to the owner.
- `tests/test_gate.py` extended.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. Clean receipt for the matching subject/amount within policy releases.
3. Each of these leaves the gate held: over-cap, HOLD verdict, forged
   receipt, RED_FLAG, wrong subject, wrong amount, wrong currency, expired.
4. The original gate object is never mutated.

## Not in this slice

- No money actually moves; still a local illustration, not a payment rail.
- No accumulation of spend across gates against a shared cap (Slice 22).
- Receipts remain unsigned, so "genuine" means internally consistent, not
  attributed to a trusted issuer (Slice 21).
