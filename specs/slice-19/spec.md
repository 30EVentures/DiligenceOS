# Slice 19 — Authority that only narrows, and a decision

## Goal

An agent acting on someone's behalf holds delegated authority. That
authority must only ever shrink as it is passed down (a sub-agent can be
given less than its parent, never more), and a verdict receipt must be
turned into an explicit action decision against it: ALLOW, ESCALATE (a
human or a higher authority must look), or DENY.

## Included

- `diligenceos/policy.py`:
  - `Policy(max_amount: Money, acceptable_verdicts: frozenset[Verdict],
    min_trust_score: int)`. `RED_FLAG` can never be acceptable — rejected at
    construction. `to_dict()` / `Policy.from_dict()` (raises `ValueError`
    on malformed input, including float amounts).
  - `narrow(parent, child) -> Policy` — returns `child` if it is at least
    as restrictive on every axis (same currency; amount <=; verdicts a
    subset; trust score >=); raises `WideningError` naming the axis if not.
  - `effective_policy(chain) -> Policy` — folds a delegation chain,
    every link checked against the one before it.
  - `decide(receipt, policy, *, now=None, sources=None) -> Decision`
    (`outcome`, `reasons`):
    - DENY: receipt fails `verify_receipt`; or verdict is `RED_FLAG`.
    - ESCALATE: verdict not in `acceptable_verdicts` (e.g. `HOLD`); trust
      score below minimum; no transaction on the receipt; currency differs;
      amount over the cap; receipt expired. All failing reasons are listed.
    - ALLOW: only when nothing above applies.
- `POST /v1/decide` — `{"receipt", "policy" | "policy_chain": [..],
  "sources"?}` -> `{"decision", "reasons", "effective_policy"}`. A widening
  chain is `400 policy_widening` naming the link; a malformed policy is
  `400 invalid_request`. New error code listed in capabilities.
- `tests/test_policy.py`, extended `tests/test_api.py`.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. A child policy with a larger cap, extra verdict, lower trust floor or
   different currency is refused by `narrow`; an equal or tighter one is
   accepted; a chain is only as wide as its narrowest link on each axis.
3. A clean receipt within limits decides ALLOW; each limit breach alone
   decides ESCALATE with a reason; RED_FLAG and a forged receipt decide
   DENY regardless of policy.
4. Verified live through `/v1/verdict` -> `/v1/decide`.

## Not in this slice

- Policies are supplied by the caller in the request; nothing proves *who*
  issued a policy or a chain link (no signatures — same limit as receipts).
- `EscrowGate` still consumes a bare verdict; wiring it to a `Decision` is
  a follow-up.
- No amount-tiered rules, per-counterparty limits, expiry on a policy, or
  spend accumulation across calls.
