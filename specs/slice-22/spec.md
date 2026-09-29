# Slice 22 — Freshness, revocation, and spend that accumulates

## Goal

A receipt that never goes stale, can't be withdrawn, and can be presented
again and again is a bearer token in disguise. Three gaps, closed together
because they all answer "is this receipt still good to act on, right now?":

1. **Freshness** — issued receipts expire by default.
2. **Revocation** — the issuer can withdraw a receipt; verifiers can see it.
3. **Cumulative spend** — a policy cap is a budget, not a per-call check:
   ten sub-cap payments must not add up past it, and presenting the same
   receipt twice must not spend twice.

## Included

- `receipt.issue_receipt(..., ttl_seconds=None)` sets `expires = issued_at +
  ttl` when the result has none. The API issues with a default TTL of 24h
  (`DILIGENCEOS_RECEIPT_TTL_SECONDS` overrides).
- `verify_receipt(..., revocations=None)`; `ReceiptCheck` gains `revoked`
  and `revoked_reason`. A revoked receipt is still internally valid
  (integrity is a separate question from standing).
- `policy.decide(..., revocations=None)`: revoked -> DENY.
  `gate.release_if_allowed(..., revocations=None)` passes it through.
- `Store` holds `revocations` (`receipt id -> {reason, revoked_at}`) and a
  spend ledger (`budget_id -> receipt id -> Money`), both persisted in the
  same file. `to_dict()` (the checks' data, and what `data_digest` covers)
  is unchanged: revoking must not alter what a verdict was issued against.
- `spend.try_spend(store, budget_id, receipt, policy, *, now, sources)`:
  runs `decide`; on ALLOW, commits to the budget only if cumulative spend
  stays within the cap, else ESCALATE ("cumulative spend would exceed the
  cap"). **Idempotent by receipt id**: re-presenting a committed receipt
  returns ALLOW with `already_committed` and does not spend again.
- API: `POST /v1/revoke {receipt_id, reason}`, `GET /v1/revocations`,
  `POST /v1/spend {budget_id, receipt, policy | policy_chain, sources?}` ->
  `{decision, reasons, spent_minor, remaining_minor, already_committed,
  effective_policy}`. `/v1/verify` and `/v1/decide` consult revocations;
  verify reports `revoked`.
- Capabilities document updated. Tests for each piece.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. `/v1/verdict` receipts carry an `expires` 24h after `issued_at`; an
   expired one is reported expired and decides ESCALATE.
3. After `/v1/revoke`, `/v1/verify` says `revoked: true` and `/v1/decide`
   and the gate DENY, and this survives a server restart.
4. Two receipts of 60 and 60 against a cap of 100 in one budget: the first
   is ALLOW, the second ESCALATE; a re-sent first receipt is ALLOW without
   spending again; a different budget is unaffected.
5. Verified live with `curl`.

## Not in this slice

- **No authentication on `/v1/revoke` or `/v1/spend`.** Anyone who can
  reach the server can revoke or spend; fine on localhost, not beyond it.
  Who may revoke is an authority question for the signed-receipt slice.
- Revocation is by receipt id only (no revoke-by-subject), and does not
  claw back spend already committed.
- The budget id is caller-chosen and unauthenticated; budgets don't reset
  on a schedule. Single-threaded server, so no concurrent-write handling.
