# Committed spends are signed entries in the log

Status: accepted by the owner 2026-11-20 and merged (it changes what the log holds and makes
`/v1/spend` depend on the log). Delegation issuance is *not* done here (see below).

## Goal

A spend commit lived only in `store.json`: anyone who can write that file but does not hold the issuer key
could zero a budget and spend it again. Revocations were moved into the signed log in Slice 26; spends get the
same treatment, because spend is money.

## Included

- `receipt_log.py`: `append_spend` (kind `spend`: budget_id, spent_receipt_id, amount_minor, currency, caller),
  `spend_entries()`; a hash-valid spend entry of the wrong shape is corruption (`LogCorruptError`).
- `store.py`: `commit_spend` appends to the log **first** and updates the index second; the first spend read in a
  process counts the union of the index and the log (can only add), so a crash between the two, or an edited
  `store.json`, cannot reopen a budget.
- `api.py`: `/v1/spend` answers 503 `log_unavailable` / `signer_unavailable` instead of guessing; capabilities say so.

## Not included, and why

- **Delegation issuance.** Delegations are minted offline by the `delegate` command; the server never sees the
  moment of issuance. Logging it needs either that command to append to a log a running server also appends to
  (two writers fork the chain, STATE.md P-7) or a new operator-only issuance endpoint (new authority surface).
  That is a design decision for the owner, not a build.
- Unlike revocations, spend does not fall back to the index alone when the log is unreadable: it refuses.

## Done when

- [x] A committed spend is a signed `spend` entry; a refused one and a repeat are not logged again.
- [x] Zeroing the index, or a crash between log and index, does not reopen the budget.
- [x] An unreadable log gives 503 and commits nothing; malformed spend entries are corruption.
- [x] An independent witness accepts a log that holds spends.
- [x] Mutation checks (no reconcile, no log append) fail the new tests. Full suite OK.
