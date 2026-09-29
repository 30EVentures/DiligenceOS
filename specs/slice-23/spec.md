# Slice 23 — Append-only receipt log

## Goal

A receipt proves what the issuer *says*. It doesn't stop an issuer from
saying something different tomorrow about the same facts. An append-only,
hash-chained log of every receipt issued makes that visible: entries can't
be edited, reordered or removed without breaking the chain, and issuing a
different outcome for identical inputs is recorded as a permanent,
un-removable conflict.

## Included

- `diligenceos/receipt_log.py`:
  - Entry: `seq`, `receipt_id`, `inputs_digest`, `outcome_digest` (digest of
    verdict, score, findings and rules), `logged_at`, `conflict_with`
    (`seq` of the first entry with the same `inputs_digest` but a different
    outcome, else `null`), `prev_hash`, `entry_hash`. The genesis
    `prev_hash` is `sha256:` + 64 zeros.
  - `verify_chain(entries, *, expected_head=None) -> list[str]` — pure,
    offline. Reports a wrong `seq`, a broken `prev_hash` link, an
    `entry_hash` that doesn't match the contents, and (when the caller
    remembers a head it saw earlier) a head that doesn't match — the only
    way to detect a dropped tail.
  - `ReceiptLog(path=None)`: in-memory, or a JSON-lines file opened for
    append. Loads and verifies on open and raises `LogCorruptError` rather
    than appending to a broken chain (fail closed). `append(receipt, *,
    now=None)` is idempotent per receipt id. `head`, `entries`, `lookup`,
    `conflicts`, `verify()`.
  - `Store.log` (lazy): `receipts.jsonl` beside the store file, or in memory
    when the store has no persist path.
- `POST /v1/verdict` logs every receipt it issues and adds response headers
  `X-DiligenceOS-Log-Seq`, `X-DiligenceOS-Log-Entry-Hash` and, on a
  conflict, `X-DiligenceOS-Log-Conflict`. The receipt body is unchanged (an
  extra field would break its own id).
- API: `GET /v1/log/head`, `GET /v1/log/entries`, `POST /v1/log/lookup
  {receipt_id}`, `GET /v1/log/verify` (server self-check), `GET
  /v1/log/conflicts`. A corrupt log answers `503 log_unavailable` and stops
  issuing receipts.
- Capabilities document updated; tests for each piece.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. `verify_chain` passes an honest log and fails each of: an edited entry, a
   recomputed-but-relinked entry, a removed middle entry, reordered
   entries, and (with `expected_head`) a truncated tail.
3. Two receipts for identical inputs but different outcomes: the second
   entry carries `conflict_with`, and `/v1/log/conflicts` lists it.
4. The same receipt logged twice yields one entry.
5. A restarted server reopens the same log and continues the chain; a
   hand-edited log file makes `/v1/verdict` return `503`.
6. Verified live with `curl`.

## Not in this slice

- **A log the issuer controls proves nothing to an outsider on its own.**
  It makes the issuer's history checkable *by anyone who remembers an
  earlier head* (or anchors it elsewhere); until heads are signed and
  published/witnessed (Slice 21 and later) the operator can still rewrite
  the whole file. This is tamper-evidence against accident and lazy
  tampering, not against the operator.
- Chain, not Merkle tree: no logarithmic inclusion proofs; `entries`
  returns everything (fine at this size).
- Revocations and spend commits are not yet logged.
- Same `inputs_digest` with a different outcome is expected only when
  rules or engine changed, or something is wrong; the log flags it, it
  doesn't decide which.
