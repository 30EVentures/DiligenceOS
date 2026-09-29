# Slice 26 — Signed log entries, revocations in the log, and a witness

## Goal

Slice 23 made the receipt log tamper-*evident* and Slice 21 signed its
head, but the operator who holds the file can still rewrite the whole chain
and re-sign a new head, and revocations lived in a plain JSON field that the
operator could quietly delete. This slice closes what can be closed without
outside infrastructure:

1. every log entry is individually signed by the issuer;
2. revocations are entries **in the log** (signed, append-only, attributed to
   the caller who made them), not a mutable side table;
3. an independent **witness** remembers the heads it has seen and refuses to
   countersign a history that isn't an extension of the last one — turning
   "the operator could rewrite history" into "the operator could not
   rewrite it without a witness noticing".

## Included

- `receipt_log.py`
  - New entries carry `kind` (`receipt` | `revocation`) and `issuer`
    (inside the hashed body) plus `signature` over `entry_hash`, domain
    `diligenceos.log-entry/1`. `signature` is excluded from `entry_hash`.
    Entries written before this slice (no `kind`/`issuer`/`signature`) still
    load and verify; they are receipt entries and simply unsigned.
  - `append_revocation(target_id, reason, revoked_by, signer=...)`.
  - `verify_chain(..., trusted_issuers=None, require_signed=False)` also
    checks each signature and, if given, that its issuer is trusted; a
    signature that doesn't verify is corruption (the log fails closed).
- `Store.revoke(receipt_id, reason, by=None)` appends a signed revocation
  entry first (fails closed if the log or key is unusable) and only then
  updates the index. The index gains `revoked_by` and `log_seq`.
  `GET /v1/revocations` returns the index **and** the signed log `entries`
  that back it, so a verifier can check them against a pinned issuer.
- `diligenceos/witness.py`
  - `check_consistency(previous, entries, head_doc, pinned_issuer)` — pure.
    Checks the head signature and issuer, the chain and entry signatures, that
    the head matches the entries, and that the log is an **append-only
    extension** of what this witness saw last (same hash at the same
    position; never shorter).
  - `cosign_head(...)` / `verify_cosignature(...)` — a witness's signature
    over `(issuer, length, head_hash)`, domain `diligenceos.log-cosign/1`.
  - `run_witness(fetch, state_path, signer, pinned_issuer, submit=None)` —
    one witnessing round; state only advances on success. A failure exits
    with the reason and **does not update state**.
- CLI: `python -m diligenceos witness --url U --issuer ID --key F --state F
  [--submit]`; exit `0` ok, `3` inconsistent history, `2` other error.
- API: `POST /v1/log/cosign` accepts a cosignature **only from witnesses the
  operator has listed** (`DILIGENCEOS_WITNESSES`, comma-separated ids;
  unset = none accepted) and only for a head that is really in the log;
  `GET /v1/log/head` includes the cosignatures for the current head.
- Tests in `tests/test_witness.py`; existing log/revocation tests updated.

## Done when

1. `.venv/bin/python -m unittest discover -s tests -v` reports `OK`.
2. Signed entries verify; editing any field or signature, swapping the
   issuer, or (with `require_signed`) an unsigned entry, is reported; old
   unsigned logs still load.
3. A revocation appears as a signed entry naming who made it, survives a
   restart, and `/v1/revoke` returns 503 (not a silent success) if the log
   can't be written.
4. A witness that has seen head N refuses: a log rewritten before N, a
   truncated log, a forged head, a head signed by another issuer — and it
   leaves its state untouched; it accepts a genuine extension and
   cosigns it.
5. The server stores a cosignature only from a listed witness for a real head.
6. Verified live: a real server, a real witness process, then a tampered log
   that the witness catches.

## Not in this slice

- **A witness only helps if it is run by someone other than the operator.**
  One process on the operator's machine proves the mechanism, not the
  independence; the value comes from a third party (or several) running it
  and keeping their state and cosignatures.
- No gossip between witnesses, no public transparency log, no timestamp
  authority: a witness that starts late can't vouch for history before it
  first looked.
- Delegation issuance is still not logged (only receipts and revocations).
- Revocation-by-delegate exists (scope `revoke`) but there is still no
  per-delegate revocation of *only their own* issuances.
- Key rotation for the issuer or witnesses.
