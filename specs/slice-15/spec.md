# Slice 15 — Verdict receipt

## Goal

A verdict an agent can act on has to be checkable by someone who does not
trust the server that issued it. A receipt is one self-contained JSON
document: the verdict, the findings behind it, a digest of the inputs, and a
content-hash id. Anyone can re-verify it offline, in any language, from the
document alone.

## Included

- `diligenceos/receipt.py`:
  - `SCHEMA = "diligenceos.receipt/1"`, `RULES = "verdict-rules/1"` (names
    the assembly rules a verifier must replay).
  - `canonical_json(obj) -> bytes` — sorted keys, no whitespace, UTF-8. The
    one serialization every digest is computed over.
  - `digest(obj) -> str` — `"sha256:<hex>"` of `canonical_json(obj)`.
  - `issue_receipt(*, subject, inputs, result, issued_at=None) -> dict` —
    body fields: `schema`, `rules`, `subject`, `inputs_digest`, `verdict`,
    `trust_score`, `findings`, `issued_at`, `expires`; plus `id`, the digest
    of the body without `id`. `issued_at` is injectable for determinism;
    default is now, UTC, ISO-8601 seconds.
  - `verify_receipt(receipt, *, now=None) -> ReceiptCheck` with `valid`,
    `expired`, `errors`. Checks: schema and rules known; `id` matches the
    recomputed digest; verdict and trust score match what `assemble_verdict`
    produces from the receipt's own findings; if `expires` is set and `now`
    is given, whether it has passed. Never raises on a malformed receipt —
    returns `valid=False` with the reason.
- `serialize.py`: `finding_from_dict` (inverse of `finding_to_dict`).
- `tests/test_receipt.py`.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. A freshly issued receipt verifies.
3. Changing any field (verdict, a finding, the score, the subject) makes
   `verify_receipt` fail; so does changing a field and recomputing only the
   `id` (the verdict/score replay catches a forged-but-self-consistent id).
4. Two issues of the same inputs at the same `issued_at` are byte-identical.
5. Malformed input returns `valid=False`, not an exception.

## Not in this slice

- **Not signed.** The id proves the document wasn't altered after issue only
  to someone who already trusts the id they were handed. It does not prove
  who issued it. Signatures need a real crypto dependency (stdlib has no
  asymmetric signing) — a deliberate later slice, recorded in decisions.md.
- The receipt does not embed the raw inputs, only their digest.
- No revocation and no log; `expires` is advisory until freshness is built.
