# Slice 21 — Signed receipts

## Goal

Until now a receipt proved only that it hadn't been altered after issue. It
said nothing about *who* issued it. This slice gives the issuer an Ed25519
identity and signs what it issues, so a stranger holding a receipt and the
issuer's public key can verify — offline — that this issuer stands behind
exactly this document, and can refuse receipts from issuers they don't
trust. It is also DiligenceOS's first third-party dependency.

## Dependency (owner-approved 2026-09-29)

`cryptography==50.0.1` (plus its pinned transitive deps `cffi==2.1.1`,
`pycparser==3.0`) in `requirements.txt`. Why this and not hand-rolled
Ed25519 or HMAC: see `docs/decisions.md`. `CLAUDE.md` gains a venv setup
step; the server and tests now run from `.venv`.

## Included

- `diligenceos/signing.py`:
  - `Signer` — an Ed25519 key. `issuer_id` is `ed25519:<64 hex>` of the
    public key (self-certifying: the id *is* the key). `sign(domain,
    message)` returns `ed25519:<128 hex>` over `domain + "\n" + message`;
    domains stop a signature made for one purpose being replayed for
    another (`diligenceos.receipt/1`, `diligenceos.log-head/1`).
  - `Signer.load_or_create(path)` — key file written mode `0600`, outside
    the repo; a malformed file raises `SignerError` (never silently
    replaced — that would change the issuer's identity).
  - `verify_signature(issuer_id, domain, message, signature) -> bool` —
    pure, never raises.
- `issue_receipt(..., signer=None)` — body gains `issuer` (sealed by the id;
  `null` if unsigned); a signed receipt also carries `signature` over its
  `id`. The id excludes `signature`.
- `verify_receipt(..., trusted_issuers=None)` — `ReceiptCheck` gains
  `signed`, `issuer`, `trusted` (`None` if no trust list was given). A bad
  signature, or an `issuer` with no signature, is an integrity error.
  **Untrusted is not invalid**: a validly signed receipt from an unknown
  issuer stays `valid` but `trusted=False`.
- `decide(..., trusted_issuers=None)`, `release_if_allowed(...)`,
  `try_spend(...)` — when given a trust list, a receipt not validly signed
  by a listed issuer is DENY.
- `Store.signer` (lazy): `issuer.key` beside the store file; an ephemeral
  in-memory key when the store has no path.
- API: `POST /v1/verdict` signs. `GET /v1/issuer`. `GET /v1/log/head` is
  signed (`issuer`, `signature` over `<length>:<head_hash>`), so heads can
  be witnessed. `/v1/verify`, `/v1/decide`, `/v1/spend` accept optional
  `trusted_issuers: [..]` and default to the server's own issuer.
  `503 signer_unavailable` when the key file is unusable.
- Tests: `tests/test_signing.py`.

## Done when

1. From the venv, `python -m unittest discover -s tests -v` reports `OK`.
2. A signed receipt verifies; changing any field fails (id); changing a
   field *and* re-sealing the id fails (signature); signing with a
   different key verifies as signed but is untrusted and decides DENY.
3. A signed log head verifies offline and fails if `length` or the hash is
   changed.
4. The key file is mode 0600, survives restart with the same `issuer_id`,
   and a corrupted key file yields 503, not a new identity.
5. Verified live with `curl`.

## Not in this slice

- **Trust is pinned by the verifier, never discovered.** `/v1/issuer` and
  the `issuer` field are claims; a verifier must already hold the
  issuer's key from somewhere it trusts. No key directory, no rotation, no
  revocation of keys, no expiry on keys.
- `/v1/revoke` and `/v1/spend` are **still unauthenticated**: who is
  *calling* is a caller-identity question (delegated agent credentials),
  not an issuer-signature one. Next slice.
- Revocation entries and log entries themselves are not signed (only the
  head is). No key storage in an HSM/keychain; a plain 0600 file.
