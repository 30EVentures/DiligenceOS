# Slice 24 — A discoverable, signed manifest

## Goal

Everything built in Track A is only useful to a stranger if they can find
out — from the service itself — *who* runs it, *which key* to pin, *what
documents* it issues and *exactly how to verify them*, well enough to write
their own verifier without reading this repo. `GET /v1/capabilities`
describes the endpoints; the manifest describes the trust surface, and is
itself signed so tampering in transit is detectable by anyone who has pinned
the issuer.

## Included

- `diligenceos/manifest.py`
  - `build_manifest(...)` — `diligenceos.manifest/1`: `operator` (name only),
    `issuer` (the id, marked as a claim to be pinned out of band), the API's
    `routes` with which are `authenticated`, and — for every signed or hashed
    document (receipt, delegation, request auth, log entry, log head,
    cosignature, this manifest) — its schema id, what its id/hash covers,
    what is signed and under which **domain string**. An `encoding` section
    states the canonical-JSON, digest and signature rules, and a `vectors`
    section gives a known-answer test for them. Also `limits` (body size,
    clock skew, chain depth, default TTL) and the configured `witnesses`.
    Every schema/domain/limit is read from the module that enforces it, so
    the manifest cannot drift from the code.
  - `sign_manifest(manifest, signer)` -> `{manifest, issuer, signature}`
    (signature over the manifest's digest, domain `diligenceos.manifest/1`).
  - `verify_manifest(doc, pinned_issuer=None)` -> list of errors.
- `GET /v1/manifest` (open, signed on each request; `generated_at` inside
  the signed body). `503 signer_unavailable` if the key is unusable.
- The operator name defaults to `30E Ventures`; `DILIGENCEOS_OPERATOR_NAME`
  overrides it. Nothing else about the operator is published.
- `tests/test_manifest.py`, including a **reference verifier written without
  importing any `diligenceos` code** (only `json`, `hashlib` and the Ed25519
  primitive) that verifies a real receipt, log entry and log head using only
  what the manifest says. If that test passes, the manifest is sufficient.

## Done when

1. `.venv/bin/python -m unittest discover -s tests -v` reports `OK`.
2. The manifest verifies against the pinned issuer; editing any field, or
   pinning a different issuer, fails.
3. The manifest's domains, schemas and limits equal the modules' constants.
4. The independent reference verifier verifies real documents from the
   manifest's rules alone, and rejects tampered ones.
5. The served manifest names the operator and no one else (no personal name
   or email).
6. Verified live with `curl`.

## Not in this slice

- **The path is `/v1/manifest`, not `/.well-known/...`.** A well-known
  location is a decision about publishing to the wider ecosystem; it is the
  owner's call and is left for a later, explicit request (an alias would be
  a one-liner).
- The manifest is a *claim by the issuer*, signed by the issuer. It proves
  nothing about the issuer to someone who hasn't pinned the key; it only lets
  someone who has pinned it detect tampering, and tells them how to verify.
- No key rotation or versioned manifest history.
- Schemas are described in prose and identifiers, not JSON Schema files.
