# Slice 25 — Caller identity: delegation that only narrows

## Goal

Slice 21 authenticated the *issuer*. It said nothing about the *caller*:
anyone who can reach the server can still revoke a receipt or spend a
budget. This slice makes both operator-only-by-default and delegable — with
credentials that can be passed down a chain but only ever narrowed, and
requests that prove possession of the caller's key so a copied credential
is not a bearer token.

## Included

- `diligenceos/delegation.py` — a signed **delegation**
  (`diligenceos.delegation/1`): `delegator` and `delegate` (Ed25519 issuer
  ids), `scopes` (`spend`, `revoke`), an optional `policy` (the Slice 19
  `Policy`), an optional `budget_id`, `issued_at`, a mandatory `expires`,
  and `parent` (the id of the delegation it extends). Its `id` seals the
  body; the delegator signs the id.
  - `issue_delegation(...)`, `extend_chain(...)`.
  - `verify_chain(chain, *, root_issuers, now, revocations)` — pure,
    offline, never raises. Checks: starts at a trusted root; each link's
    delegator is the previous delegate; ids and signatures; every link
    unexpired and not revoked; and **narrowing at every link**: scopes are
    a subset, `expires` is no later, a parent's `budget_id` is inherited
    unchanged, and if the parent has a `policy` the child must have one that
    `policy.narrow` accepts. Depth is capped (4).
- `diligenceos/auth.py` — `sign_request(signer, chain, path, body)` and
  `authenticate(...)`. A request carries an `auth` envelope
  (`signer`, `chain`, `issued_at`, `nonce`, `signature`); the signature
  covers the **path**, the **body without `auth`**, the time and the nonce,
  so a signed spend can't be replayed as a revoke, against another body, or
  later than ±5 minutes; a nonce is accepted once. An empty chain means the
  caller *is* the server's own issuer key (the operator).
- Enforcement: `POST /v1/revoke` requires scope `revoke`; `POST /v1/spend`
  requires `spend`. Missing/invalid auth is `401 unauthenticated`; valid auth
  without the scope, the wrong budget, or a request policy wider than the
  credential's is `403 forbidden`. For `spend`, a credential's own policy
  *is* the policy (a request policy is optional and may only narrow it); the
  caller is recorded on the spend entry. A delegation can be revoked through
  `/v1/revoke` (`delegation_id`) and stops working immediately.
- CLI: `python -m diligenceos keygen | delegate | sign-request` so a human or
  an agent can mint keys and credentials and sign requests without writing
  code. `delegate` refuses to create a widening child.
- Existing tests that call `/v1/revoke` and `/v1/spend` now sign as the
  operator; new `tests/test_authority.py`.

## Done when

1. `.venv/bin/python -m unittest discover -s tests -v` reports `OK`.
2. A chain operator -> A -> B verifies; every widening attempt (scope,
   expiry, cap, verdicts, trust floor, budget, dropping the policy) is
   refused; an expired, revoked, forged, mis-linked or foreign-rooted chain
   fails.
3. A request is rejected if the body, path, time, nonce or signer changed,
   if the leaf key doesn't match the credential, or if it is replayed.
4. Unauthenticated `/v1/revoke` and `/v1/spend` return 401; a `spend`-only
   credential cannot revoke (403); a budget-bound credential cannot spend
   from another budget (403).
5. Verified live with the CLI and `curl`: operator, delegate and
   sub-delegate flows, and revocation of a delegation.

## Not in this slice

- `/v1/decide`, `/v1/verify`, `/v1/verdict` and the read-only log and
  revocation lists stay open: they compute or expose no authority.
- Delegations are not logged and not revocable *by the delegator* (only via
  the operator's `/v1/revoke`); no per-delegate rate limits.
- The nonce cache is in memory: a restart inside the 5-minute window forgets
  it. Replays remain harmless for the two endpoints (both are idempotent).
- Caller keys are plain key files (`keygen`); no rotation or directory.
- Still unsigned: revocation entries and log entries (Slice 26).
