# DRAFT: signed requests that name their audience and survive a restart (request/2)

Status: drafted on branch `request-v2-draft`; **not for merge until the owner decides** the three
open choices in `docs/proposals/request-replay-and-audience.md` (see `docs/decisions.md`, 2026-11-18).

## Goal

A signed request should say which server and which authority it is for, and a replay must not work
after a restart.

## Included

- `auth.py`: domain `diligenceos.request/2`; the signature covers
  `{path, body, issued_at, nonce, audience, digest(chain)}`; the envelope carries `audience`.
- `api.py`: audience is the issuer id, or `DILIGENCEOS_AUDIENCE`.
- `store.py`: nonces persisted to `nonces.jsonl` before acceptance, pruned on load; unrecordable
  means refused.
- `tools.py`: `sign-request --audience` (required). Manifest, capabilities, README updated.

## Not included

The lone-surrogate 500 on authenticated routes (owner's decision); a dated overlap with `request/1`;
rewriting the reference verifier in `tests/test_manifest.py`.

## Done when

- [x] Wrong audience, missing audience, relabelled audience: refused; never raises.
- [x] A captured request re-presented with a wider chain: refused.
- [x] A nonce survives a restart; a damaged last line is tolerated; an unwritable file refuses.
- [x] Two deployments with one key are separated by `DILIGENCEOS_AUDIENCE`.
- [x] Mutation checks (no chain binding, no audience check, no persistence) fail the new tests.
- [x] Full suite `OK`; the known-failure corpus case is still a known failure.
