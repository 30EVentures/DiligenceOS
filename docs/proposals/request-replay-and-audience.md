# Proposal: nonces that survive a restart, and an audience in the signed request

Status: **proposal only, no code.** It changes what a valid signed request is, so
it waits for the owner's go-ahead. Audit item: `mine-diligenceos.md` §10 item 6.

## The problem (two parts, both reproduced against `main` at 4205487)

**1. The nonce cache is lost on restart.** `Store._nonces` is an in-memory dict
and is not part of `_state_dict()`. A request accepted just before a restart can
be replayed just after it, as long as it is still inside the ±300 s skew window.
Reproduced: `remember_nonce("abc123", ...)` returns "seen" in the same process and
"fresh" in a new `Store` loaded from the same file.

**2. The signed message has no audience.** `auth._message` covers
`{path, body, issued_at, nonce}`. Nothing says which server it is for.

### How bad is each, honestly

- Replay across a restart only matters for a request that is worth replaying.
  Both authenticated endpoints are idempotent (`/v1/revoke` keeps the first
  reason; `/v1/spend` is idempotent per receipt id), which limits the damage to
  replaying a spend or revocation the caller really did sign. Real, narrow.
- Cross-deployment replay needs two servers that accept the same chain. The root
  of trust is the server's own issuer key, so this requires two deployments
  sharing an `issuer.key` (staging cloned from production, a restored backup).
  With distinct keys it cannot happen. Worth closing because the failure is silent
  and key reuse across environments is common, not because it is open today.

## Options: nonces

1. **Persist nonces** to a small append-only file beside `store.json`, pruned to
   the window on load. Exact. Cost: one small write per authenticated request.
2. **Start-time floor, no storage:** reject any request whose `issued_at` is
   earlier than this process's start time. Every request signed before a restart
   is then refused, which is precisely the set that could have been seen. Cost: a
   client whose clock runs behind the server's by up to 300 s is rejected for a
   few minutes after each restart (it retries with a fresh nonce; it only
   succeeds once its own clock passes the floor).

## Options: audience

Add the server's issuer id to the signed message and bump the domain to
`diligenceos.request/2`; `sign_request` takes an `audience` (the CLI gains
`--audience`, or fetches `/v1/issuer`). The signed manifest (`documents.request`)
and the reference verifier in `tests/test_manifest.py` change with it. Accepting
`/1` alongside `/2` keeps the hole open, so either hard-cut (there are no outside
callers today) or accept `/1` only until a stated date.

## Recommendation

Persist nonces (option 1) if a small write per request is acceptable; the
start-time floor if storage should stay out of the request path. Add the audience
with a hard cut to `/2`. The audience change is the larger one: it breaks every
existing signed-request client, and the owner should confirm no pilot caller
exists first.

## Decisions needed from the owner

- Option 1 or 2 for nonces?
- Hard cut to `request/2`, or a dated overlap?
- Audience = issuer id only, or issuer id plus host/URL? (Host binds to a
  deployment but not to a key, so the issuer id is the sturdier choice.)

## Test plan (when approved)

The reproduction above; a replay-after-restart case; a request signed for another
audience refused; manifest and reference-verifier updated and the sufficiency test
still green.
