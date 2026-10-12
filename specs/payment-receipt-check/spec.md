# A payer's check: is there a fresh, unrevoked PROCEED receipt for this counterparty?

## Goal

Let a payer (a wallet policy service, an agent's spend gate) require a DiligenceOS
receipt for a counterparty before a large transfer, and get back ALLOW / ESCALATE /
DENY with one closed reason code. A library function only: no endpoint, no new
document format, no keys, no funds. Used with testnet and mocks until the owner says
otherwise.

```
verify_receipt_for_payment(receipt, counterparty, amount_minor, asset_ref, max_age, *,
                           now, trusted_issuers, revocations, policy, assets) -> PaymentDecision
```

- `counterparty`: `{"name": str, "registration_id": str}`, from the payer's own records.
- `amount_minor`: the transfer, as an `int`, in the minor units of the receipt's
  currency. The **caller converts** (a 6-decimal USDT transfer is not USD cents);
  this function never guesses a conversion.
- `asset_ref`: an opaque string naming the exact asset (for example chain + contract).
  `assets` maps each asset_ref the payer accepts to the currency code its
  `amount_minor` is expressed in. An asset not in the map is refused, so a token with
  the same symbol and a different contract cannot pass.
- `max_age`: seconds, an `int`; a receipt older than that is stale even if it has not
  expired.
- `now`: ISO-8601 with a timezone, **required**. No default and no `Date.now()`
  equivalent: a verifier that reads the clock itself cannot be replayed or tested.
- `trusted_issuers`: the issuer ids the payer pinned. Required, non-empty.
- `revocations`: the payer's view of the revocation set (mapping id -> entry), or
  `None` if it could not be read. `None` fails closed; `{}` means "nothing revoked".
- `policy`: the payer's `Policy` (cap, acceptable verdicts, trust floor).

## Rules (first failing DENY wins; ESCALATE only if there is no DENY)

DENY (integrity, identity, freshness; a human cannot fix these by approving):
`MISSING_INPUT`, `BAD_PARAMETER`, `INTERNAL_ERROR` (anything unforeseen), `RECEIPT_INVALID`, `ISSUER_UNTRUSTED`,
`REVOCATIONS_UNAVAILABLE`, `REVOKED`, `CLOCK_UNREADABLE`, `NO_EXPIRY`, `EXPIRED`,
`STALE`, `FUTURE_DATED`, `RED_FLAG`, `NO_TRANSACTION`, `COUNTERPARTY_UNIDENTIFIED`,
`SUBJECT_MISMATCH`, `ASSET_UNKNOWN`, `CURRENCY_MISMATCH`, `AMOUNT_MISMATCH`.

ESCALATE (policy limits, same meaning as `decide()`; a human may approve):
`VERDICT_NOT_ACCEPTABLE`, `SCORE_BELOW_FLOOR`, `OVER_CAP`.

ALLOW: `OK`.

Exactness: the receipt must name this counterparty (name **and** registration id,
byte-for-byte, no normalisation) and this exact amount in this currency. A receipt is
a verdict on one transaction; a smaller or larger transfer needs its own.

## What it does not do (stated so it is not assumed)

- It does not bind a destination address or chain to the subject. A receipt names a
  subject and an amount, not an account. The payer must hold the counterparty to
  address mapping itself (a payee allowlist). The `spend-auth` proposal in
  `docs/design/proceed-gate-and-mcp.md` is the fix and is not built.
- It does not consume the receipt. Using the same receipt for two payments is the
  caller's atomic spent-set to prevent.
- It does not fetch revocations or check the freshness of the caller's revocation
  view; it is only as current as the set it is given. `revocations_for_payment(store)`
  reads a store's revocations and returns `None` (fail closed) if the signed log
  cannot be read.
- No existing endpoint, document, manifest or receipt format changes.

## Done when

- [x] Tests written first and seen failing, including: expired receipt; revoked
      receipt after a restart (also when only the log, not the saved index, has the
      revocation); amount above the policy cap; receipt for a different subject; an
      injection string in the subject name stays data.
- [x] Every DENY and ESCALATE code is reached by at least one test; the result never
      echoes receipt or caller text, only a closed code and the receipt id.
- [x] The function never raises on hostile input (fuzz over wrong types).
- [x] Agrees with `decide()` wherever both apply.
- [x] Full suite passes.
