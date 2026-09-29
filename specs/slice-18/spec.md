# Slice 18 — Money in integer minor units

## Goal

A float can't represent most decimal amounts exactly and an agent moving
money can't afford "240000.00000000003". Money in DiligenceOS becomes an
integer count of minor units (cents, pence) plus a currency code — never a
float — and the request/receipt carry the transaction so a verdict is bound
to what it was issued for.

## Included

- `types.Money(amount_minor: int, currency: str)` — frozen; rejects
  floats and bools, negative amounts, and anything but a 3-letter uppercase
  currency code. `to_dict()` / `Money.from_dict()`.
- `gate.EscrowGate` now holds `held: Money` instead of `held_amount: float`.
  **This changes a tested API** (Slice 10's demo gate); `tests/test_gate.py`
  is updated to match. Nothing else in the repo used the field.
- `POST /v1/verdict` accepts an optional `transaction:
  {"amount_minor": int, "currency": "USD"}`; a float, bool, negative or
  malformed value is a `400 invalid_request` naming the field
  (`transaction.amount_minor` / `transaction.currency`).
- The receipt gains a `transaction` field (the object, or `null`), sealed
  under the id, and `inputs_digest` covers it.
- Capabilities document lists the field.
- `tests/test_money.py`; `test_gate.py`, `test_api.py`, `test_receipt.py`
  extended.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. `Money(240000.0, "USD")`, `Money(True, "USD")`, `Money(-1, "USD")`,
   `Money(5, "usd")` all raise.
3. An API request with `"amount_minor": 12.5` is rejected with the field
   named; `24000000` is accepted and echoed in the receipt.
4. Editing a receipt's `transaction` breaks verification.

## Not in this slice

- The verdict does not yet *depend* on the amount; it is carried and bound,
  not scored. What a caller may do with a given amount is Slice 19.
- No currency conversion, no ISO-4217 table (shape check only), no
  per-currency minor-unit exponent.
