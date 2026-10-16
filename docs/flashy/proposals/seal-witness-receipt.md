# Proposal: a witness receipt for sealed snapshots (not published)

Status: **proposal, unpublished.** Implemented in `diligenceos/flashy/seal_witness.py`; nothing here is served or sent anywhere.

## What it is
A signed receipt that DiligenceOS checked a store of another product's sealed snapshots and counted what was in them. It is a smaller claim than the producer's own verifier on purpose, and it says so inside the receipt.

## Schema `diligenceos.flashy-seal-witness-receipt/1` (closed; signed with the DiligenceOS issuer key, domain = the schema string)
| Field | Type | Meaning |
|---|---|---|
| `schema` | string | exactly the schema name above |
| `statement` | string | fixed text: integrity and contents only; not truth, not the producer's clock, not value correctness; approves nothing |
| `approves_spend` | `false` | always false; a receipt with anything else does not verify |
| `witness_spend_envelope_base_units` | `"0"` | DiligenceOS holds no spending authority |
| `seal_key_ids` | [64 hex] | the producer keys (SHA-256 of the SPKI) the seals were made with, all of which the caller pinned |
| `seal_count` | int | seals in the store, all verified |
| `datapoints_by_kind` | {kind: int} | counts per fixed kind name (`price change headline sentiment futures cross`) |
| `sources_total`, `omitted_total` | int | counts |
| `earliest_sealed_at`, `latest_sealed_at` | int (epoch ms) | the producers' claims, not a trusted clock |
| `store_digest` | `sha256:` | digest of the sorted list of seal payload hashes (order-independent) |
| `issued_at` | ISO-8601 UTC `Z` | |
| `issuer` | `ed25519:` | the witness; verified against a PINNED id, never the one the receipt names |
| `id`, `signature` | | `id = digest(body)`, signature over `id` |

No free text from a seal is ever copied in (not a headline, a URL, a producer name or an id): only counts and the fixed kind names.

## What is checked per seal
Strict parse (no floats, duplicate keys, byte-order mark, trailing data, unknown fields, nesting over 32); pinned key (the seal cannot supply one; a private key or small-order key as a pin is refused); signature over `MTOS-SEAL-V1\n` + canonical header; payload hash; each data point's hash binds it to the response hashes it names; the named responses exist and succeeded; no repeated ids; times in order; a clock is required.

## What is not checked (and the receipt does not claim)
Whether values are well formed or consistent (the producer's verifier re-derives those), whether the data is true, whether any clock is right.

## Store rules
All or nothing: one seal that fails, or a file whose name is not its own payload hash, and no receipt is signed (the refusal lists the offending ids). A store only grows: `pinned_count` makes fewer seals than last time `store_shrank`.

## Evidence it matches the producer
`tests/flashy/test_seal_witness.py` runs the producer's own sealer to make real seals and its own verifier as the oracle (node, a throwaway in-memory key, a temp directory; nothing is written to the producer's repository). Real seals are accepted; about 35 forgeries of the checked properties and 12 text-level forgeries are refused by both.

## Open
- Recording each attempt in the witness ledger (as is done for plane logs) is not wired.
- The producer's store (`data/seals`) holds no seals yet, so there is no real store to pilot on; the pilot above uses seals made by the real sealer.
