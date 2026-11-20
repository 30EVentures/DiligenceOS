# Registry adapter: a real company register behind the existing identity check

## Goal

Until now `identity` could only match a record a person typed in at `/data`, so every real
company was a HOLD. This slice puts the UK company register (Companies House, free,
requires an API key) behind the existing `RegistryLookup` interface, in the same shape as the
sanctions refresh: a human runs one command, the response is saved with its provenance, and
the server only uses it while it is exactly what was recorded. Free source only; licensed data
is a Phase 1 decision.

## Included

- `diligenceos/registry_ingest.py`
  - `refresh_company(dest_dir, number, *, api_key, fetch=None, now=None)`: one GET of
    `/company/<number>` on the pinned host, https only, no redirects, size-capped. Saves
    `registry/<number>.json` (the raw bytes) and `registry/<number>.meta.json` (source,
    retrieved_at, bytes, sha256). The key is never saved, logged or put in an error.
  - `parse_company_profile(body, number)`: strict. Duplicate keys, a number that is not the one
    asked for, a missing or non-string name or status, are all refused.
  - `load_verified_record(dest_dir, number, now, max_age_days)`: the record for a snapshot that
    is exactly what was recorded; `None` if none exists; `RegistryUnavailable` for anything in
    between (edited, truncated, bad provenance). Never "no record" for a damaged snapshot.
- `Store.registry_lookup()` uses an operator-entered record first (unchanged), then a verified
  snapshot for the subject's registration id.
- `identity` findings made from a snapshot name the source, the retrieval date and the first
  12 hex of the digest; a snapshot older than 30 days is a FLAG ("refresh it"), not a pass.
- A damaged snapshot stops the verdict with `503 registry_unavailable`.
- A receipt's `data_digest` also covers the snapshots' number, sha256 and retrieved_at, only
  when snapshots exist (digests of stores without them are unchanged).
- CLI: `python -m diligenceos refresh-registry <number>`; the key comes from
  `COMPANIES_HOUSE_API_KEY`, never from an argument.

## Not included

Other countries' registers; ownership or officer data; serving the raw snapshot to a
counterparty (so a stranger cannot yet re-fetch the exact bytes); fuzzy name matching;
running it against the live service (this slice is tested with recorded responses only).

## Done when

- [x] A recorded-style profile refreshes, loads and passes identity, citing source/date/digest.
- [x] Tampered, truncated, missing-meta, wrong-number and oversized snapshots are refused.
- [x] Stale snapshot flags; operator record still wins; no snapshots means unchanged digests.
- [x] The key never appears in files, errors or output.
- [x] Full suite reports `OK`.
