# Slice 3b — Real OFAC SDN ingestion

## Goal

Parse the real, published OFAC SDN list format into `SanctionsEntry`
records, so Slice 3's matcher can eventually run against the real list
instead of a fixture — without making the test suite depend on the network.

## Included

- `diligenceos/sdn_ingest.py`:
  - `parse_sdn_csv(path) -> SanctionsList` — parses the real SDN file's
    column layout (headerless, 12 columns: ent_num, SDN_Name, SDN_Type,
    Program, Title, Call_Sign, Vess_type, Tonnage, GRT, Vess_flag,
    Vess_owner, Remarks). Extracts `name` and `program` directly; best-effort
    extracts aliases from `a.k.a. '...'` patterns inside `Remarks` — stated
    as best-effort, not exhaustive (the real field has inconsistent
    formatting the regex won't catch every case of).
  - `fetch_sdn_list(dest_path, url=DEFAULT_SDN_URL) -> Path` — a thin
    `urllib.request` download to a local path. Not called by any test:
    network fetches in an automated test suite are flaky and the published
    URL can move: this function exists to be run by a human or a scheduled
    job, not by `unittest discover`.
- `fixtures/golden/sdn_sample.csv` — a few rows in the real column format,
  with clearly fictional names (not real designated persons/entities) so
  the parser is tested without embedding real government sanctions data
  whose accuracy this repo cannot vouch for.
- `tests/test_sdn_ingest.py`.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. `parse_sdn_csv` on the fixture CSV returns a `SanctionsList` whose
   entries match Slice 3's `SanctionsEntry` shape and can be passed straight
   into `screen_subject`.
3. At least one fixture row's `Remarks` field with an `a.k.a.` pattern
   produces a non-empty `aliases` tuple.
4. `fetch_sdn_list` exists and is importable, but no test calls it.

## Not in this slice

- No test coverage of `fetch_sdn_list` itself (network). A human runs it
  once real ingestion is actually wired into a deployment.
- No caching, no incremental updates, no dedup against a previous
  ingestion. The real list is ~10k+ entries; loading it fully each time is
  fine for now and revisited only if it's ever measured to be slow.
