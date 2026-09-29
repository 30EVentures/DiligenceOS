# Slice 12 — Editable data through the web UI

## Goal

The web front end (Slice 11) only ever checked against the fixed bundled
sample dataset — no way to add a subject, a sanctions entry, or a delivery
record without hand-editing a fixture file. This slice makes the three
datasets (sanctions list, registry, delivery ledger) editable through the
UI itself, and makes checks actually see what was added — the same running
process, not a separate copy.

## Included

- `diligenceos/track_record.py`: one small addition, `Ledger.all_records()`
  — every record, not filtered by subject. Slice 7 only ever needed
  `for_subject()`; the `/data` listing page needs everything, and reaching
  into `Ledger`'s private list from another module would be worse than a
  one-line, genuinely public method.
- `diligenceos/store.py`:
  - `Store` — a small, mutable, in-memory holder for all three datasets,
    seeded once from `fixtures/golden/sample_request.json` (the same demo
    data Slice 11 used, now a starting point instead of a fixed ceiling):
    - `add_sanctions_entry(name, program, aliases)` — appends a
      `SanctionsEntry`. Duplicates are allowed (append-only); dedup isn't
      this slice's problem.
    - `add_registry_record(registration_id, name, status, jurisdiction)` —
      sets/overwrites the registry dict entry for that id. A second add
      with the same id is an intentional update, not an error.
    - `add_delivery_record(subject, on_time, note)` — appends to the
      existing `Ledger` (Slice 7's `Ledger.record()` already supports
      this; no change needed there).
    - `sanctions_list() -> SanctionsList`, `registry_lookup() -> RegistryLookup`,
      and a `ledger` property — what `run_diligence` actually consumes,
      always reflecting the latest adds.
- `diligenceos/webapp.py`:
  - A single `Store` instance per process, replacing Slice 11's static,
    load-once `_context()`. `/verdict` now runs against it, so a subject
    added through `/data` a moment ago is immediately checkable.
  - `GET /data` — three tables (sanctions entries, registry records,
    delivery records) as they currently stand, each followed by its own
    small add-form.
  - `POST /data/sanctions`, `POST /data/registry`, `POST /data/delivery` —
    each adds one record to the `Store` and redirects (`302`) back to
    `/data` (post/redirect/get, so refreshing the result page never
    re-submits the form).
  - A nav link between `/` (run a check) and `/data` (manage data) on both
    pages.
  - Every field written into a page — including everything just typed into
    an add-form — stays HTML-escaped, the same discipline Slice 11
    established, now covering more surface.
- `tests/test_store.py` and an extended `tests/test_webapp.py`.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. Adding a registry record for a brand-new registration id through
   `POST /data/registry`, then checking that same id through
   `POST /verdict`, no longer returns "no registry record found" — it
   reflects the just-added record.
3. The same is true end to end for a newly added sanctions entry (the
   subject is now flagged) and a newly added run of late delivery records
   (the subject's track record is now flagged).
4. `GET /data` lists every record added so far, including ones added in
   the same test run/process.
5. A sanctions entry added with a name containing `<script>` renders
   escaped on `/data`, not executed.
6. Nothing written through `/data` survives a server restart — verified by
   the fact `Store` is constructed fresh per process, not backed by a file
   write. This is a stated limit, not an oversight (see Not in this
   slice).

## Not in this slice

- No persistence across restarts. Everything added lives in the running
  process's memory only, same as Slice 7's ledger always has. A durable
  store (a file, a database) is a real decision about format and
  migration, not assumed here.
- No edit or delete of an existing record (registry records can be
  overwritten by re-adding the same id; sanctions and delivery records
  cannot be removed or corrected once added in this slice).
- No validation beyond "the required fields aren't blank" — a malformed
  registration id format, a nonsense status string, or a negative amount
  are all accepted as typed. Phase 0's own "prove the loop" scope, not a
  production data-entry form.
