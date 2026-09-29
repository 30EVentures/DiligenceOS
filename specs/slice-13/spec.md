# Slice 13 — Durable storage for the Store

## Goal

Slice 12's `Store` was explicitly in-memory only, by deliberate choice
(see `docs/decisions.md`, 2026-09-28) — but the reason given there was
about not polluting the checked-in sample fixture, not "persistence is
never wanted." Now that DiligenceOS is a real, always-running local tool
(Slice 11), losing every added record on restart is a real, felt cost, not
a hypothetical one. This slice adds a durable, git-ignored data file
outside the checked-in fixtures entirely.

## Included

- `diligenceos/store.py`:
  - `Store.__init__` takes an optional `persist_path: Path | None`. Every
    `add_*` call saves to it immediately if one is set; with none, `Store`
    behaves exactly as it did in Slice 12 (pure in-memory — existing tests
    unchanged).
  - `Store.to_dict()` / `Store.from_dict(data, persist_path=...)` — the
    wire shape is the same three collections `seeded_from_sample` already
    builds from, just self-contained (sanctions entries carry their data
    directly, not a path to a fixture).
  - `Store.seeded_from_sample(persist_path=None)` — unchanged behavior with
    no path; with one, seeds in memory first (no repeated writes while
    seeding) then saves once at the end.
  - `Store.load_or_seed(persist_path) -> Store` — loads the file if it
    exists; otherwise seeds from the sample and writes the file for the
    first time. This is what a real run now starts from.
- `diligenceos/webapp.py`: `_get_store()` now calls
  `Store.load_or_seed(data_path())`, where `data_path()` reads
  `DILIGENCEOS_DATA_PATH` (default `~/.diligenceos/store.json`, expanded
  via `Path.expanduser()`) — outside this repo entirely, so it can never
  collide with the checked-in fixtures or get picked up by `git status`.
- `tests/test_store.py` and `tests/test_webapp.py` extended: webapp tests
  now point `DILIGENCEOS_DATA_PATH` at a fresh temp file per test (setUp/
  tearDown), so persistence is genuinely exercised without one test's data
  leaking into another's, or into the real `~/.diligenceos/`.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`, and no test run
   ever touches the real `~/.diligenceos/store.json`.
2. Starting the server, adding a registry record through `/data`, stopping
   the server (`Ctrl-C`), and starting it again shows that same record
   still there — verified by hand, not just by a test asserting a file
   write happened.
3. `Store()` with no `persist_path` (the Slice 12 shape) still works
   exactly as before — every existing test in `test_store.py` keeps
   passing unmodified.
4. Deleting `~/.diligenceos/store.json` and restarting falls back to the
   bundled sample dataset, same as a first-ever run.

## Not in this slice

- No handling of a corrupted or partially-written data file — it's read
  with a plain `json.loads`, and a bad file crashes the server on startup.
  A production tool would want a backup-and-recover strategy; this one
  doesn't have real users' money on the line yet.
- No locking or concurrent-write safety. `wsgiref`'s dev server handles
  one request at a time by default, so this isn't a real risk yet — worth
  revisiting the moment that stops being true.
- No way to edit or delete a persisted record from the UI — still
  append/overwrite-by-id only, the same limit Slice 12 stated.
