# Slice 3 — Sanctions/watchlist screening (fixture list)

## Goal

The first real check: one subject name in, one `Finding` out — `PASS` if
there's no match against a sanctions/watchlist list, `FLAG` (with the
matched name and program named in `detail`) if there is.

This slice proves the screening *mechanism* — exact and alias matching,
case-insensitive — against a small local fixture list of fictional entries.
It deliberately does not ingest the real, published OFAC SDN list yet: that
is real-world data with its own format quirks (weak aliases, punctuation
noise, thousands of entries) and belongs in its own slice once the matching
mechanism it will feed is proven. Building both at once risks debugging the
matcher and the data ingestion at the same time.

## Included

- `diligenceos/sanctions.py`:
  - `SanctionsEntry` — frozen dataclass: `name: str`, `program: str`,
    `aliases: tuple[str, ...] = ()`.
  - `SanctionsList` — frozen dataclass wrapping `entries: tuple[SanctionsEntry, ...]`,
    with `match(name: str) -> SanctionsEntry | None`: case-insensitive exact
    match against an entry's `name` or any of its `aliases`. No fuzzy
    matching, no partial matching — a deliberate, stated limit (see Not in
    this slice).
  - `screen_subject(name: str, sanctions_list: SanctionsList) -> Finding` —
    category `"sanctions"`; `PASS` with no match; `FLAG` with a `detail`
    naming the matched entry and its program on a match. `evidence_url` is
    `None` for now — there's no real citable record behind a fixture entry;
    a real source's URL is wired in when Slice 3 gets a real-data
    successor.
- `fixtures/golden/sanctions_sample.json` — a handful of clearly fictional
  entries (no real designated persons or entities), used by the tests.
- `tests/test_sanctions.py`.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK` with the new
   tests included.
2. A name with no match against the fixture list produces a `PASS` `Finding`.
3. A name matching an entry's `name` field, case-insensitively, produces a
   `FLAG` `Finding` whose `detail` names the entry and its program.
4. A name matching one of an entry's `aliases` produces the same `FLAG`.
5. A name that is merely similar (not an exact or alias match) still
   produces `PASS` — proving the "no fuzzy matching yet" limit is real,
   not just stated.

## Not in this slice

- No real OFAC SDN ingestion (no network fetch, no CSV/XML parsing of the
  actual published list). Tracked as its own item in `ROADMAP.md`.
- No fuzzy/typo-tolerant matching, no transliteration handling. A stated
  limit, not a bug — the roadmap's Phase 1 (real data, real stakes) is
  where matching quality actually has to hold up; Phase 0 only has to prove
  the check produces an honest, evidenced `Finding`.
- No other check (identity, track record, documents) — Slice 4 onward.
