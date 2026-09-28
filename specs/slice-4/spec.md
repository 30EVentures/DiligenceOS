# Slice 4 — Identity/legitimacy check

## Goal

The second check: is the subject actually registered, under the name and
id given, and in good standing — not a shell or a dissolved entity dressed
up as a live one.

## Included

- `diligenceos/identity.py`:
  - `RegistryRecord` — frozen dataclass: `name: str`, `registration_id: str`,
    `status: str` (e.g. `"active"`, `"dissolved"`), `jurisdiction: str`.
  - `RegistryLookup` — a type alias for `Callable[[str], RegistryRecord | None]`:
    a lookup is *injected*, not hard-coded to one registry's API. A real
    Companies House / OpenCorporates HTTP adapter can be swapped in later
    without touching the check logic.
  - `check_identity(name, registration_id, lookup) -> Finding` — category
    `"identity"`. `FLAG` if the lookup returns nothing (nothing registered
    under that id), if `status` isn't `"active"`, or if the claimed `name`
    doesn't reasonably match the registry's name for that id
    (case-insensitive, whitespace-normalized comparison — no fuzzy
    matching, same stated limit as Slice 3). `PASS` otherwise.
- `tests/test_identity.py`, using an in-memory dict-backed lookup — no real
  registry API integration in this slice.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. An unknown `registration_id` produces a `FLAG` with a detail saying
   nothing was found.
3. A known id with `status != "active"` produces a `FLAG` naming the actual
   status.
4. A known id whose registry name doesn't match the claimed name produces a
   `FLAG` naming both.
5. A known, active, name-matching id produces `PASS`.

## Not in this slice

- No real registry HTTP client (Companies House, OpenCorporates, or any
  other). `RegistryLookup` is the seam a later slice plugs one into.
- No jurisdiction-specific id format validation.
