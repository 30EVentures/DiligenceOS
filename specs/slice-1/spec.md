# Slice 1 — Repo skeleton + test harness

## Goal

Create the project's folder structure and a test command that runs, so every
later slice has a place to live and a way to be checked.

## Included

- `README.md`, `CLAUDE.md`, `ROADMAP.md`
- `specs/slice-1/spec.md` (this file)
- `fixtures/golden/README.md` (placeholder — real fixtures come in a later
  slice, once there's a check whose output needs pinning)
- `tests/test_smoke.py` — one trivial passing test
- `.gitignore` for Python

## Done when

1. `python3 -m unittest discover -s tests -v` runs and reports one test,
   `OK`.
2. A fresh session can find and run that command using only `CLAUDE.md`.
3. The folders `specs/`, `fixtures/golden/`, `tests/`, `diligenceos/` all
   exist in git.

## Not in this slice

- No `Verdict`/`Finding` types, no checks, no verdict engine.
- No third-party dependencies — added later, when a slice actually needs one.
- No GitHub Actions / CI — added when there's more than one contributor or a
  real deploy target.
