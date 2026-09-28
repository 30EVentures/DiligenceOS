# DiligenceOS — working notes for Claude

## What this is

DiligenceOS: a due-diligence agent. Give it a subject and a transaction, it
returns one verdict (`PROCEED` / `HOLD` / `RED_FLAG`) built from independently
checkable evidence. The roadmap (concept → Fortune-10-credible) lives outside
this repo, in a private doc; ask the owner for the link if it matters for a
decision. `ROADMAP.md` here is the working, slice-level version.

## How to run

- Repo lives at `~/DiligenceOS`.
- Language: Python 3 (developed on 3.14). No third-party dependencies yet —
  when a slice needs one, it's added deliberately (see Boundaries) and this
  section gains a venv setup step.
- Tests:

  ```
  python3 -m unittest discover -s tests -v
  ```

  Must report `OK` before any commit.

## Conventions

- Work one slice at a time. Each slice gets a folder under `specs/` with a
  `spec.md` (goal + "Done when" checks) written *before* any code.
- Small commits on a branch; open a pull request for review. Never commit to
  `main` directly, except the repo-skeleton bootstrap commit.
- `gh` is installed and authenticated as `30EVentures`. After `git push`,
  open the PR with `gh pr create`; merging is the owner's call, not automatic.
- Every verdict must eventually carry evidence a counterparty can re-check
  independently — not a claim, a link. Not enforced yet — Slice 1 has no
  checks at all — but it is the core rule everything else answers to.

## Boundaries — ask before changing

- **Brand separation.** DiligenceOS is its own product under 30E Ventures.
  Nothing in this repo — code, docs, commit history, package metadata, test
  fixtures — may name AnalystOS, DepositX, Concord, KPMG, Michael Gord, Gord
  Holdings, or a personal email address. Only "30E Ventures" is named. Scan
  with grep before any push, especially before the repo is made public.
  Local git identity in this repo is already set to
  `30E Ventures <233154122+30EVentures@users.noreply.github.com>` — check
  `git config user.email` in a fresh clone before committing; don't let it
  fall back to a personal one.
- **No shared code with AnalystOS or Concord/DepositX.** Capabilities that
  look similar (citation verification, an escrow-style release gate) are
  reimplemented here from scratch, informed by the design, never imported or
  copy-pasted with attribution intact. See `docs/decisions.md` for why.
- `fixtures/golden/` is the regression set, once real fixtures exist. Add
  cases; do not edit existing ones.
- Dependencies: none yet. When a slice's explicit point is adding one, pin an
  exact version in `requirements.txt` and record *why* in `docs/decisions.md`.

## Where things are

- `diligenceos/`          — the code
- `docs/decisions.md`     — dated log of choices and why
- `specs/<slice>/spec.md` — what each slice does and how it's checked
- `ROADMAP.md`            — working queue, slice by slice
