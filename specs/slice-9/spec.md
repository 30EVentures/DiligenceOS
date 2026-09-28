# Slice 9 — Glue: one command, one verdict

## Goal

Everything built so far (sanctions screening, identity, track record,
document scan, verdict assembly) run together on one subject through one
command — the first point where DiligenceOS is runnable by someone who
didn't write it, not just importable by tests.

This is also the first slice with a real reason to serialize
`VerdictResult`/`Finding` to JSON — Slice 2 deliberately deferred that until
something actually crossed a process boundary. A CLI is that something.

## Included

- `diligenceos/pipeline.py`:
  - `run_diligence(*, name, registration_id, sanctions_list, registry_lookup, ledger, document_text=None) -> VerdictResult`
    — runs sanctions screening, identity, and track record unconditionally;
    runs the document scan only if `document_text` is given (no document
    supplied is not treated as a missing check, since none was asked for);
    assembles everything with `assemble_verdict`.
- `diligenceos/serialize.py`:
  - `finding_to_dict(finding) -> dict`, `verdict_result_to_dict(result) -> dict`
    — the wire shape matches the worked example on the product one-pager:
    `{"verdict", "trust_score", "findings": [{"category","status","detail","evidence_url"}], "expires"}`.
- `diligenceos/__main__.py` — `python3 -m diligenceos <request.json>` reads a
  request file (subject name + registration id, an optional path to a
  sanctions fixture list, an optional inline registry dict, optional past
  delivery records, optional document text), runs `run_diligence`, and
  prints the verdict as JSON to stdout.
- `fixtures/golden/sample_request.json` — a worked example request.
- `tests/test_pipeline.py` (direct calls) and `tests/test_cli.py` (actually
  invokes the command as a subprocess against the sample request — proving
  the command runs, not just that the function underneath it does).

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. `run_diligence` with no document text runs three checks, not four, and
   still assembles a verdict.
3. `python3 -m diligenceos fixtures/golden/sample_request.json` (from the
   repo root) prints valid JSON to stdout with a `verdict` field.
4. `verdict_result_to_dict` round-trips every field of a `VerdictResult`
   built with all four checks flagged in different combinations.

## Not in this slice

- No real registry HTTP client or real SDN fetch wired into the CLI by
  default — the request format still takes an inline registry dict and an
  optional local sanctions fixture path, matching what each check slice
  actually built.
- No escrow gate (Slice 10). This slice's command prints a verdict; it
  doesn't act on one yet.
