# Slice 11 — A persistent local web front end

## Goal

DiligenceOS stops being CLI-only. `python3 -m diligenceos`, with no
argument, now starts a small local web server instead of erroring — a real,
always-available front end, not a one-off demo page. The existing batch
mode (`python3 -m diligenceos <request.json>`, Slice 9) is unchanged and
still works for scripting/automation.

## Included

- `diligenceos/loaders.py` — `build_registry_lookup(registry_dict)` and
  `build_ledger(delivery_records)`, moved out of `__main__.py` unchanged, so
  both the CLI batch mode and the web app can share them instead of
  duplicating the logic.
- `diligenceos/webapp.py` — a dependency-free WSGI app (`wsgiref`, stdlib
  only, no Flask/etc. — see `docs/decisions.md` for why):
  - `GET /` — a form: subject name, registration id, optional
    contract/terms text.
  - `POST /verdict` — runs `run_diligence` and renders the verdict as a
    colored badge (green/amber/red, matching the product one-pager's
    palette) plus each finding, or a 400 with a plain error if the
    required fields are missing.
  - Every user-submitted or check-produced string is HTML-escaped before
    being written into a page — this is a real, if small, web surface, and
    reflected values are a real XSS vector if left unescaped.
  - Runs against the bundled `fixtures/golden/sample_request.json` dataset
    (sanctions list, registry, delivery records) for every request in the
    process's lifetime. This is Phase 0's sample data, not a real registry
    or sanctions feed, and the result page says so.
  - `serve(host=None, port=None)` binds to `127.0.0.1` only (never `0.0.0.0`
    — this is a local dev tool, not something to expose on a network) on
    port `8000` by default, both overridable via `DILIGENCEOS_HOST` /
    `DILIGENCEOS_PORT`.
- `diligenceos/__main__.py` updated: zero arguments starts the web server
  (blocks); one argument (a path) runs the existing batch mode; anything
  else prints usage and exits `2` — unchanged from before except that zero
  arguments used to be the error case and now isn't.
- `tests/test_webapp.py` — calls the WSGI `app` callable directly (no
  sockets): the form renders, a valid submission renders the right verdict
  and findings, a missing required field renders a 400, an unknown path
  renders a 404.
- A subprocess test in `tests/test_cli.py` that actually launches
  `python3 -m diligenceos` with no arguments, polls a real HTTP `GET /`
  against it until it answers (or times out), and terminates the process —
  proving the real server starts, not just the WSGI function underneath it.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. `python3 -m diligenceos` (no arguments) starts a server; `GET /` returns
   the form; a valid `POST /verdict` returns the correct verdict, trust
   score, and findings, matching what the batch CLI would produce for the
   same inputs.
3. Submitting the sample request's subject and its document text (missing
   the indemnification clause) through the form renders `HOLD`, the same
   result the batch mode already produces for it.
4. A crafted subject name containing `<script>` renders escaped, not
   executed, on the result page.
5. `python3 -m diligenceos fixtures/golden/sample_request.json` (the old
   batch mode) still works exactly as it did in Slice 9.

## Not in this slice

- No way to edit the registry, sanctions list, or delivery-record ledger
  through the UI — the demo dataset is fixed per process. Slice 12,
  if it's wanted.
- No authentication, no HTTPS, no production WSGI server — `wsgiref` is
  explicitly a development server; a real deployment target is a Phase-1+
  decision, not assumed here.
- Submitting a check does not add anything to the track-record ledger — a
  verdict check isn't the same event as a real delivery outcome, and
  conflating them would misrepresent what the ledger tracks.
