# Slice 16 — Machine API

## Goal

The caller is as likely an agent as a person. Give it a JSON interface on
the same server and the same Store: structured in, a Slice-15 receipt out,
one endpoint to verify a receipt, one to discover what the service does,
and errors with a stable, parseable shape. No HTML, no form encoding.

## Included

- `diligenceos/api.py`: `handle(method, path, body, store) -> (status,
  headers, body_bytes)` — pure, no WSGI, so it is unit-testable directly.
  - `POST /v1/verdict` — body `{"subject": {"name", "registration_id"},
    "document_text"?: str}`. Returns `200` with a receipt. The receipt's
    `inputs_digest` covers the request **and** a snapshot of the store's
    data, so the same request against changed data is distinguishable.
  - `POST /v1/verify` — body is a receipt; returns `200`
    `{"valid", "expired", "errors"}` (a *failed* verification is still a
    successful call). Uses the current time for expiry.
  - `GET /v1/capabilities` — versions, verdict values, check categories,
    endpoints with request/response shape, error shape.
  - Errors: `{"error": {"code", "message", "field"?}}`; `400`
    `invalid_json` / `invalid_request`, `404 not_found`, `405
    method_not_allowed` (with `Allow`), `413 body_too_large` (1 MiB cap).
- `webapp.py`: any path starting `/v1/` is delegated to `api.handle`.
- `tests/test_api.py`, plus one wiring test in `tests/test_webapp.py`.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. A `/v1/verdict` response verifies through `/v1/verify`, and a tampered
   copy does not.
3. Every error path returns the documented JSON shape and status.
4. Verified live with `curl` against a running server.

## Not in this slice

- No authentication, rate limiting or caller identity — localhost only for
  now. Who is calling (and under what delegated authority) is Slice 19.
- No async / long-running mode, no API versioning beyond the `/v1/` prefix.
- Receipts are still unsigned (Slice 15).
