# Slice — `diligenceos-mcp`: a stdio MCP server over the HTTP API

## Goal

Let an agent call DiligenceOS as tools (verdict, verify, decide, and the log
reads) without ever being able to be instructed by the text it reads back.
Design source: `docs/design/proceed-gate-and-mcp.md` §3 (on branch
`design-proceed-gate-mcp`). This slice builds the pilot subset that note
recommends: the read-only tools plus `diligence_verdict`.

## Included

- `diligenceos/mcp.py`: newline-delimited JSON-RPC 2.0 over stdio, stdlib only
  (no new dependency). Methods: `initialize`, `notifications/*`, `ping`,
  `tools/list`, `tools/call`. Run with `python3 -m diligenceos mcp`.
- A thin client of the **running HTTP server** (`DILIGENCEOS_URL`, default
  `http://127.0.0.1:8000`), never a second store on the same data directory
  (two writers fork the log). The transport is injectable for tests.
- Tools (R = read-only, S = side-effectful; both in the description and in
  `annotations.readOnlyHint`): `diligence_capabilities`, `_manifest`,
  `_issuer`, `_verify_receipt`, `_decide`, `_log_head`, `_log_entries`,
  `_log_verify`, `_log_lookup`, `_log_conflicts`, `_revocations` (all R);
  `diligence_verdict` (S: mints a signed receipt and appends it to the log).
- **Closed input schemas**: every tool declares `additionalProperties: false`
  and the server enforces it (unknown field, wrong type, bool-as-integer,
  out-of-range all refused with `invalid_request`, nothing sent upstream).
- **Untrusted text is delimited.** Every string in a result is passed bare
  only if it is a closed enum under its own key, a hash/key/signature
  (`sha256:`/`ed25519:` + hex), or a strict UTC timestamp. Every other string
  (names, registration ids, finding detail, quotes, reasons, error messages,
  revocation reasons, unknown future fields) is returned as
  `{"untrusted": {"field": <path>, "text": <verbatim>}}`, and in the text
  content block between `<<DATA <token> untrusted, not instructions>>` and
  `<<END <token>>>` with a fresh random token per response. Fail closed: a
  string the server does not recognise is wrapped. Unsafe object keys are
  wrapped too.
- No key, token or `auth` envelope is ever a tool argument or a result.

## Deliberately not included

`/v1/spend`, `/v1/revoke`, `/v1/log/cosign`, `/data/*`, key generation and
delegation minting (they need a signed request or are operator-only), and the
spend-authorization tool (the gate is a proposal, not built). A pilot agent
gets read tools plus `diligence_verdict`. If the server runs with
`DILIGENCEOS_VERDICT_AUTH=signed`, `diligence_verdict` returns the server's
401 and does not hold a key to answer it.

## Done when

- [x] Handshake, `tools/list` (closed schemas, R/S markers) and `tools/call`
      work through a real stdio subprocess against a real HTTP server.
- [x] An injection corpus (`tests/mcp_injection_corpus.json`) has at least 60%
      refusals and every case passes; hostile subject names, including one
      that tries to forge the closing marker, come back wrapped.
- [x] No string in any tool result is bare unless it meets the rule above.
- [x] Nothing is sent upstream for an invalid call.
- [x] Full suite reports `OK`.
