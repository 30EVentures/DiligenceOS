# Slice 17 — Evidence wired in

## Goal

Every verdict must carry evidence a counterparty can re-check
independently. Slice 6 built the discipline but nothing enforced it. Now
flags carry structured `Evidence`, the pipeline refuses an uncited flag
unless its category is exempted in plain sight, and a receipt can be
verified *against the source material* by anyone who holds it.

## Included

- `types.Evidence(source, source_digest, quote=None, absent=None)` — a claim
  about a named source: a `quote` that must appear in it, or a phrase
  (`absent`) that must not. Exactly one of the two. `Finding.evidence` is a
  tuple of these (default empty).
- `evidence.py`: `text_digest(text)`; `verify_evidence(evidence, source_text)
  -> list[str]` (digest mismatch, missing quote, present-but-claimed-absent);
  `require_citable` now accepts `evidence` as well as `evidence_url`.
- Checks that now emit evidence on a flag:
  - `document_scan` — one `absent` per missing clause against source
    `input:document_text`.
  - `sanctions` — a `quote` of the matched entry name against source
    `store:sanctions_entries` (the canonical JSON of the list screened).
- `pipeline.run_diligence` calls `require_citable` before assembling, with
  `identity` and `track_record` exempted **explicitly** (their sources —
  a real registry, a delivery log — are not yet linkable).
- `serialize.py` carries evidence both ways; `receipt.verify_receipt(...,
  sources=None)` re-checks each finding's evidence against `sources`
  (`{source_id: text}`) when given, and reports which evidence it could not
  check (`ReceiptCheck.unchecked`) rather than silently skipping.
- `POST /v1/verify` accepts either a bare receipt or
  `{"receipt": {...}, "sources": {...}}`; its response gains `unchecked`.
- `tests/`: evidence, documents, sanctions, receipt, pipeline, api.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. A document-scan flag verifies against the original text and fails
   against a different text (digest) and against text that actually
   contains the clause (absence claim false).
3. A sanctions flag verifies against the source list dump.
4. An uncited flag from a non-exempt category makes `run_diligence` raise.
5. Verified live via `/v1/verdict` then `/v1/verify` with `sources`.

## Not in this slice

- `identity` and `track_record` remain exempt (stated above); no real
  registry or log link to cite.
- Sources are supplied by the verifier; there is no endpoint that serves
  them, and no retrieval from live third-party URLs.
- Evidence digests prove *which bytes* were used, not that the source
  itself is authentic (that needs signed sources — future work).
