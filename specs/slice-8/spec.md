# Slice 8 — Document red-flag scan

## Goal

The fourth check: does the supplied contract/terms text actually contain
the protections a transaction like this one normally has — not full
contract-review NLP, a stated-limits keyword presence scan.

## Included

- `diligenceos/documents.py`:
  - `DEFAULT_REQUIRED_CLAUSES = ("liability cap", "termination", "indemnification")`
    — a plain, overridable tuple, not a hidden constant.
  - `scan_document(text, *, required_clauses=DEFAULT_REQUIRED_CLAUSES) -> Finding`
    — category `"document_scan"`. Case-insensitive substring search (reuses
    `diligenceos.evidence.fold`, so "is this phrase present" means the same
    thing here as it does for citation verification) for each required
    clause phrase. `FLAG` naming every missing clause in `detail` if one or
    more are absent; `PASS` if every required clause phrase is found
    somewhere in the text.
- `tests/test_documents.py`.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. Text containing all default required clause phrases passes.
3. Text missing one required clause phrase is flagged, naming exactly that
   one in `detail`.
4. Text missing more than one is flagged, naming all of them.
5. The required-clause list is overridable per call, not hard-coded into
   the function body.

## Not in this slice

- No real clause *quality* review (is the liability cap actually
  reasonable, is the termination clause one-sided). This scan only checks
  whether the phrase is present at all — a much smaller, honestly-scoped
  claim, and the spec says so plainly rather than implying more.
- No PDF/DOCX extraction. `scan_document` takes plain text; getting text out
  of a real contract file is a separate, later concern.
- No page-number citation in `detail` (the roadmap's illustrative example
  said "page 4"; plain text has no pages). Real citation, if this needs it,
  waits for a real document format that actually carries page structure.
