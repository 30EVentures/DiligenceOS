# Slice 6 — Evidence discipline

## Goal

The rule the whole project answers to, made checkable: a flagged finding
without a re-checkable citation is treated as a bug, not shipped silently.
This is DiligenceOS's own, independent implementation of that discipline —
see `CLAUDE.md` on why it isn't shared code with anything else.

## Included

- `diligenceos/evidence.py`:
  - `EvidenceError(ValueError)`.
  - `fold(text: str) -> str` — lowercase, collapse whitespace, strip. The
    shared normalization every citation check in this module uses, so two
    checks can't quietly disagree about what "the same text" means.
  - `verify_citation(quote: str, source_text: str) -> bool` — `True` if the
    folded `quote` is a substring of the folded `source_text`. This is the
    actual re-check: given a claimed quote and the real document, does the
    quote really appear in it.
  - `require_citable(findings, *, exempt_categories=frozenset()) -> None` —
    raises `EvidenceError` naming the first offending finding if any `FLAG`
    finding, whose `category` is not in `exempt_categories`, has
    `evidence_url is None`. Every Phase-0 check that screens against a
    fixture list (Slice 3's sanctions, Slice 4's identity, until they have
    real, linkable sources) is passed in `exempt_categories` explicitly at
    the call site — never silently, so the exemption is visible in the
    code that calls it, not buried in this module.
- `tests/test_evidence.py`.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. `verify_citation` matches a quote that differs only in case, whitespace,
   or line breaks from the source text, and correctly fails a quote that
   isn't really there.
3. `require_citable` raises on a flagged, non-exempt finding with no
   `evidence_url`, and does not raise once one is supplied.
4. `require_citable` does not raise on a flagged finding whose category was
   explicitly exempted, or on any `PASS` finding regardless of
   `evidence_url`.

## Not in this slice

- No wiring of `require_citable` into `assemble_verdict` yet — that's a
  judgment call about *where* the discipline gets enforced (per check? at
  assembly time? both?) that deserves its own look once there's more than
  one real caller to learn from, not decided speculatively here.
- No Merkle root, no signature, no tamper-evidence. That's real
  infrastructure this project's other capabilities already prove works
  elsewhere; DiligenceOS's own version, if it ever needs one, is a later,
  deliberate decision — not assumed by default.
