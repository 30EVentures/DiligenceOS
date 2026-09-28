# Slice 7 — Track record

## Goal

The third check: has this counterparty actually delivered before — not a
sanctions match, not a registry lookup, but a record of what actually
happened on past engagements.

## Included

- `diligenceos/track_record.py`:
  - `DeliveryRecord` — frozen dataclass: `subject: str`, `on_time: bool`,
    `note: str = ""`.
  - `Ledger` — an append-only, in-memory store: `record(delivery_record)`
    adds one; `for_subject(subject) -> tuple[DeliveryRecord, ...]` returns
    every record for that subject, in insertion order. Deliberately no file
    or database backing yet — see Not in this slice.
  - `check_track_record(subject, ledger, *, late_threshold=0.4) -> Finding`
    — category `"track_record"`. No records for the subject: `PASS` (no
    history is not evidence of a problem, and isn't treated as one). One or
    more records: computes the late ratio; `FLAG` if it's strictly above
    `late_threshold`, naming the count ("2 of 5 past deliveries late") in
    `detail`; `PASS` otherwise.
- `tests/test_track_record.py`.

## Done when

1. `python3 -m unittest discover -s tests -v` reports `OK`.
2. A subject with no records passes.
3. A subject whose late ratio is at or below `late_threshold` passes.
4. A subject whose late ratio is above `late_threshold` is flagged, with the
   exact counts named in `detail`.
5. Records for one subject never leak into another subject's `for_subject`
   result.

## Not in this slice

- No durable storage (a file, a database). The ledger is process-memory
  only; whoever wires this into a real deployment decides how records
  actually get in and persist — that's an integration decision, not this
  slice's.
- No real "delivery" data source (invoices, shipment records, a payments
  API). Records are supplied directly to the ledger; where they come from
  in practice is out of scope here.
