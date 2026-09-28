"""Track record: has this counterparty actually delivered before."""

from __future__ import annotations

from dataclasses import dataclass, field

from diligenceos.types import CheckStatus, Finding

CATEGORY = "track_record"


@dataclass(frozen=True)
class DeliveryRecord:
    subject: str
    on_time: bool
    note: str = ""


@dataclass
class Ledger:
    _records: list[DeliveryRecord] = field(default_factory=list)

    def record(self, delivery_record: DeliveryRecord) -> None:
        self._records.append(delivery_record)

    def for_subject(self, subject: str) -> tuple[DeliveryRecord, ...]:
        return tuple(r for r in self._records if r.subject == subject)


def check_track_record(subject: str, ledger: Ledger, *, late_threshold: float = 0.4) -> Finding:
    records = ledger.for_subject(subject)
    if not records:
        return Finding(category=CATEGORY, status=CheckStatus.PASS)

    late = sum(1 for r in records if not r.on_time)
    total = len(records)
    if late / total > late_threshold:
        return Finding(
            category=CATEGORY,
            status=CheckStatus.FLAG,
            detail=f"{late} of {total} past deliveries late",
        )
    return Finding(category=CATEGORY, status=CheckStatus.PASS)
