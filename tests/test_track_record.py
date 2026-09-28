import unittest

from diligenceos.track_record import DeliveryRecord, Ledger, check_track_record
from diligenceos.types import CheckStatus


class CheckTrackRecordTest(unittest.TestCase):
    def setUp(self):
        self.ledger = Ledger()

    def test_no_records_passes(self):
        finding = check_track_record("Nobody Ltd.", self.ledger)
        self.assertEqual(finding.status, CheckStatus.PASS)

    def test_all_on_time_passes(self):
        for _ in range(5):
            self.ledger.record(DeliveryRecord(subject="Meridian Robotics", on_time=True))
        finding = check_track_record("Meridian Robotics", self.ledger)
        self.assertEqual(finding.status, CheckStatus.PASS)

    def test_late_ratio_at_threshold_passes(self):
        # 2 of 5 = 0.4, at the default threshold, not above it
        for on_time in [True, True, True, False, False]:
            self.ledger.record(DeliveryRecord(subject="Meridian Robotics", on_time=on_time))
        finding = check_track_record("Meridian Robotics", self.ledger, late_threshold=0.4)
        self.assertEqual(finding.status, CheckStatus.PASS)

    def test_late_ratio_above_threshold_flags_with_counts(self):
        # 3 of 5 = 0.6, above the default threshold
        for on_time in [True, True, False, False, False]:
            self.ledger.record(DeliveryRecord(subject="Meridian Robotics", on_time=on_time))
        finding = check_track_record("Meridian Robotics", self.ledger)
        self.assertEqual(finding.status, CheckStatus.FLAG)
        self.assertIn("3 of 5", finding.detail)

    def test_records_do_not_leak_across_subjects(self):
        self.ledger.record(DeliveryRecord(subject="A", on_time=False))
        self.ledger.record(DeliveryRecord(subject="A", on_time=False))
        self.ledger.record(DeliveryRecord(subject="B", on_time=True))
        finding_b = check_track_record("B", self.ledger)
        self.assertEqual(finding_b.status, CheckStatus.PASS)
        self.assertEqual(len(self.ledger.for_subject("B")), 1)


if __name__ == "__main__":
    unittest.main()
