import unittest

from diligenceos.store import Store
from diligenceos.types import CheckStatus
from diligenceos.identity import check_identity
from diligenceos.sanctions import screen_subject
from diligenceos.track_record import check_track_record


class SeededFromSampleTest(unittest.TestCase):
    def test_seeds_all_three_datasets(self):
        store = Store.seeded_from_sample()
        self.assertGreater(len(store.sanctions_entries), 0)
        self.assertGreater(len(store.registry_records), 0)
        self.assertGreater(len(store.delivery_records), 0)


class AddSanctionsEntryTest(unittest.TestCase):
    def test_added_entry_is_screenable_immediately(self):
        store = Store()
        store.add_sanctions_entry(name="Nova Freight Co.", program="TEST", aliases=["Nova"])
        finding = screen_subject("Nova", store.sanctions_list())
        self.assertEqual(finding.status, CheckStatus.FLAG)


class AddRegistryRecordTest(unittest.TestCase):
    def test_added_record_is_lookup_able_immediately(self):
        store = Store()
        store.add_registry_record(
            registration_id="US123", name="Newco Ltd.", status="active", jurisdiction="US"
        )
        finding = check_identity("Newco Ltd.", "US123", store.registry_lookup())
        self.assertEqual(finding.status, CheckStatus.PASS)

    def test_re_adding_the_same_id_overwrites(self):
        store = Store()
        store.add_registry_record(registration_id="US123", name="Old Name", status="active")
        store.add_registry_record(registration_id="US123", name="New Name", status="active")
        self.assertEqual(len(store.registry_records), 1)
        self.assertEqual(store.registry_records[0].name, "New Name")


class AddDeliveryRecordTest(unittest.TestCase):
    def test_added_records_feed_track_record_check(self):
        store = Store()
        for on_time in [False, False, False, True, True]:
            store.add_delivery_record(subject="Slow Co.", on_time=on_time)
        finding = check_track_record("Slow Co.", store.ledger)
        self.assertEqual(finding.status, CheckStatus.FLAG)
        self.assertIn("3 of 5", finding.detail)

    def test_delivery_records_lists_everything_added(self):
        store = Store()
        store.add_delivery_record(subject="A", on_time=True)
        store.add_delivery_record(subject="B", on_time=False, note="late once")
        self.assertEqual(len(store.delivery_records), 2)


if __name__ == "__main__":
    unittest.main()
