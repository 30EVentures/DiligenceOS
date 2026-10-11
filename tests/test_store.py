import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_with_no_persist_path_writes_nothing(self):
        # Slice 12's original shape must keep working unmodified.
        store = Store.seeded_from_sample()
        self.assertIsNone(store.persist_path)


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


class PersistenceTest(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.path = Path(self._tmpdir.name) / "store.json"

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_add_writes_to_disk_immediately(self):
        store = Store(persist_path=self.path)
        store.add_registry_record(registration_id="US1", name="A", status="active")
        self.assertTrue(self.path.exists())
        on_disk = json.loads(self.path.read_text())
        self.assertIn("US1", on_disk["registry"])

    def test_load_or_seed_creates_the_file_on_first_run(self):
        self.assertFalse(self.path.exists())
        store = Store.load_or_seed(self.path)
        self.assertTrue(self.path.exists())
        self.assertGreater(len(store.registry_records), 0)  # seeded from the sample

    def test_load_or_seed_reads_back_a_previous_run(self):
        first = Store.load_or_seed(self.path)
        first.add_registry_record(registration_id="US1", name="Round Trip Ltd.", status="active")

        second = Store.load_or_seed(self.path)
        finding = check_identity("Round Trip Ltd.", "US1", second.registry_lookup())
        self.assertEqual(finding.status, CheckStatus.PASS)

    def test_seeded_from_sample_writes_the_full_seed_to_disk(self):
        seeded = Store.seeded_from_sample(persist_path=self.path)
        on_disk = json.loads(self.path.read_text())
        self.assertEqual(len(on_disk["sanctions_entries"]), len(seeded.sanctions_entries))
        self.assertEqual(len(on_disk["registry"]), len(seeded.registry_records))
        self.assertEqual(len(on_disk["delivery_records"]), len(seeded.delivery_records))

    def test_with_no_persist_path_still_works_unmodified(self):
        store = Store()
        store.add_registry_record(registration_id="US1", name="A", status="active")
        self.assertFalse(self.path.exists())  # nothing written anywhere

    def test_save_leaves_no_temp_file_behind_on_success(self):
        store = Store(persist_path=self.path)
        store.add_registry_record(registration_id="US1", name="A", status="active")
        self.assertFalse(self.path.with_name(self.path.name + ".tmp").exists())
        self.assertTrue(self.path.exists())

    def test_a_crash_mid_write_never_corrupts_the_real_file(self):
        # Fixed 2026-10-02: _save() used to write_text() the real path
        # directly, so a process killed mid-write (power loss, OOM) left a
        # truncated, unparseable store.json - not just losing the latest
        # change, but making the server refuse to start at all next time.
        # Writing to a sibling temp file and os.replace()-ing it into place
        # means a crash during the write only ever damages the temp file;
        # the real path is untouched until the replace, which is atomic.
        store = Store(persist_path=self.path)
        store.add_registry_record(registration_id="US1", name="Before The Crash", status="active")
        good_bytes = self.path.read_bytes()

        real_write_text = Path.write_text

        def crashes_halfway(self_path, data, *a, **kw):
            if self_path == store.persist_path.with_name(store.persist_path.name + ".tmp"):
                self_path.write_bytes(data.encode()[: len(data) // 2])
                raise OSError("simulated crash mid-write")
            return real_write_text(self_path, data, *a, **kw)

        with mock.patch.object(Path, "write_text", crashes_halfway):
            with self.assertRaises(OSError):
                store.add_registry_record(registration_id="US2", name="During The Crash", status="active")

        # the real file must be exactly what it was before the crashed write -
        # never a half-written mix, and it must still parse.
        self.assertEqual(self.path.read_bytes(), good_bytes)
        reloaded = json.loads(self.path.read_text())
        self.assertIn("US1", reloaded["registry"])
        self.assertNotIn("US2", reloaded["registry"])
        Store.load_or_seed(self.path)  # must not raise


if __name__ == "__main__":
    unittest.main()
