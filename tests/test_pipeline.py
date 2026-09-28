import unittest

from diligenceos.identity import RegistryRecord
from diligenceos.pipeline import run_diligence
from diligenceos.sanctions import SanctionsList
from diligenceos.serialize import verdict_result_to_dict
from diligenceos.track_record import Ledger
from diligenceos.types import Verdict

ACTIVE_REGISTRY = {
    "UK09456213": RegistryRecord(
        name="Meridian Robotics Ltd.",
        registration_id="UK09456213",
        status="active",
        jurisdiction="UK",
    )
}


class RunDiligenceTest(unittest.TestCase):
    def test_clean_subject_with_no_document_is_proceed(self):
        result = run_diligence(
            name="Meridian Robotics Ltd.",
            registration_id="UK09456213",
            sanctions_list=SanctionsList(),
            registry_lookup=ACTIVE_REGISTRY.get,
            ledger=Ledger(),
        )
        self.assertEqual(result.verdict, Verdict.PROCEED)
        self.assertEqual(len(result.findings), 3)  # no document check ran

    def test_document_text_adds_a_fourth_finding(self):
        result = run_diligence(
            name="Meridian Robotics Ltd.",
            registration_id="UK09456213",
            sanctions_list=SanctionsList(),
            registry_lookup=ACTIVE_REGISTRY.get,
            ledger=Ledger(),
            document_text="no relevant clauses here",
        )
        self.assertEqual(len(result.findings), 4)
        self.assertEqual(result.verdict, Verdict.HOLD)

    def test_unknown_registration_id_holds(self):
        result = run_diligence(
            name="Nobody Ltd.",
            registration_id="UK00000000",
            sanctions_list=SanctionsList(),
            registry_lookup=ACTIVE_REGISTRY.get,
            ledger=Ledger(),
        )
        self.assertEqual(result.verdict, Verdict.HOLD)


class VerdictResultToDictTest(unittest.TestCase):
    def test_round_trips_all_fields(self):
        result = run_diligence(
            name="Meridian Robotics Ltd.",
            registration_id="UK09456213",
            sanctions_list=SanctionsList(),
            registry_lookup=ACTIVE_REGISTRY.get,
            ledger=Ledger(),
            document_text="Termination. Liability Cap. Indemnification.",
        )
        as_dict = verdict_result_to_dict(result)
        self.assertEqual(as_dict["verdict"], "PROCEED")
        self.assertEqual(len(as_dict["findings"]), 4)
        self.assertIn("category", as_dict["findings"][0])
        self.assertIn("status", as_dict["findings"][0])


if __name__ == "__main__":
    unittest.main()
