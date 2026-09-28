import unittest
from pathlib import Path

from diligenceos.sanctions import SanctionsEntry, SanctionsList, load_sanctions_list, screen_subject
from diligenceos.types import CheckStatus

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "golden" / "sanctions_sample.json"


class SanctionsListTest(unittest.TestCase):
    def setUp(self):
        self.sanctions_list = load_sanctions_list(FIXTURE)

    def test_loads_fixture_entries(self):
        self.assertEqual(len(self.sanctions_list.entries), 3)

    def test_no_match_for_unrelated_name(self):
        self.assertIsNone(self.sanctions_list.match("Riverstone Analytics LLC"))

    def test_exact_match_is_case_insensitive(self):
        self.assertIsNotNone(self.sanctions_list.match("ILSA MARCHETTI"))

    def test_alias_match(self):
        entry = self.sanctions_list.match("NW Trading")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "Northwind Trading Co.")

    def test_similar_but_not_exact_name_does_not_match(self):
        # proves the "no fuzzy matching" limit is real: a close-but-not-exact
        # name must not be flagged.
        self.assertIsNone(self.sanctions_list.match("Northwind Trade Co"))


class ScreenSubjectTest(unittest.TestCase):
    def setUp(self):
        self.sanctions_list = load_sanctions_list(FIXTURE)

    def test_pass_when_no_match(self):
        finding = screen_subject("Riverstone Analytics LLC", self.sanctions_list)
        self.assertEqual(finding.category, "sanctions")
        self.assertEqual(finding.status, CheckStatus.PASS)
        self.assertIsNone(finding.detail)

    def test_flag_when_matched_on_primary_name(self):
        finding = screen_subject("Ilsa Marchetti", self.sanctions_list)
        self.assertEqual(finding.status, CheckStatus.FLAG)
        self.assertIn("FICTIONAL-TEST-2", finding.detail)

    def test_flag_when_matched_on_alias(self):
        finding = screen_subject("Cobalt Ferry Logistics", self.sanctions_list)
        self.assertEqual(finding.status, CheckStatus.FLAG)
        self.assertIn("Cobalt Ferry Logistics Ltd.", finding.detail)

    def test_screen_subject_works_without_a_fixture_too(self):
        empty = SanctionsList(entries=(SanctionsEntry(name="Solo Entry", program="X"),))
        self.assertEqual(screen_subject("Nobody Here", empty).status, CheckStatus.PASS)
        self.assertEqual(screen_subject("Solo Entry", empty).status, CheckStatus.FLAG)


if __name__ == "__main__":
    unittest.main()
