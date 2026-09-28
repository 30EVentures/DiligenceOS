import unittest
from pathlib import Path

from diligenceos.sanctions import screen_subject
from diligenceos.sdn_ingest import fetch_sdn_list, parse_sdn_csv
from diligenceos.types import CheckStatus

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "golden" / "sdn_sample.csv"


class ParseSdnCsvTest(unittest.TestCase):
    def setUp(self):
        self.sanctions_list = parse_sdn_csv(FIXTURE)

    def test_parses_all_rows(self):
        self.assertEqual(len(self.sanctions_list.entries), 3)

    def test_extracts_single_alias(self):
        entry = next(e for e in self.sanctions_list.entries if e.name == "HARBORLINE EXPORTS LTD")
        self.assertEqual(entry.aliases, ("HARBORLINE TRADING",))

    def test_extracts_multiple_aliases(self):
        entry = next(e for e in self.sanctions_list.entries if e.name == "REDLINE MARITIME CO")
        self.assertEqual(entry.aliases, ("REDLINE SHIPPING", "RL MARITIME"))

    def test_row_with_no_aka_has_no_aliases(self):
        entry = next(e for e in self.sanctions_list.entries if e.name == "PIETRA VOSS")
        self.assertEqual(entry.aliases, ())

    def test_parsed_list_feeds_screen_subject(self):
        finding = screen_subject("RL MARITIME", self.sanctions_list)
        self.assertEqual(finding.status, CheckStatus.FLAG)
        self.assertIn("REDLINE MARITIME CO", finding.detail)


class FetchSdnListTest(unittest.TestCase):
    def test_is_importable_but_not_called_here(self):
        self.assertTrue(callable(fetch_sdn_list))


if __name__ == "__main__":
    unittest.main()
