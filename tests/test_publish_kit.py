"""The kit is files on disk for a person to host. Making it publishes nothing, creates no key, and puts no secret in it."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from diligenceos import publish_kit, tools
from diligenceos.signing import Signer

ROOT = Path(__file__).resolve().parent.parent
CHARTER = (ROOT / "docs" / "flashy" / "mesh" / "flashyos-charter.draft.json").read_text(encoding="utf-8")
PROFILE, API = "https://diligenceos.example.org", "https://api.diligenceos.example.org"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = tools.main(list(argv))
        except SystemExit as stop:
            code = stop.code
    return code, out.getvalue(), err.getvalue()


class TheKitSaysWhoYouAreAndHowToCheck(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.signer = Signer.load_or_create(self.dir / "issuer.key")
        self.out = self.dir / "kit"

    def tearDown(self):
        self._tmp.cleanup()

    def build(self, **kw):
        kw.setdefault("profile_url", PROFILE)
        kw.setdefault("api_url", API)
        return publish_kit.build_kit(self.out, self.signer, charter_text=CHARTER, **kw)

    def test_it_writes_exactly_these_files(self):
        self.build()
        names = sorted(str(p.relative_to(self.out)) for p in self.out.rglob("*") if p.is_file())
        self.assertEqual(names, [".well-known/diligenceos-issuer.json", ".well-known/flashyos-charter.json", ".well-known/flashyos.json", "PUBLISHING.txt"])

    def test_the_handshake_names_the_org_and_declares_no_capability(self):
        self.build()
        hs = json.loads((self.out / ".well-known" / "flashyos.json").read_text())
        self.assertEqual(hs, {"mesh": "flashyos/1", "org": {"slug": "diligenceos", "name": "DiligenceOS", "profile": PROFILE}})
        self.assertNotIn("capabilities", hs)

    def test_the_charter_is_copied_byte_for_byte(self):
        self.build()
        self.assertEqual((self.out / ".well-known" / "flashyos-charter.json").read_text(encoding="utf-8"), CHARTER)

    def test_the_issuer_statement_names_the_key_and_where_to_verify(self):
        self.build()
        doc = json.loads((self.out / ".well-known" / "diligenceos-issuer.json").read_text())
        self.assertEqual((doc["issuer"], doc["algorithm"], doc["manifest"]), (self.signer.issuer_id, "ed25519", API + "/v1/manifest"))
        self.assertIn("pin", doc["statement"].lower())
        self.assertTrue(publish_kit.verify_issuer_statement(doc, self.signer.issuer_id))

    def test_the_statement_is_a_claim_by_the_key_not_proof_of_who_holds_it(self):
        self.build()
        doc = json.loads((self.out / ".well-known" / "diligenceos-issuer.json").read_text())
        self.assertIn("does not by itself", doc["statement"])

    def test_nothing_secret_is_in_any_file(self):
        self.build()
        secret = (self.dir / "issuer.key").read_text().strip()
        for p in self.out.rglob("*"):
            if p.is_file():
                self.assertNotIn(secret, p.read_text(encoding="utf-8"), p.name)

    def test_the_instructions_say_nothing_has_been_published(self):
        self.build()
        text = (self.out / "PUBLISHING.txt").read_text()
        self.assertIn("NOT been published", text)
        self.assertIn("/.well-known/flashyos.json", text)


class AnEditedStatementOrTheWrongKeyIsNotAccepted(unittest.TestCase):
    def setUp(self):
        self.signer = Signer.generate()
        self._tmp = tempfile.TemporaryDirectory()
        publish_kit.build_kit(Path(self._tmp.name) / "k", self.signer, charter_text=CHARTER, profile_url=PROFILE, api_url=API)
        self.doc = json.loads((Path(self._tmp.name) / "k" / ".well-known" / "diligenceos-issuer.json").read_text())

    def tearDown(self):
        self._tmp.cleanup()

    def test_every_field_is_covered(self):
        for field, value in self.doc.items():
            if field == "signature":
                continue
            self.assertFalse(publish_kit.verify_issuer_statement({**self.doc, field: "x" if value != "x" else "y"}, self.signer.issuer_id), field)

    def test_other_keys_extra_or_missing_fields_and_junk(self):
        self.assertFalse(publish_kit.verify_issuer_statement(self.doc, Signer.generate().issuer_id))
        self.assertFalse(publish_kit.verify_issuer_statement({**self.doc, "extra": 1}, self.signer.issuer_id))
        self.assertFalse(publish_kit.verify_issuer_statement({k: v for k, v in self.doc.items() if k != "manifest"}, self.signer.issuer_id))
        for junk in (None, [], "x", 5, {}):
            self.assertFalse(publish_kit.verify_issuer_statement(junk, self.signer.issuer_id))


class TheKitRefusesToDoAnythingSurprising(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.signer = Signer.load_or_create(self.dir / "issuer.key")

    def tearDown(self):
        self._tmp.cleanup()

    def test_urls_must_be_https_without_credentials(self):
        for bad in ("http://example.org", "ftp://example.org", "https://u:p@example.org", "https://", "example.org", "", None, 5, "https://example.org/?x=1", "https://example.org#f"):
            for field in ("profile_url", "api_url"):
                kw = {"profile_url": PROFILE, "api_url": API, field: bad}
                with self.assertRaises(ValueError, msg=(field, bad)):
                    publish_kit.build_kit(self.dir / "kit", self.signer, charter_text=CHARTER, **kw)
        self.assertFalse((self.dir / "kit").exists())

    def test_an_existing_non_empty_directory_is_never_overwritten(self):
        (self.dir / "kit").mkdir()
        (self.dir / "kit" / "keep.txt").write_text("mine")
        with self.assertRaises(FileExistsError):
            publish_kit.build_kit(self.dir / "kit", self.signer, charter_text=CHARTER, profile_url=PROFILE, api_url=API)
        self.assertEqual((self.dir / "kit" / "keep.txt").read_text(), "mine")

    def test_a_charter_that_is_not_json_is_refused(self):
        for bad in ("", "not json", "[]", "null"):
            with self.assertRaises(ValueError):
                publish_kit.build_kit(self.dir / "kit", self.signer, charter_text=bad, profile_url=PROFILE, api_url=API)
            self.assertFalse((self.dir / "kit").exists())


class TheCommand(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_it_makes_the_kit_from_an_existing_key(self):
        signer = Signer.load_or_create(self.dir / "issuer.key")
        code, out, _ = run("publish-kit", "--key", str(self.dir / "issuer.key"), "--out", str(self.dir / "kit"), "--profile-url", PROFILE, "--api-url", API)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["issuer"], signer.issuer_id)
        self.assertTrue((self.dir / "kit" / ".well-known" / "flashyos.json").exists())

    def test_it_never_creates_a_key(self):
        code, out, err = run("publish-kit", "--key", str(self.dir / "nope.key"), "--out", str(self.dir / "kit"), "--profile-url", PROFILE, "--api-url", API)
        self.assertEqual(code, 2)
        self.assertFalse((self.dir / "nope.key").exists())
        self.assertFalse((self.dir / "kit").exists())

    def test_bad_arguments_are_exit_2_and_write_nothing(self):
        Signer.load_or_create(self.dir / "issuer.key")
        for extra in (["--profile-url", "http://x.org", "--api-url", API], ["--profile-url", PROFILE, "--api-url", "nope"], ["--profile-url", PROFILE]):
            code, _, _ = run("publish-kit", "--key", str(self.dir / "issuer.key"), "--out", str(self.dir / "kit"), *extra)
            self.assertEqual(code, 2, extra)
            self.assertFalse((self.dir / "kit").exists())


if __name__ == "__main__":
    unittest.main()
