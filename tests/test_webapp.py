import io
import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from diligenceos import webapp

TEST_ADMIN_TOKEN = "test-admin-token-not-a-real-secret"
_UNSET = object()


def call_app(method: str, path: str, form: dict | None = None, *, admin_token=_UNSET):
    """`admin_token` defaults to the configured test token for a /data/* POST
    (so existing callers don't need to think about the auth gate at all) and
    to nothing otherwise. Pass `admin_token=None` or an explicit wrong value
    to exercise the gate itself."""
    form = dict(form) if form else {}
    if admin_token is _UNSET:
        admin_token = TEST_ADMIN_TOKEN if method == "POST" and path.startswith("/data/") else None
    if admin_token is not None and "admin_token" not in form:
        form["admin_token"] = admin_token
    body = urlencode(form).encode("utf-8") if form else b""
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": "application/x-www-form-urlencoded",
        "wsgi.input": io.BytesIO(body),
    }
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = headers

    result = webapp.app(environ, start_response)
    return captured["status"], dict(captured["headers"]), b"".join(result).decode("utf-8")


class WebappTestCase(unittest.TestCase):
    """Resets the module-level Store before each test, pointed at a fresh
    temp file, so additions in one test never leak into another via the
    real Store singleton or its persisted file (Slice 13) — and never
    touch the real ~/.diligenceos/store.json. Also configures a known
    DILIGENCEOS_ADMIN_TOKEN so /data/* writes (gated since 2026-10-01) work
    by default; see call_app."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._old_data_path = os.environ.get("DILIGENCEOS_DATA_PATH")
        self._old_admin_token = os.environ.get("DILIGENCEOS_ADMIN_TOKEN")
        os.environ["DILIGENCEOS_DATA_PATH"] = str(Path(self._tmpdir.name) / "store.json")
        os.environ["DILIGENCEOS_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN
        webapp._store = None

    def tearDown(self):
        for name, old in (
            ("DILIGENCEOS_DATA_PATH", self._old_data_path),
            ("DILIGENCEOS_ADMIN_TOKEN", self._old_admin_token),
        ):
            if old is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old
        webapp._store = None
        self._tmpdir.cleanup()


class MachineApiWiringTest(WebappTestCase):
    def test_v1_paths_are_served_as_json(self):
        status, headers, body = call_app("GET", "/v1/capabilities")
        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertIn('"verdicts"', body)

    def test_v1_errors_carry_reason_phrase(self):
        status, _, body = call_app("GET", "/v1/nope")
        self.assertEqual(status, "404 Not Found")
        self.assertIn("not_found", body)


class GetFormTest(WebappTestCase):
    def test_get_root_renders_the_form(self):
        status, _, body = call_app("GET", "/")
        self.assertEqual(status, "200 OK")
        self.assertIn("DiligenceOS", body)
        self.assertIn('name="name"', body)
        self.assertIn('name="registration_id"', body)
        self.assertIn('name="document_text"', body)


class PostVerdictTest(WebappTestCase):
    def test_valid_submission_renders_the_expected_verdict(self):
        # Same subject and document as fixtures/golden/sample_request.json,
        # which the batch CLI resolves to HOLD, trust_score 70.
        status, _, body = call_app(
            "POST",
            "/verdict",
            {
                "name": "Meridian Robotics Ltd.",
                "registration_id": "UK09456213",
                "document_text": (
                    "Section 3: Termination. Either party may terminate with 30 days "
                    "notice. Section 4: Liability Cap. Total liability is capped at the "
                    "contract value."
                ),
            },
        )
        self.assertEqual(status, "200 OK")
        self.assertIn("HOLD", body)
        self.assertIn("trust score 70", body)
        self.assertIn("document_scan", body)
        self.assertIn("indemnification", body)

    def test_missing_required_field_is_a_400(self):
        status, _, body = call_app("POST", "/verdict", {"name": "", "registration_id": "UK09456213"})
        self.assertEqual(status, "400 Bad Request")
        self.assertIn("required", body)

    def test_script_tag_in_subject_name_is_escaped_not_executed(self):
        status, _, body = call_app(
            "POST",
            "/verdict",
            {"name": "<script>alert(1)</script>", "registration_id": "UK09456213"},
        )
        self.assertEqual(status, "200 OK")
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)


class GetDataTest(WebappTestCase):
    def test_lists_the_seeded_sample_data(self):
        status, _, body = call_app("GET", "/data")
        self.assertEqual(status, "200 OK")
        self.assertIn("Sanctions list", body)
        self.assertIn("Registry", body)
        self.assertIn("Delivery records", body)
        self.assertIn("Meridian Robotics Ltd.", body)  # seeded registry entry


class AddSanctionsEntryTest(WebappTestCase):
    def test_add_redirects_to_data(self):
        status, headers, _ = call_app(
            "POST", "/data/sanctions", {"name": "Nova Freight Co.", "program": "TEST", "aliases": "Nova, NFC"}
        )
        self.assertEqual(status, "302 Found")
        self.assertEqual(headers["Location"], "/data")

    def test_added_entry_appears_on_data_page(self):
        call_app("POST", "/data/sanctions", {"name": "Nova Freight Co.", "program": "TEST", "aliases": "Nova"})
        _, _, body = call_app("GET", "/data")
        self.assertIn("Nova Freight Co.", body)
        self.assertIn("Nova", body)

    def test_added_entry_is_checkable_immediately(self):
        call_app("POST", "/data/sanctions", {"name": "Nova Freight Co.", "program": "TEST", "aliases": ""})
        _, _, body = call_app(
            "POST", "/verdict", {"name": "Nova Freight Co.", "registration_id": "DOES-NOT-EXIST"}
        )
        self.assertIn("RED_FLAG", body)
        self.assertIn("sanctions", body)

    def test_missing_field_is_a_400_and_does_not_add(self):
        status, _, body = call_app("POST", "/data/sanctions", {"name": "", "program": "TEST"})
        self.assertEqual(status, "400 Bad Request")
        self.assertIn("required", body)

    def test_name_is_escaped_on_data_page(self):
        call_app("POST", "/data/sanctions", {"name": "<script>alert(1)</script>", "program": "TEST"})
        _, _, body = call_app("GET", "/data")
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)


class AddRegistryRecordTest(WebappTestCase):
    def test_added_record_is_checkable_immediately(self):
        call_app(
            "POST",
            "/data/registry",
            {"registration_id": "US999", "name": "Newco Ltd.", "status": "active", "jurisdiction": "US"},
        )
        _, _, body = call_app("POST", "/verdict", {"name": "Newco Ltd.", "registration_id": "US999"})
        self.assertIn("PROCEED", body)

    def test_missing_field_is_a_400(self):
        status, _, _ = call_app("POST", "/data/registry", {"registration_id": "", "name": "Newco Ltd."})
        self.assertEqual(status, "400 Bad Request")


class AddDeliveryRecordTest(WebappTestCase):
    def test_added_records_are_reflected_in_a_later_check(self):
        for _ in range(3):
            call_app("POST", "/data/delivery", {"subject": "Slow Co.", "note": "late"})
        call_app(
            "POST",
            "/data/registry",
            {"registration_id": "GB1", "name": "Slow Co.", "status": "active"},
        )
        _, _, body = call_app("POST", "/verdict", {"name": "Slow Co.", "registration_id": "GB1"})
        self.assertIn("HOLD", body)
        self.assertIn("track_record", body)

    def test_missing_subject_is_a_400(self):
        status, _, _ = call_app("POST", "/data/delivery", {"subject": ""})
        self.assertEqual(status, "400 Bad Request")


class NotFoundTest(WebappTestCase):
    def test_unknown_path_is_a_404(self):
        status, _, _ = call_app("GET", "/nope")
        self.assertEqual(status, "404 Not Found")


class DataWriteAuthTest(WebappTestCase):
    """/data/* writes are gated behind DILIGENCEOS_ADMIN_TOKEN, fixed 2026-10-01
    (these routes directly rewrite the dataset verdicts are checked against
    and had no auth at all). See docs/decisions.md."""

    _FORMS = {
        "/data/sanctions": {"name": "Shadow Corp", "program": "TEST"},
        "/data/registry": {"registration_id": "ZZ1", "name": "Shadow Corp"},
        "/data/delivery": {"subject": "Shadow Corp"},
    }

    def test_refused_when_no_admin_token_is_configured(self):
        os.environ.pop("DILIGENCEOS_ADMIN_TOKEN", None)
        for path, form in self._FORMS.items():
            status, _, body = call_app("POST", path, form, admin_token=None)
            self.assertEqual(status, "401 Unauthorized", path)
            self.assertIn("disabled", body)
        _, _, data_page = call_app("GET", "/data")
        self.assertNotIn("Shadow Corp", data_page)

    def test_refused_with_the_wrong_token(self):
        for path, form in self._FORMS.items():
            status, _, _ = call_app("POST", path, form, admin_token="not-the-real-token")
            self.assertEqual(status, "401 Unauthorized", path)
        _, _, data_page = call_app("GET", "/data")
        self.assertNotIn("Shadow Corp", data_page)

    def test_succeeds_with_the_configured_token(self):
        for path, form in self._FORMS.items():
            status, _, _ = call_app("POST", path, form)  # call_app auto-fills the right token
            self.assertIn(status, ("200 OK", "302 Found"), path)
        _, _, data_page = call_app("GET", "/data")
        self.assertIn("Shadow Corp", data_page)


if __name__ == "__main__":
    unittest.main()
