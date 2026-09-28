import io
import unittest
from urllib.parse import urlencode

from diligenceos import webapp


def call_app(method: str, path: str, form: dict | None = None):
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
    return captured["status"], b"".join(result).decode("utf-8")


class GetFormTest(unittest.TestCase):
    def test_get_root_renders_the_form(self):
        status, body = call_app("GET", "/")
        self.assertEqual(status, "200 OK")
        self.assertIn("DiligenceOS", body)
        self.assertIn('name="name"', body)
        self.assertIn('name="registration_id"', body)
        self.assertIn('name="document_text"', body)


class PostVerdictTest(unittest.TestCase):
    def test_valid_submission_renders_the_expected_verdict(self):
        # Same subject and document as fixtures/golden/sample_request.json,
        # which the batch CLI resolves to HOLD, trust_score 70.
        status, body = call_app(
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
        status, body = call_app("POST", "/verdict", {"name": "", "registration_id": "UK09456213"})
        self.assertEqual(status, "400 Bad Request")
        self.assertIn("required", body)

    def test_script_tag_in_subject_name_is_escaped_not_executed(self):
        status, body = call_app(
            "POST",
            "/verdict",
            {"name": "<script>alert(1)</script>", "registration_id": "UK09456213"},
        )
        self.assertEqual(status, "200 OK")
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)


class NotFoundTest(unittest.TestCase):
    def test_unknown_path_is_a_404(self):
        status, _ = call_app("GET", "/nope")
        self.assertEqual(status, "404 Not Found")


if __name__ == "__main__":
    unittest.main()
