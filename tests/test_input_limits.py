"""Round 5 of the overnight review: the web app reads a request body only when its declared size
is sane, and a malformed body is a 4xx, never an exception or a wait for the peer to hang up."""

import io
import json
import unittest

from diligenceos import api, webapp
from test_webapp import WebappTestCase


class SpyInput(io.BytesIO):
    """Records every read size: read(-1) on a real socket waits for the client to close."""

    def __init__(self, data=b""):
        super().__init__(data)
        self.asked = []

    def read(self, n=-1):
        self.asked.append(n)
        return super().read(n)


def post(path, body=b"", *, length=None, method="POST"):
    spy = SpyInput(body)
    environ = {
        "REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": "",
        "CONTENT_LENGTH": str(len(body)) if length is None else str(length),
        "CONTENT_TYPE": "application/x-www-form-urlencoded", "wsgi.input": spy,
    }
    seen = {}
    page = webapp.app(environ, lambda status, headers: seen.update(status=status))
    return seen["status"], b"".join(page), spy.asked


class BodySizeTest(WebappTestCase):
    FORM = b"name=Acme&registration_id=R1"

    def test_an_oversize_form_is_refused_unread(self):
        for path in ("/verdict", "/data/sanctions", "/data/registry", "/data/delivery"):
            status, _, asked = post(path, self.FORM, length=200_000_000)
            self.assertTrue(status.startswith("413"), (path, status))
            self.assertEqual(asked, [], f"{path} must not read a body it will refuse")

    def test_an_oversize_api_body_is_refused_unread(self):
        status, body, asked = post("/v1/verdict", b"{}", length=200_000_000)
        self.assertTrue(status.startswith("413"), status)
        self.assertEqual(json.loads(body)["error"]["code"], "body_too_large")
        self.assertEqual(asked, [])

    def test_the_limit_itself_is_allowed_and_one_over_is_not(self):
        pad = b"x=" + b"a" * (api.MAX_BODY_BYTES - 2)
        self.assertEqual(len(pad), api.MAX_BODY_BYTES)
        self.assertTrue(post("/verdict", pad)[0].startswith("400"))      # read in full, then refused for missing fields
        self.assertTrue(post("/verdict", pad + b"a")[0].startswith("413"))

    def test_a_negative_or_non_numeric_length_never_reaches_read(self):
        for path in ("/verdict", "/data/sanctions", "/v1/verdict", "/v1/verify"):
            for length in ("-1", "-5", "abc", "1e3", "0x10", "١٢", " -1", "+5", "5.0"):
                status, _, asked = post(path, self.FORM, length=length)
                self.assertTrue(status.startswith("400"), (path, length, status))
                self.assertEqual(asked, [], (path, length))

    def test_a_missing_or_zero_length_is_just_an_empty_body(self):
        status, _, _ = post("/verdict", b"", length=0)
        self.assertTrue(status.startswith("400"))
        self.assertTrue(post("/v1/verdict", b"", length=0)[0].startswith("400"))

    def test_invalid_utf8_in_a_form_is_a_400_not_an_exception(self):
        for path in ("/verdict", "/data/sanctions"):
            status, body, _ = post(path, b"name=\xff\xfe&registration_id=b")
            self.assertTrue(status.startswith("400"), (path, status))
            self.assertNotIn(b"Traceback", body)

    def test_a_form_with_absurdly_many_fields_is_refused(self):
        junk = b"&".join(b"k%d=v" % i for i in range(5000))
        status, _, _ = post("/verdict", self.FORM + b"&" + junk)       # a valid form plus 5000 extra fields
        self.assertTrue(status.startswith("400"), status)

    def test_ordinary_requests_still_work(self):
        self.assertTrue(post("/verdict", self.FORM)[0].startswith("200"))
        status, body, _ = post("/v1/verdict", json.dumps({"subject": {"name": "A", "registration_id": "R"}}).encode())
        self.assertTrue(status.startswith("200"), body)


class WitnessReadsBoundedRepliesTest(unittest.TestCase):
    """The witness is the party that distrusts the server, so the server cannot choose how much it buffers."""

    class Reply:
        def __init__(self, payload):
            self.payload, self.asked = payload, []

        def read(self, n=-1):
            self.asked.append(n)
            return self.payload if n < 0 else self.payload[:n]

    def test_a_reply_over_the_limit_is_refused_after_reading_only_the_limit(self):
        from diligenceos import tools
        reply = self.Reply(b'{"entries": [' + b"0," * (tools.MAX_RESPONSE_BYTES // 2 + 10) + b"0]}")
        with self.assertRaises(ValueError):
            tools._json_from_response(reply)
        self.assertEqual(reply.asked, [tools.MAX_RESPONSE_BYTES + 1])

    def test_an_ordinary_reply_parses(self):
        from diligenceos import tools
        self.assertEqual(tools._json_from_response(self.Reply(b'{"a": [1, 2]}')), {"a": [1, 2]})

    def test_a_reply_that_is_not_utf8_or_not_json_is_a_value_error(self):
        from diligenceos import tools
        for payload in (b"\xff\xfe", b"not json", b""):
            with self.assertRaises(ValueError):
                tools._json_from_response(self.Reply(payload))


if __name__ == "__main__":
    unittest.main()
