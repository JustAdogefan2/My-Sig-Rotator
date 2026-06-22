import os
import re
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


temp = tempfile.TemporaryDirectory()
os.environ["SIG_ROTATOR_DB"] = str(Path(temp.name) / "test.db")

import app


class SigRotatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.initialize_database()

    def test_password_hashes_are_salted_and_verify(self):
        first = app.hash_password("correct horse battery staple")
        second = app.hash_password("correct horse battery staple")
        self.assertNotEqual(first, second)
        self.assertTrue(app.password_matches("correct horse battery staple", first))
        self.assertFalse(app.password_matches("wrong password", first))

    def test_username_validation(self):
        self.assertTrue(app.valid_username("Max_123"))
        self.assertFalse(app.valid_username("no spaces"))
        self.assertFalse(app.valid_username("x"))

    def test_image_url_validation(self):
        self.assertTrue(app.valid_image_url("https://example.com/image.png"))
        self.assertFalse(app.valid_image_url("javascript:alert(1)"))
        self.assertFalse(app.valid_image_url("/relative.png"))

    def test_database_schema(self):
        with app.db() as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        self.assertIn("users", tables)
        self.assertIn("images", tables)

    def test_registration_save_and_redirect_flow(self):
        server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.App)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"

        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = build_opener(NoRedirect)
        try:
            register_body = urlencode(
                {"username": "flow_user", "password": "correct-horse-123"}
            ).encode()
            with self.assertRaises(HTTPError) as raised:
                opener.open(Request(base + "/register", register_body), timeout=5)
            self.assertEqual(raised.exception.code, 303)
            session_cookie = raised.exception.headers["Set-Cookie"].split(";", 1)[0]

            manage_request = Request(base + "/manage", headers={"Cookie": session_cookie})
            manage_html = opener.open(manage_request, timeout=5).read().decode()
            csrf = re.search(r'name="csrf" value="([^"]+)"', manage_html).group(1)

            image_body = urlencode(
                [
                    ("csrf", csrf),
                    ("url", "https://example.com/one.png"),
                    ("url", "https://example.com/two.png"),
                ]
            ).encode()
            save_request = Request(
                base + "/images", image_body, headers={"Cookie": session_cookie}
            )
            saved_html = opener.open(save_request, timeout=5).read().decode()
            self.assertIn("Image URLs saved.", saved_html)

            with self.assertRaises(HTTPError) as rotated:
                opener.open(base + "/r/flow_user", timeout=5)
            self.assertEqual(rotated.exception.code, 302)
            self.assertIn(
                rotated.exception.headers["Location"],
                {"https://example.com/one.png", "https://example.com/two.png"},
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
