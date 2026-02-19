import io
from http import cookies
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from wsgiref.util import setup_testing_defaults

from app import TaskTrackerApp


def call_app(app, method="GET", path="/", body="", cookie_header=""):
    environ = {}
    setup_testing_defaults(environ)
    environ["REQUEST_METHOD"] = method
    environ["PATH_INFO"] = path
    data = body.encode("utf-8")
    environ["CONTENT_LENGTH"] = str(len(data))
    environ["wsgi.input"] = io.BytesIO(data)
    environ["CONTENT_TYPE"] = "application/x-www-form-urlencoded"
    if cookie_header:
        environ["HTTP_COOKIE"] = cookie_header

    result = {}

    def start_response(status, headers):
        result["status"] = status
        result["headers"] = headers

    chunks = app(environ, start_response)
    result["body"] = b"".join(chunks).decode("utf-8")
    return result


def merge_cookies(old_cookie_header, response_headers):
    jar = cookies.SimpleCookie()
    if old_cookie_header:
        jar.load(old_cookie_header)
    for header, value in response_headers:
        if header.lower() == "set-cookie":
            jar.load(value)
    return "; ".join(f"{k}={m.coded_value}" for k, m in jar.items() if m.value)


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "test.db")
        self.app = TaskTrackerApp(db_path=self.db_path, secret_key="test-secret")

    def tearDown(self):
        self.tmp.cleanup()

    def test_login_required_redirects_to_login(self):
        response = call_app(self.app, method="GET", path="/")
        self.assertTrue(response["status"].startswith("302"))
        headers = dict(response["headers"])
        self.assertEqual(headers.get("Location"), "/login")


    def test_login_works_without_content_length_header(self):
        environ = {}
        setup_testing_defaults(environ)
        body = b"username=alex&password=password123"
        environ["REQUEST_METHOD"] = "POST"
        environ["PATH_INFO"] = "/login"
        environ["wsgi.input"] = io.BytesIO(body)
        environ["CONTENT_TYPE"] = "application/x-www-form-urlencoded"
        environ["CONTENT_LENGTH"] = ""

        result = {}

        def start_response(status, headers):
            result["status"] = status
            result["headers"] = headers

        chunks = self.app(environ, start_response)
        result["body"] = b"".join(chunks).decode("utf-8")

        self.assertTrue(result["status"].startswith("302"))
        headers = dict(result["headers"])
        self.assertEqual(headers.get("Location"), "/")

    def test_login_session_cookie_allows_immediate_dashboard_access(self):
        cookie = ""

        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=password123")
        self.assertTrue(login["status"].startswith("302"))
        self.assertEqual(dict(login["headers"]).get("Location"), "/")
        cookie = merge_cookies(cookie, login["headers"])

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie)
        self.assertTrue(dashboard["status"].startswith("200"))
        self.assertIn("Welcome, Alex", dashboard["body"])

    def test_dashboard_access_with_session_and_flash_cookies(self):
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=password123")
        self.assertTrue(login["status"].startswith("302"))

        set_cookie_values = [value for header, value in login["headers"] if header.lower() == "set-cookie"]
        self.assertGreaterEqual(len(set_cookie_values), 2)

        cookie_pairs = []
        for header_value in set_cookie_values:
            cookie_pairs.append(header_value.split(";", 1)[0])

        cookie_header = "; ".join(cookie_pairs)
        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie_header)

        self.assertTrue(dashboard["status"].startswith("200"))
        self.assertIn("Welcome, Alex", dashboard["body"])

    def test_two_users_see_shared_task_completion(self):
        alex_cookie = ""
        sam_cookie = ""

        response = call_app(
            self.app,
            method="POST",
            path="/login",
            body="username=alex&password=password123",
        )
        alex_cookie = merge_cookies(alex_cookie, response["headers"])

        response = call_app(
            self.app,
            method="POST",
            path="/login",
            body="username=sam&password=password123",
        )
        sam_cookie = merge_cookies(sam_cookie, response["headers"])

        response = call_app(self.app, method="POST", path="/task/complete", cookie_header=alex_cookie)
        alex_cookie = merge_cookies(alex_cookie, response["headers"])

        sam_dashboard = call_app(self.app, method="GET", path="/", cookie_header=sam_cookie)
        self.assertIn("Alex", sam_dashboard["body"])
        self.assertIn("Sam", sam_dashboard["body"])
        self.assertEqual(sam_dashboard["body"].count("Completed"), 1)

        response = call_app(self.app, method="POST", path="/task/complete", cookie_header=sam_cookie)
        sam_cookie = merge_cookies(sam_cookie, response["headers"])

        alex_dashboard = call_app(self.app, method="GET", path="/", cookie_header=alex_cookie)
        self.assertEqual(alex_dashboard["body"].count("Completed"), 2)

    def test_logout_clears_session_and_allows_relogin(self):
        cookie = ""

        login = call_app(self.app, method="POST", path="/login", body="username=sam&password=password123")
        cookie = merge_cookies(cookie, login["headers"])

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie)
        self.assertTrue(dashboard["status"].startswith("200"))
        self.assertIn("Welcome, Sam", dashboard["body"])

        logout = call_app(self.app, method="POST", path="/logout", cookie_header=cookie)
        cookie = merge_cookies(cookie, logout["headers"])

        redirected = call_app(self.app, method="GET", path="/", cookie_header=cookie)
        self.assertTrue(redirected["status"].startswith("302"))
        self.assertEqual(dict(redirected["headers"]).get("Location"), "/login")

        relogin = call_app(self.app, method="POST", path="/login", body="username=sam&password=password123", cookie_header=cookie)
        self.assertTrue(relogin["status"].startswith("302"))
        self.assertEqual(dict(relogin["headers"]).get("Location"), "/")


if __name__ == "__main__":
    unittest.main()
