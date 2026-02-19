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

    def login(self, username, password):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body=f"username={username}&password={password}")
        self.assertEqual(dict(login["headers"]).get("Location"), "/")
        return merge_cookies(cookie, login["headers"])

    def test_login_required_redirects_to_login(self):
        response = call_app(self.app, method="GET", path="/")
        self.assertTrue(response["status"].startswith("302"))
        self.assertEqual(dict(response["headers"]).get("Location"), "/login")

    def test_non_employer_can_create_employer_from_onboarding_form(self):
        cookie = self.login("alex", "password123")
        form = (
            "legal_name=Acme+Health&contact_name=Jamie+Lee&work_email=jamie%40acme.com"
            "&phone=555-111-0000&company_size=25-49&industry=Healthcare"
            "&website=https%3A%2F%2Facme.com&state=CA"
        )
        create = call_app(self.app, method="POST", path="/employers/create", body=form, cookie_header=cookie)
        self.assertEqual(dict(create["headers"]).get("Location"), "/")

        db = self.app.db()
        employer = db.execute("SELECT * FROM employers WHERE legal_name = 'Acme Health'").fetchone()
        self.assertIsNotNone(employer)
        linked = db.execute("SELECT * FROM users WHERE id = ?", (employer["linked_user_id"],)).fetchone()
        self.assertEqual(linked["role"], "employer")
        db.close()

    def test_employer_accounts_are_read_only_and_cannot_create(self):
        creator_cookie = self.login("alex", "password123")
        create = call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=North+Star&contact_name=Ari+B&work_email=ari%40northstar.com&phone=555"
                "&company_size=1-24&industry=Tech&website=https%3A%2F%2Fnorthstar.com&state=WA"
            ),
            cookie_header=creator_cookie,
        )
        creator_cookie = merge_cookies(creator_cookie, create["headers"])

        db = self.app.db()
        employer_user = db.execute("SELECT username FROM users WHERE role = 'employer' LIMIT 1").fetchone()
        db.close()
        employer_cookie = self.login(employer_user["username"], "employer123")

        forbidden = call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Should+Fail&contact_name=Nope&work_email=nope%40x.com&phone=555"
                "&company_size=1-24&industry=Nope&website=https%3A%2F%2Fx.com&state=OR"
            ),
            cookie_header=employer_cookie,
        )
        self.assertEqual(dict(forbidden["headers"]).get("Location"), "/")

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=employer_cookie)
        self.assertIn("read-only", dashboard["body"])
        self.assertNotIn("Employer onboarding form", dashboard["body"])

    def test_employer_visibility_is_limited_to_creator_scope(self):
        alex_cookie = self.login("alex", "password123")
        sam_cookie = self.login("sam", "password123")

        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Atlas+One&contact_name=A1&work_email=a1%40atlas.com&phone=555"
                "&company_size=1-24&industry=Tech&website=https%3A%2F%2Fatlas.com&state=CA"
            ),
            cookie_header=alex_cookie,
        )
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Beta+Care&contact_name=B1&work_email=b1%40beta.com&phone=555"
                "&company_size=25-49&industry=Medical&website=https%3A%2F%2Fbeta.com&state=TX"
            ),
            cookie_header=sam_cookie,
        )

        db = self.app.db()
        employer_user = db.execute(
            "SELECT username FROM users WHERE role = 'employer' AND created_by_user_id = (SELECT id FROM users WHERE username='alex') LIMIT 1"
        ).fetchone()
        db.close()

        employer_cookie = self.login(employer_user["username"], "employer123")
        dashboard = call_app(self.app, method="GET", path="/", cookie_header=employer_cookie)

        self.assertIn("Atlas One", dashboard["body"])
        self.assertNotIn("Beta Care", dashboard["body"])


if __name__ == "__main__":
    unittest.main()
