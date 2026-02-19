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
        self.assertEqual(dict(response["headers"]).get("Location"), "/login")

    def test_regular_user_can_update_username_and_password(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=password123")
        cookie = merge_cookies(cookie, login["headers"])

        update = call_app(
            self.app,
            method="POST",
            path="/settings/profile",
            body="username=alex2&password=betterpw",
            cookie_header=cookie,
        )
        self.assertEqual(dict(update["headers"]).get("Location"), "/")

        relogin = call_app(self.app, method="POST", path="/login", body="username=alex2&password=betterpw")
        self.assertEqual(dict(relogin["headers"]).get("Location"), "/")

    def test_regular_user_can_customize_dashboard_style(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=sam&password=password123")
        cookie = merge_cookies(cookie, login["headers"])

        style = call_app(
            self.app,
            method="POST",
            path="/settings/style",
            body="theme=midnight&density=compact",
            cookie_header=cookie,
        )
        cookie = merge_cookies(cookie, style["headers"])

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie)
        self.assertIn("theme-midnight", dashboard["body"])
        self.assertIn("density-compact", dashboard["body"])

    def test_super_admin_can_create_and_modify_users(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=admin&password=admin123")
        cookie = merge_cookies(cookie, login["headers"])

        create = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=river&password=riverpass&role=user",
            cookie_header=cookie,
        )
        self.assertEqual(dict(create["headers"]).get("Location"), "/")

        users = self.app.get_users_with_completion()
        river = next(u for u in users if u["username"] == "river")

        update = call_app(
            self.app,
            method="POST",
            path="/admin/users/update",
            body=f"user_id={river['id']}&username=river2&role=super_admin&password=",
            cookie_header=cookie,
        )
        self.assertEqual(dict(update["headers"]).get("Location"), "/")

        relogin = call_app(self.app, method="POST", path="/login", body="username=river2&password=riverpass")
        self.assertEqual(dict(relogin["headers"]).get("Location"), "/")

    def test_regular_user_cannot_create_or_modify_users(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=password123")
        cookie = merge_cookies(cookie, login["headers"])

        create = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=hacker&password=hackerpw&role=user",
            cookie_header=cookie,
        )
        cookie = merge_cookies(cookie, create["headers"])
        self.assertEqual(dict(create["headers"]).get("Location"), "/")

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie)
        self.assertNotIn("hacker", dashboard["body"])
        self.assertIn("Team Completion Status", dashboard["body"])

    def test_login_session_cookie_allows_immediate_dashboard_access(self):
        cookie = ""

        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=password123")
        self.assertTrue(login["status"].startswith("302"))
        self.assertEqual(dict(login["headers"]).get("Location"), "/")
        cookie = merge_cookies(cookie, login["headers"])

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie)
        self.assertTrue(dashboard["status"].startswith("200"))
        self.assertIn("Welcome, Alex", dashboard["body"])

    def test_non_employer_can_create_employer_from_onboarding_form(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=password123")
        cookie = merge_cookies(cookie, login["headers"])

        create = call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Acme+Health&contact_name=Jamie+Lee&work_email=jamie%40acme.com"
                "&phone=555-111-0000&company_size=25-49&industry=Healthcare"
                "&website=https%3A%2F%2Facme.com&state=CA"
            ),
            cookie_header=cookie,
        )
        self.assertEqual(dict(create["headers"]).get("Location"), "/")

        db = self.app.db()
        employer = db.execute("SELECT * FROM employers WHERE legal_name = 'Acme Health'").fetchone()
        self.assertIsNotNone(employer)
        linked = db.execute("SELECT * FROM users WHERE id = ?", (employer["linked_user_id"],)).fetchone()
        self.assertEqual(linked["role"], "employer")
        db.close()

    def test_employer_accounts_are_read_only_and_hidden_from_admin_features(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=password123")
        cookie = merge_cookies(cookie, login["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=North+Star&contact_name=Ari+B&work_email=ari%40northstar.com&phone=555"
                "&company_size=1-24&industry=Tech&website=https%3A%2F%2Fnorthstar.com&state=WA"
            ),
            cookie_header=cookie,
        )

        db = self.app.db()
        employer_user = db.execute("SELECT username FROM users WHERE role = 'employer' LIMIT 1").fetchone()
        db.close()

        employer_cookie = ""
        employer_login = call_app(
            self.app,
            method="POST",
            path="/login",
            body=f"username={employer_user['username']}&password=employer123",
        )
        employer_cookie = merge_cookies(employer_cookie, employer_login["headers"])

        forbidden = call_app(
            self.app,
            method="POST",
            path="/settings/profile",
            body="username=shouldfail&password=123456",
            cookie_header=employer_cookie,
        )
        self.assertEqual(dict(forbidden["headers"]).get("Location"), "/")

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=employer_cookie)
        self.assertNotIn("User Settings", dashboard["body"])
        self.assertNotIn("Super Admin · User Management", dashboard["body"])
        self.assertIn("Employers", dashboard["body"])

    def test_employer_visibility_is_limited_to_creator_scope(self):
        alex_cookie = ""
        sam_cookie = ""
        alex_cookie = merge_cookies(alex_cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=password123")["headers"])
        sam_cookie = merge_cookies(sam_cookie, call_app(self.app, method="POST", path="/login", body="username=sam&password=password123")["headers"])

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

        employer_cookie = ""
        employer_cookie = merge_cookies(
            employer_cookie,
            call_app(
                self.app,
                method="POST",
                path="/login",
                body=f"username={employer_user['username']}&password=employer123",
            )["headers"],
        )
        dashboard = call_app(self.app, method="GET", path="/", cookie_header=employer_cookie)

        self.assertIn("Atlas One", dashboard["body"])
        self.assertNotIn("Beta Care", dashboard["body"])


if __name__ == "__main__":
    unittest.main()
