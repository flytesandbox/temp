import io
from http import cookies
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from wsgiref.util import setup_testing_defaults

from app import TaskTrackerApp


def call_app(app, method="GET", path="/", body="", cookie_header="", query_string=""):
    environ = {}
    setup_testing_defaults(environ)
    environ["REQUEST_METHOD"] = method
    environ["PATH_INFO"] = path
    environ["QUERY_STRING"] = query_string
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


    def test_app_boots_with_fresh_database(self):
        app = TaskTrackerApp(db_path=str(Path(self.tmp.name) / "fresh.db"), secret_key="test-secret")
        self.assertIsNotNone(app)

        db = app.db()
        default_team = db.execute("SELECT id FROM teams WHERE name = 'Core Admin Team' LIMIT 1").fetchone()
        db.close()

        self.assertIsNotNone(default_team)

    def test_app_boots_with_existing_default_team_row(self):
        existing_db = Path(self.tmp.name) / "existing.db"
        app = TaskTrackerApp(db_path=str(existing_db), secret_key="test-secret")

        db = app.db()
        db.execute("DELETE FROM teams")
        db.execute("INSERT INTO teams (name, created_by_user_id) VALUES (?, ?)", ("Core Admin Team", 1))
        db.commit()
        db.close()

        restarted_app = TaskTrackerApp(db_path=str(existing_db), secret_key="test-secret")
        self.assertIsNotNone(restarted_app)

        check_db = restarted_app.db()
        default_team = check_db.execute("SELECT id FROM teams WHERE name = 'Core Admin Team' LIMIT 1").fetchone()
        check_db.close()

        self.assertIsNotNone(default_team)

    def test_dev_log_tab_is_visible_and_lists_pr_history(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=user")
        cookie = merge_cookies(cookie, login["headers"])

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie, query_string="view=devlog")
        self.assertIn("Dev Log", dashboard["body"])
        self.assertIn("Development Log", dashboard["body"])
        self.assertIn("PR #1", dashboard["body"])
        self.assertIn("PR #30", dashboard["body"])
    def test_login_required_redirects_to_login(self):
        response = call_app(self.app, method="GET", path="/")
        self.assertTrue(response["status"].startswith("302"))
        self.assertEqual(dict(response["headers"]).get("Location"), "/login")

    def test_admin_user_can_update_username_and_password(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=user")
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

    def test_admin_user_can_customize_dashboard_style(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=sam&password=user")
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
        login = call_app(self.app, method="POST", path="/login", body="username=admin&password=user")
        cookie = merge_cookies(cookie, login["headers"])

        create = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=river&password=user&role=admin",
            cookie_header=cookie,
        )
        self.assertEqual(dict(create["headers"]).get("Location"), "/")

        users = self.app.get_users_with_completion()
        river = next(u for u in users if u["username"] == "river")

        update = call_app(
            self.app,
            method="POST",
            path="/admin/users/update",
            body=f"user_id={river['id']}&username=river2&role=admin&is_active=1&password=",
            cookie_header=cookie,
        )
        self.assertEqual(dict(update["headers"]).get("Location"), "/")

        relogin = call_app(self.app, method="POST", path="/login", body="username=river2&password=user")
        self.assertEqual(dict(relogin["headers"]).get("Location"), "/")

    def test_admin_can_create_brokers_under_org(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=user")
        cookie = merge_cookies(cookie, login["headers"])

        create = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=teambroker&password=user&role=broker",
            cookie_header=cookie,
        )
        self.assertEqual(dict(create["headers"]).get("Location"), "/")

        relogin = call_app(self.app, method="POST", path="/login", body="username=teambroker&password=user")
        self.assertEqual(dict(relogin["headers"]).get("Location"), "/")

    def test_login_session_cookie_allows_immediate_dashboard_access(self):
        cookie = ""

        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=user")
        self.assertTrue(login["status"].startswith("302"))
        self.assertEqual(dict(login["headers"]).get("Location"), "/")
        cookie = merge_cookies(cookie, login["headers"])

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie)
        self.assertTrue(dashboard["status"].startswith("200"))
        self.assertIn("Welcome, Alex", dashboard["body"])

    def test_non_employer_can_create_employer_from_onboarding_form(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=user")
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
        self.assertEqual(dict(create["headers"]).get("Location"), "/?view=employers")

        db = self.app.db()
        employer = db.execute("SELECT * FROM employers WHERE legal_name = 'Acme Health'").fetchone()
        self.assertIsNotNone(employer)
        linked = db.execute("SELECT * FROM users WHERE id = ?", (employer["linked_user_id"],)).fetchone()
        self.assertEqual(linked["role"], "employer")
        db.close()

    def test_employer_accounts_are_read_only_and_hidden_from_admin_features(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=user")
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
            body=f"username={employer_user['username']}&password=user",
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

        dashboard = call_app(self.app, method="GET", path="/", query_string="view=employers", cookie_header=employer_cookie)
        self.assertNotIn("User Settings", dashboard["body"])
        self.assertNotIn("Admin · Account Management", dashboard["body"])
        self.assertIn("Applications", dashboard["body"])
        self.assertNotIn("href='/?view=employers'", dashboard["body"])

    def test_employer_visibility_is_limited_to_creator_scope(self):
        alex_cookie = ""
        sam_cookie = ""
        alex_cookie = merge_cookies(alex_cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])
        sam_cookie = merge_cookies(sam_cookie, call_app(self.app, method="POST", path="/login", body="username=sam&password=user")["headers"])

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
                body=f"username={employer_user['username']}&password=user",
            )["headers"],
        )
        dashboard = call_app(self.app, method="GET", path="/", query_string="view=employers", cookie_header=employer_cookie)

        self.assertIn("Atlas One", dashboard["body"])
        self.assertNotIn("Beta Care", dashboard["body"])


    def test_super_admin_can_create_broker_accounts(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=admin&password=user")
        cookie = merge_cookies(cookie, login["headers"])

        create = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=broker1&password=user&role=broker",
            cookie_header=cookie,
        )
        self.assertEqual(dict(create["headers"]).get("Location"), "/")

        relogin = call_app(self.app, method="POST", path="/login", body="username=broker1&password=user")
        self.assertEqual(dict(relogin["headers"]).get("Location"), "/")

    def test_broker_can_create_employer_and_owns_it(self):
        admin_cookie = ""
        admin_cookie = merge_cookies(admin_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=broker2&password=user&role=broker",
            cookie_header=admin_cookie,
        )

        broker_cookie = ""
        broker_cookie = merge_cookies(broker_cookie, call_app(self.app, method="POST", path="/login", body="username=broker2&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Broker+Client&contact_name=Casey&work_email=casey%40client.com&phone=555"
                "&company_size=10&industry=Consulting&website=https%3A%2F%2Fclient.com&state=CA"
            ),
            cookie_header=broker_cookie,
        )

        dashboard = call_app(self.app, method="GET", path="/", query_string="view=employers", cookie_header=broker_cookie)
        self.assertIn("Broker Client", dashboard["body"])
        self.assertIn("broker2", dashboard["body"])

    def test_team_tab_exists_and_contains_user_management(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])

        view = call_app(self.app, method="GET", path="/", query_string="view=team", cookie_header=cookie)
        self.assertIn("Team", view["body"])
        self.assertIn("Account Management", view["body"])

    def test_broker_referral_notifies_employer_and_sets_ichra_started(self):
        admin_cookie = ""
        admin_cookie = merge_cookies(admin_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=brokerref&password=user&role=broker",
            cookie_header=admin_cookie,
        )

        broker_cookie = ""
        broker_cookie = merge_cookies(broker_cookie, call_app(self.app, method="POST", path="/login", body="username=brokerref&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Invite+Co&contact_name=Robin&work_email=robin%40invite.com&phone=555"
                "&company_size=10&industry=Services&website=https%3A%2F%2Finvite.com&state=WA"
            ),
            cookie_header=broker_cookie,
        )

        db = self.app.db()
        employer = db.execute("SELECT id, linked_user_id FROM employers WHERE legal_name = 'Invite Co'").fetchone()
        db.close()

        refer = call_app(
            self.app,
            method="POST",
            path="/employers/refer",
            body=f"employer_id={employer['id']}",
            cookie_header=broker_cookie,
        )
        self.assertEqual(dict(refer["headers"]).get("Location"), "/")

        employer_cookie = ""
        db = self.app.db()
        employer_user = db.execute("SELECT username FROM users WHERE id = ?", (employer["linked_user_id"],)).fetchone()
        db.close()
        employer_cookie = merge_cookies(
            employer_cookie,
            call_app(self.app, method="POST", path="/login", body=f"username={employer_user['username']}&password=user")["headers"],
        )
        dashboard = call_app(self.app, method="GET", path="/", cookie_header=employer_cookie)
        self.assertIn("Finish ICHRA Setup Application", dashboard["body"])
        notifications = call_app(self.app, method="GET", path="/", query_string="view=notifications", cookie_header=employer_cookie)
        self.assertIn("ready and waiting for you to finish", notifications["body"])

    def test_employer_can_complete_application_without_incomplete_toggle(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Apply+Now&contact_name=Toni&work_email=toni%40apply.com&phone=555"
                "&company_size=10&industry=Retail&website=https%3A%2F%2Fapply.com&state=WA"
            ),
            cookie_header=cookie,
        )
        db = self.app.db()
        employer_user = db.execute("SELECT username FROM users WHERE role='employer' ORDER BY id DESC LIMIT 1").fetchone()
        db.close()

        employer_cookie = ""
        employer_cookie = merge_cookies(
            employer_cookie,
            call_app(self.app, method="POST", path="/login", body=f"username={employer_user['username']}&password=user")["headers"],
        )
        call_app(
            self.app,
            method="POST",
            path="/employers/start-ichra",
            body="",
            cookie_header=employer_cookie,
        )
        call_app(
            self.app,
            method="POST",
            path="/employers/start-ichra",
            body="",
            cookie_header=employer_cookie,
        )
        dashboard = call_app(self.app, method="GET", path="/", query_string="view=employers", cookie_header=employer_cookie)
        self.assertIn("Complete", dashboard["body"])

    def test_login_page_shows_db_backed_accounts_for_roles(self):
        admin_cookie = ""
        admin_cookie = merge_cookies(admin_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=brokerx&password=user&role=broker",
            cookie_header=admin_cookie,
        )

        login_page = call_app(self.app, method="GET", path="/login")
        self.assertIn("Active demo accounts (DB-backed)", login_page["body"])
        self.assertIn("admin", login_page["body"])
        self.assertIn("brokerx", login_page["body"])
        self.assertIn("alex", login_page["body"])
        self.assertIn("Open New Employer Setup", login_page["body"])
        self.assertIn("new-employer-modal", login_page["body"])

    def test_application_view_renders_toggle_panels(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=admin&password=user")
        cookie = merge_cookies(cookie, login["headers"])

        view = call_app(self.app, method="GET", path="/", query_string="view=application", cookie_header=cookie)
        self.assertIn("ICHRA Application", view["body"])
        self.assertIn("Existing Employer", view["body"])
        self.assertIn("Employer Setup Form", view["body"])
        self.assertIn("data-panel-mode='basic' hidden", view["body"])

    def test_public_signup_creates_employer_request(self):
        response = call_app(
            self.app,
            method="POST",
            path="/signup",
            body="legal_name=Public+Co&prospect_name=Riley&prospect_email=riley%40public.com&prospect_phone=555",
        )
        self.assertEqual(dict(response["headers"]).get("Location"), "/login")

        db = self.app.db()
        employer = db.execute("SELECT legal_name, primary_user_id FROM employers WHERE legal_name = 'Public Co'").fetchone()
        self.assertIsNotNone(employer)
        self.assertIsNotNone(employer["primary_user_id"])
        db.close()

    def test_notifications_view_supports_mark_seen(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Notice+Target&contact_name=Rae&work_email=rae%40notice.com&phone=555"
                "&company_size=10&industry=Retail&website=https%3A%2F%2Fnotice.com&state=WA"
            ),
            cookie_header=cookie,
        )

        notifications = call_app(self.app, method="GET", path="/", query_string="view=notifications", cookie_header=cookie)
        self.assertIn("Notifications", notifications["body"])

        db = self.app.db()
        note = db.execute("SELECT id FROM notifications WHERE user_id = (SELECT id FROM users WHERE username='alex') ORDER BY id DESC LIMIT 1").fetchone()
        db.close()
        seen = call_app(self.app, method="POST", path="/notifications/seen", body=f"notification_id={note['id']}", cookie_header=cookie)
        self.assertEqual(dict(seen["headers"]).get("Location"), "/?view=notifications")


    def test_admin_cannot_create_super_admin_accounts(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])

        create = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=nosuper&password=user&role=super_admin",
            cookie_header=cookie,
        )
        self.assertEqual(dict(create["headers"]).get("Location"), "/")

        relogin = call_app(self.app, method="POST", path="/login", body="username=nosuper&password=user")
        self.assertNotEqual(dict(relogin["headers"]).get("Location"), "/")

    def test_super_admin_can_deactivate_user_and_block_login(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])

        call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=toggleme&password=user&role=admin",
            cookie_header=cookie,
        )

        users = self.app.get_users_with_completion()
        target = next(u for u in users if u["username"] == "toggleme")

        call_app(
            self.app,
            method="POST",
            path="/admin/users/update",
            body=f"user_id={target['id']}&username=toggleme&role=admin&is_active=0&password=",
            cookie_header=cookie,
        )

        relogin = call_app(self.app, method="POST", path="/login", body="username=toggleme&password=user")
        self.assertEqual(dict(relogin["headers"]).get("Location"), "/login")

    def test_super_admin_can_filter_logs_and_update_employer_settings(self):
        admin_cookie = ""
        admin_cookie = merge_cookies(admin_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Log+Target&contact_name=Taylor&work_email=taylor%40log.com&phone=555"
                "&company_size=10&industry=Services&website=https%3A%2F%2Flog.com&state=CO"
            ),
            cookie_header=admin_cookie,
        )

        db = self.app.db()
        employer = db.execute("SELECT id FROM employers WHERE legal_name = 'Log Target'").fetchone()
        db.close()

        update = call_app(
            self.app,
            method="POST",
            path="/employers/update",
            body=(
                f"employer_id={employer['id']}&legal_name=Log+Target&contact_name=Taylor+Updated"
                "&work_email=taylor%40log.com&phone=555-222&company_size=10-20&industry=Services"
                "&website=https%3A%2F%2Flog.com&state=CO&onboarding_task=Collect+docs&portal_username=logtarget1"
            ),
            cookie_header=admin_cookie,
        )
        self.assertEqual(dict(update["headers"]).get("Location"), f"/employers/settings?id={employer['id']}")

        logs_view = call_app(self.app, method="GET", path="/", query_string="view=logs&action=employer_updated", cookie_header=admin_cookie)
        self.assertIn("Admin Activity Log", logs_view["body"])
        self.assertIn("employer_updated", logs_view["body"])
        self.assertIn("Log Target", logs_view["body"])

    def test_employer_update_rejects_duplicate_username_without_partial_save(self):
        admin_cookie = ""
        admin_cookie = merge_cookies(admin_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])

        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Duplicate+One&contact_name=Taylor&work_email=taylor1%40dup.com&phone=555"
                "&company_size=10&industry=Services&website=https%3A%2F%2Fdup.com&state=CO"
            ),
            cookie_header=admin_cookie,
        )
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Duplicate+Two&contact_name=Riley&work_email=riley%40dup.com&phone=777"
                "&company_size=20&industry=Retail&website=https%3A%2F%2Fduptwo.com&state=WA"
            ),
            cookie_header=admin_cookie,
        )

        db = self.app.db()
        first = db.execute("SELECT id, linked_user_id FROM employers WHERE legal_name = 'Duplicate One'").fetchone()
        second = db.execute("SELECT id, linked_user_id, contact_name, phone FROM employers WHERE legal_name = 'Duplicate Two'").fetchone()
        first_username = db.execute("SELECT username FROM users WHERE id = ?", (first["linked_user_id"],)).fetchone()["username"]
        db.close()

        update = call_app(
            self.app,
            method="POST",
            path="/employers/update",
            body=(
                f"employer_id={second['id']}&legal_name=Duplicate+Two&contact_name=Changed+Name"
                "&work_email=riley%40dup.com&phone=888&company_size=20&industry=Retail"
                f"&website=https%3A%2F%2Fduptwo.com&state=WA&onboarding_task=Collect+docs&portal_username={first_username}"
            ),
            cookie_header=admin_cookie,
        )

        self.assertEqual(dict(update["headers"]).get("Location"), f"/employers/settings?id={second['id']}")
        admin_cookie = merge_cookies(admin_cookie, update["headers"])

        follow = call_app(self.app, method="GET", path="/employers/settings", query_string=f"id={second['id']}", cookie_header=admin_cookie)
        self.assertIn("Employer username is already in use.", follow["body"])

        db = self.app.db()
        second_after = db.execute("SELECT contact_name, phone FROM employers WHERE id = ?", (second["id"],)).fetchone()
        db.close()
        self.assertEqual(second_after["contact_name"], second["contact_name"])
        self.assertEqual(second_after["phone"], second["phone"])


    def test_employer_list_links_to_settings_page(self):
        admin_cookie = ""
        admin_cookie = merge_cookies(admin_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Settings+Target&contact_name=Taylor&work_email=taylor%40settings.com&phone=555"
                "&company_size=10&industry=Services&website=https%3A%2F%2Fsettings.com&state=CO"
            ),
            cookie_header=admin_cookie,
        )
        dashboard = call_app(self.app, method="GET", path="/", query_string="view=employers", cookie_header=admin_cookie)
        self.assertIn("/employers/settings?id=", dashboard["body"])

    def test_logs_view_has_clear_filters_link(self):
        admin_cookie = ""
        admin_cookie = merge_cookies(admin_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        logs_view = call_app(self.app, method="GET", path="/", query_string="view=logs&action=login", cookie_header=admin_cookie)
        self.assertIn("Clear Filters", logs_view["body"])


    def test_employer_applications_open_in_modal(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Modal+Co&contact_name=Mo&work_email=mo%40modal.com&phone=555"
                "&company_size=10&industry=Retail&website=https%3A%2F%2Fmodal.com&state=WA"
            ),
            cookie_header=cookie,
        )
        db = self.app.db()
        employer_user = db.execute("SELECT username FROM users WHERE role='employer' ORDER BY id DESC LIMIT 1").fetchone()
        db.close()

        employer_cookie = ""
        employer_cookie = merge_cookies(
            employer_cookie,
            call_app(self.app, method="POST", path="/login", body=f"username={employer_user['username']}&password=user")["headers"],
        )
        view = call_app(self.app, method="GET", path="/", query_string="view=applications", cookie_header=employer_cookie)
        self.assertIn("data-modal-open='ichra-application-modal'", view["body"])

    def test_super_admin_team_management_forms_present(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        view = call_app(self.app, method="GET", path="/", query_string="view=team", cookie_header=cookie)
        self.assertIn("Team Administration", view["body"])
        self.assertIn("/teams/create", view["body"])
        self.assertIn("/teams/assign-admin", view["body"])

    def test_admin_can_send_notification_to_super_admin(self):
        admin_cookie = ""
        admin_cookie = merge_cookies(admin_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=teamadmin&password=user&role=admin",
            cookie_header=admin_cookie,
        )

        team_admin_cookie = ""
        team_admin_cookie = merge_cookies(team_admin_cookie, call_app(self.app, method="POST", path="/login", body="username=teamadmin&password=user")["headers"])
        sent = call_app(
            self.app,
            method="POST",
            path="/notifications/create",
            body=f"user_id={self.app.get_user('admin')['id']}&message=Ops+note",
            cookie_header=team_admin_cookie,
        )
        self.assertEqual(dict(sent["headers"]).get("Location"), "/?view=notifications")

if __name__ == "__main__":
    unittest.main()
