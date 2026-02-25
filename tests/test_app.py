import io
import json
import re
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


    def test_dashboard_shows_team_task_engine(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=user")
        cookie = merge_cookies(cookie, login["headers"])

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie, query_string="view=dashboard")
        self.assertIn("Team Task Engine", dashboard["body"])
        self.assertIn("including Super Admin accounts", dashboard["body"])

    def test_team_task_can_be_assigned_to_super_admin_and_completed_by_assignee(self):
        admin_cookie = ""
        admin_login = call_app(self.app, method="POST", path="/login", body="username=admin&password=user")
        admin_cookie = merge_cookies(admin_cookie, admin_login["headers"])

        assign = call_app(
            self.app,
            method="POST",
            path="/team-tasks/create",
            body="title=Review+Roadmap&details=Please+review+priorities&assigned_to_user_id=3",
            cookie_header=admin_cookie,
        )
        self.assertEqual(dict(assign["headers"]).get("Location"), "/?view=dashboard")

        db = self.app.db()
        task = db.execute("SELECT id, assigned_to_user_id, status FROM team_tasks ORDER BY id DESC LIMIT 1").fetchone()
        db.close()
        self.assertEqual(task["assigned_to_user_id"], 3)
        self.assertEqual(task["status"], "open")

        complete = call_app(
            self.app,
            method="POST",
            path="/team-tasks/complete",
            body=f"task_id={task['id']}",
            cookie_header=admin_cookie,
        )
        self.assertEqual(dict(complete["headers"]).get("Location"), "/?view=dashboard")

        db = self.app.db()
        updated = db.execute("SELECT status, completed_at FROM team_tasks WHERE id = ?", (task["id"],)).fetchone()
        db.close()
        self.assertEqual(updated["status"], "completed")
        self.assertIsNotNone(updated["completed_at"])

    def test_dev_log_tab_is_visible_and_lists_pr_history(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=user")
        cookie = merge_cookies(cookie, login["headers"])

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie, query_string="view=devlog")
        self.assertIn("Dev Log", dashboard["body"])
        self.assertIn("Development Log", dashboard["body"])
        self.assertIn("Merged At (UTC)", dashboard["body"])

        prs = [int(value) for value in re.findall(r">PR #(\d+)</td>", dashboard["body"])]
        self.assertTrue(prs, "Expected at least one PR entry in the development log")
        self.assertEqual(prs, sorted(prs), "PR entries should be rendered in ascending PR order")
        self.assertEqual(len(prs), len(set(prs)), "PR entries should not contain duplicates")
        self.assertIn(69, prs, "Expected the merged PR #69 entry to be visible in Dev Log")
        self.assertRegex(dashboard["body"], r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC")

    def test_permissions_tab_is_visible_in_main_nav(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=user")
        cookie = merge_cookies(cookie, login["headers"])

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie, query_string="view=dashboard")
        self.assertIn("href='/?view=permissions'", dashboard["body"])
        self.assertIn(">Permissions</a>", dashboard["body"])

    def test_permissions_view_displays_permission_matrix_and_devops_rules(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=admin&password=user")
        cookie = merge_cookies(cookie, login["headers"])

        permissions = call_app(self.app, method="GET", path="/", cookie_header=cookie, query_string="view=permissions")
        self.assertIn("Permissions and Access Control Baseline", permissions["body"])
        self.assertIn("Capability Area", permissions["body"])
        self.assertIn("Team boundary", permissions["body"])
        self.assertIn("single broker admin per team", permissions["body"].lower())

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


    def test_notification_targets_include_employer_users_in_scope(self):
        admin_cookie = ""
        login_admin = call_app(self.app, method="POST", path="/login", body="username=admin&password=user")
        admin_cookie = merge_cookies(admin_cookie, login_admin["headers"])

        create_employer = call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Bluebird+Manufacturing&contact_name=Pat+Lee&work_email=pat%40bluebird.com"
                "&phone=555-0100&company_size=75&industry=Manufacturing&website=https%3A%2F%2Fbluebird.example&state=CA"
            ),
            cookie_header=admin_cookie,
        )
        self.assertEqual(dict(create_employer["headers"]).get("Location"), "/?view=employers")

        notifications_view = call_app(self.app, method="GET", path="/", cookie_header=admin_cookie, query_string="view=notifications")
        self.assertIn("Bluebird Manufacturing", notifications_view["body"])
        self.assertIn("(employer", notifications_view["body"])


    def test_admin_employer_visibility_includes_created_by_scope_even_without_owner_or_team_links(self):
        admin_cookie = ""
        login_admin = call_app(self.app, method="POST", path="/login", body="username=alex&password=user")
        admin_cookie = merge_cookies(admin_cookie, login_admin["headers"])

        create_employer = call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Scope+Anchor+Employer&contact_name=Taylor+Case&work_email=taylor%40anchor.com"
                "&phone=555-2211&company_size=10&industry=Services&website=https%3A%2F%2Fanchor.example&state=TX"
            ),
            cookie_header=admin_cookie,
        )
        self.assertEqual(dict(create_employer["headers"]).get("Location"), "/?view=employers")

        db = self.app.db()
        employer = db.execute("SELECT id, linked_user_id FROM employers WHERE legal_name = 'Scope Anchor Employer'").fetchone()
        db.execute("UPDATE employers SET primary_user_id = NULL, broker_user_id = NULL WHERE id = ?", (employer["id"],))
        db.execute("UPDATE users SET team_id = 999 WHERE id = ?", (employer["linked_user_id"],))
        db.commit()
        admin_user = db.execute("SELECT * FROM users WHERE username = 'alex'").fetchone()
        db.close()

        visible = self.app.list_visible_employers(admin_user)
        self.assertIn("Scope Anchor Employer", [row["legal_name"] for row in visible])

    def test_notifications_include_active_visible_employer_even_if_employer_team_differs(self):
        admin_cookie = ""
        login_admin = call_app(self.app, method="POST", path="/login", body="username=alex&password=user")
        admin_cookie = merge_cookies(admin_cookie, login_admin["headers"])

        create_employer = call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Cross+Team+Notify&contact_name=Riley+Stone&work_email=riley%40notify.com"
                "&phone=555-1010&company_size=55&industry=Retail&website=https%3A%2F%2Fnotify.example&state=CA"
            ),
            cookie_header=admin_cookie,
        )
        self.assertEqual(dict(create_employer["headers"]).get("Location"), "/?view=employers")

        db = self.app.db()
        employer = db.execute("SELECT linked_user_id FROM employers WHERE legal_name = 'Cross Team Notify'").fetchone()
        db.execute("UPDATE users SET team_id = 777 WHERE id = ?", (employer["linked_user_id"],))
        db.commit()
        db.close()

        notifications_view = call_app(self.app, method="GET", path="/", cookie_header=admin_cookie, query_string="view=notifications")
        self.assertIn("Cross Team Notify", notifications_view["body"])

    def test_team_super_admin_broker_gets_team_employer_visibility(self):
        admin_cookie = ""
        login_admin = call_app(self.app, method="POST", path="/login", body="username=alex&password=user")
        admin_cookie = merge_cookies(admin_cookie, login_admin["headers"])

        create_broker = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=teamscopebroker&password=user&role=broker",
            cookie_header=admin_cookie,
        )
        self.assertEqual(dict(create_broker["headers"]).get("Location"), "/")

        db = self.app.db()
        broker = db.execute("SELECT id, team_id FROM users WHERE username = 'teamscopebroker' LIMIT 1").fetchone()
        admin_user = db.execute("SELECT id FROM users WHERE username = 'alex' LIMIT 1").fetchone()
        db.close()

        self.app.assign_team_super_admin(broker["id"], broker["team_id"])

        self.app.create_employer(
            creator_user_id=admin_user["id"],
            form={
                "legal_name": "Teamwide Employer",
                "contact_name": "Jordan Case",
                "work_email": "jordan@teamwide.example",
                "phone": "555-1001",
                "company_size": "42",
                "industry": "Services",
                "website": "https://teamwide.example",
                "state": "NY",
            },
            broker_user_id=None,
        )

        broker_cookie = ""
        login_broker = call_app(self.app, method="POST", path="/login", body="username=teamscopebroker&password=user")
        broker_cookie = merge_cookies(broker_cookie, login_broker["headers"])

        employers_view = call_app(self.app, method="GET", path="/", cookie_header=broker_cookie, query_string="view=employers")
        application_view = call_app(self.app, method="GET", path="/", cookie_header=broker_cookie, query_string="view=application")

        self.assertIn("Teamwide Employer", employers_view["body"])
        self.assertIn("Teamwide Employer", application_view["body"])

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

    def test_broker_can_create_employer_but_not_admin_or_broker(self):
        admin_cookie = ""
        login_admin = call_app(self.app, method="POST", path="/login", body="username=admin&password=user")
        admin_cookie = merge_cookies(admin_cookie, login_admin["headers"])

        create_broker = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=brokerlead&role=broker",
            cookie_header=admin_cookie,
        )
        self.assertEqual(dict(create_broker["headers"]).get("Location"), "/")

        broker_cookie = ""
        login_broker = call_app(self.app, method="POST", path="/login", body="username=brokerlead&password=user")
        broker_cookie = merge_cookies(broker_cookie, login_broker["headers"])

        denied = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=shouldfail&role=admin",
            cookie_header=broker_cookie,
        )
        self.assertEqual(dict(denied["headers"]).get("Location"), "/")

        denied_broker = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=brokerpeer&role=broker",
            cookie_header=broker_cookie,
        )
        self.assertEqual(dict(denied_broker["headers"]).get("Location"), "/")

        allowed_employer = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=brokeremployer&role=employer",
            cookie_header=broker_cookie,
        )
        self.assertEqual(dict(allowed_employer["headers"]).get("Location"), "/")


    def test_effective_access_endpoint_returns_capability_payload(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=alex&password=user")
        cookie = merge_cookies(cookie, login["headers"])

        response = call_app(self.app, method="GET", path="/me/access", cookie_header=cookie)
        self.assertTrue(response["status"].startswith("200"))
        payload = json.loads(response["body"])
        self.assertEqual(payload["role"], "admin")
        self.assertIn("team.user_admin", payload["capabilities"])
        self.assertTrue(payload["capabilities"]["team.user_admin"])

    def test_team_has_single_broker_team_admin_and_can_be_reassigned(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=admin&password=user")
        cookie = merge_cookies(cookie, login["headers"])

        create_team = call_app(self.app, method="POST", path="/teams/create", body="name=West+Team", cookie_header=cookie)
        self.assertEqual(dict(create_team["headers"]).get("Location"), "/?view=team")

        create_broker_one = call_app(self.app, method="POST", path="/admin/users/create", body="username=westbroker1&role=broker&team_id=2", cookie_header=cookie)
        create_broker_two = call_app(self.app, method="POST", path="/admin/users/create", body="username=westbroker2&role=broker&team_id=2", cookie_header=cookie)
        self.assertEqual(dict(create_broker_one["headers"]).get("Location"), "/")
        self.assertEqual(dict(create_broker_two["headers"]).get("Location"), "/")

        db = self.app.db()
        first_admin = db.execute("SELECT username FROM users WHERE team_id = 2 AND role = 'broker' AND is_team_admin = 1").fetchall()
        db.close()
        self.assertEqual(len(first_admin), 1)
        self.assertEqual(first_admin[0]["username"], "westbroker1")

        broker_two = next(u for u in self.app.get_users_with_completion() if u["username"] == "westbroker2")
        reassign = call_app(
            self.app,
            method="POST",
            path="/teams/assign-broker-admin",
            body=f"team_id=2&broker_user_id={broker_two['id']}",
            cookie_header=cookie,
        )
        self.assertEqual(dict(reassign["headers"]).get("Location"), "/?view=team")

        db = self.app.db()
        final_admin = db.execute("SELECT username FROM users WHERE team_id = 2 AND role = 'broker' AND is_team_admin = 1").fetchall()
        db.close()
        self.assertEqual(len(final_admin), 1)
        self.assertEqual(final_admin[0]["username"], "westbroker2")

    def test_only_super_admin_can_assign_team_broker_admin(self):
        admin_cookie = ""
        login_admin = call_app(self.app, method="POST", path="/login", body="username=admin&password=user")
        admin_cookie = merge_cookies(admin_cookie, login_admin["headers"])

        create_broker = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=brokerviewer&role=broker",
            cookie_header=admin_cookie,
        )
        self.assertEqual(dict(create_broker["headers"]).get("Location"), "/")

        broker_user = next(u for u in self.app.get_users_with_completion() if u["username"] == "brokerviewer")
        denied = call_app(
            self.app,
            method="POST",
            path="/teams/assign-broker-admin",
            body=f"team_id=1&broker_user_id={broker_user['id']}",
            cookie_header=admin_cookie,
        )
        self.assertEqual(dict(denied["headers"]).get("Location"), "/?view=team")

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
        self.assertIn("My ICHRA Setup Application", dashboard["body"])
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


    def test_broker_cannot_see_other_broker_employers(self):
        super_cookie = ""
        super_cookie = merge_cookies(super_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        call_app(self.app, method="POST", path="/admin/users/create", body="username=brokera&password=user&role=broker", cookie_header=super_cookie)
        call_app(self.app, method="POST", path="/admin/users/create", body="username=brokerb&password=user&role=broker", cookie_header=super_cookie)

        broker_a_cookie = ""
        broker_a_cookie = merge_cookies(broker_a_cookie, call_app(self.app, method="POST", path="/login", body="username=brokera&password=user")["headers"])
        broker_b_cookie = ""
        broker_b_cookie = merge_cookies(broker_b_cookie, call_app(self.app, method="POST", path="/login", body="username=brokerb&password=user")["headers"])

        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Broker+A+Client&contact_name=A+Owner&work_email=a%40client.com&phone=555"
                "&company_size=10&industry=Retail&website=https%3A%2F%2Fa.com&state=WA"
            ),
            cookie_header=broker_a_cookie,
        )

        broker_b_view = call_app(self.app, method="GET", path="/", query_string="view=employers", cookie_header=broker_b_cookie)
        self.assertNotIn("Broker A Client", broker_b_view["body"])



    def test_super_admin_employers_view_supports_active_inactive_scopes(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])

        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Visible+Active&contact_name=Nova&work_email=nova%40active.com&phone=555"
                "&company_size=10&industry=Retail&website=https%3A%2F%2Factive.com&state=WA"
            ),
            cookie_header=cookie,
        )
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Hidden+Inactive&contact_name=Rowan&work_email=rowan%40inactive.com&phone=555"
                "&company_size=10&industry=Services&website=https%3A%2F%2Finactive.com&state=OR"
            ),
            cookie_header=cookie,
        )

        db = self.app.db()
        db.execute(
            "UPDATE users SET is_active = 0 WHERE id = (SELECT linked_user_id FROM employers WHERE legal_name = 'Hidden Inactive')"
        )
        db.commit()
        db.close()

        active_view = call_app(self.app, method="GET", path="/", query_string="view=employers&employers_scope=active", cookie_header=cookie)
        self.assertIn("Visible Active", active_view["body"])
        self.assertNotIn("Hidden Inactive", active_view["body"])

        all_view = call_app(self.app, method="GET", path="/", query_string="view=employers&employers_scope=all", cookie_header=cookie)
        self.assertIn("Visible Active", all_view["body"])
        self.assertIn("Hidden Inactive", all_view["body"])
        self.assertIn("Portal Status", all_view["body"])
        self.assertIn(">Inactive<", all_view["body"])


    def test_main_nav_hides_settings_activity_log_and_dev_log_links(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])

        view = call_app(self.app, method="GET", path="/", query_string="view=dashboard", cookie_header=cookie)
        start = view["body"].find("<nav class='dashboard-nav floating-nav'>")
        end = view["body"].find("</nav>", start)
        nav_html = view["body"][start:end]
        self.assertNotIn("/?view=settings", nav_html)
        self.assertNotIn("/?view=logs", nav_html)
        self.assertNotIn("/?view=devlog", nav_html)

    def test_admin_employer_scope_includes_team_employers_when_broker_deactivated(self):
        admin_cookie = ""
        admin_cookie = merge_cookies(admin_cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])

        call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=inactivebookbroker&password=user&role=broker",
            cookie_header=admin_cookie,
        )
        broker_cookie = ""
        broker_cookie = merge_cookies(broker_cookie, call_app(self.app, method="POST", path="/login", body="username=inactivebookbroker&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Team+Scoped+Inactive+Broker+Employer&contact_name=Pat&work_email=pat%40scope.com&phone=555"
                "&company_size=10&industry=Retail&website=https%3A%2F%2Fscope.com&state=WA"
            ),
            cookie_header=broker_cookie,
        )

        db = self.app.db()
        db.execute("UPDATE users SET is_active = 0 WHERE username = 'inactivebookbroker'")
        db.commit()
        db.close()

        employers_view = call_app(self.app, method="GET", path="/", query_string="view=employers&employers_scope=all", cookie_header=admin_cookie)
        self.assertIn("Team Scoped Inactive Broker Employer", employers_view["body"])

    def test_employer_application_status_shows_not_started_before_ichra(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Status+Co&contact_name=Sky&work_email=sky%40status.com&phone=555"
                "&company_size=10&industry=Retail&website=https%3A%2F%2Fstatus.com&state=WA"
            ),
            cookie_header=cookie,
        )

        dashboard = call_app(self.app, method="GET", path="/", query_string="view=employers", cookie_header=cookie)
        self.assertIn("Not started", dashboard["body"])

    def test_invalid_view_falls_back_to_dashboard(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])

        view = call_app(self.app, method="GET", path="/", query_string="view=doesnotexist", cookie_header=cookie)
        self.assertIn("Workflow Snapshot", view["body"])
        self.assertIn("Welcome, Alex", view["body"])

    def test_team_tab_exists_and_contains_user_management(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])

        view = call_app(self.app, method="GET", path="/", query_string="view=team", cookie_header=cookie)
        self.assertIn("Team", view["body"])
        self.assertIn("Account Management", view["body"])
        self.assertIn("href='/?view=employers&employers_scope=all'", view["body"])

        nav_start = view["body"].find("<nav class='dashboard-nav floating-nav'>")
        nav_end = view["body"].find("</nav>", nav_start)
        floating_nav = view["body"][nav_start:nav_end]
        self.assertNotIn("href='/?view=employers'", floating_nav)

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
        self.assertIn("Continue ICHRA Workspace", dashboard["body"])
        notifications = call_app(self.app, method="GET", path="/", query_string="view=notifications", cookie_header=employer_cookie)
        self.assertIn("ready and waiting for you to finish", notifications["body"])

    def test_employer_can_submit_ichra_application(self):
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
        db = self.app.db()
        employer = db.execute("SELECT id FROM employers WHERE linked_user_id = (SELECT id FROM users WHERE username = ?)", (employer_user["username"],)).fetchone()
        db.close()
        submit = call_app(
            self.app,
            method="POST",
            path="/applications/ichra/save",
            body=(
                f"employer_id={employer['id']}&artifact_action=submit&desired_start_date=2026-01-01"
                "&service_type=ICHRA+Documents+Only&primary_first_name=Toni&primary_last_name=Stone"
                "&primary_email=toni%40apply.com&primary_phone=555-111-2222&legal_name=Apply+Now"
                "&nature_of_business=Retail&total_employee_count=10&physical_state=WA"
                "&reimbursement_option=Standard&employee_class_assistance=Yes"
                "&planned_contribution=400&claim_option=Employer+Managed&agent_support=Broker"
            ),
            cookie_header=employer_cookie,
        )
        self.assertEqual(dict(submit["headers"]).get("Location"), f"/?view=application&employer_id={employer['id']}")

        dashboard = call_app(self.app, method="GET", path="/", query_string="view=employers", cookie_header=employer_cookie)
        self.assertIn("Complete", dashboard["body"])

    def test_login_page_prioritizes_login_and_setup_entry_points(self):
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
        self.assertNotIn("Active demo accounts (DB-backed)", login_page["body"])
        self.assertNotIn("password_hint", login_page["body"])
        self.assertIn("Member Login", login_page["body"])
        self.assertIn("Start New Setup", login_page["body"])
        self.assertIn("public-setup-modal", login_page["body"])
        self.assertIn("New Employer Setup Form", login_page["body"])
        self.assertIn("New Broker Setup Form", login_page["body"])
        self.assertIn("setup-toggle active", login_page["body"])

    def test_application_view_renders_application_workspace(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=admin&password=user")
        cookie = merge_cookies(cookie, login["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Artifact+View&contact_name=Jamie&work_email=jamie%40artifact.com&phone=555"
                "&company_size=10&industry=Services&website=https%3A%2F%2Fartifact.com&state=TX"
            ),
            cookie_header=cookie,
        )

        view = call_app(self.app, method="GET", path="/", query_string="view=application", cookie_header=cookie)
        self.assertIn("ICHRA Setup Workspace", view["body"])
        self.assertIn("New Employer Setup Form", view["body"])
        self.assertIn("ICHRA Setup Workspace", view["body"])
        self.assertIn("Switch employer application", view["body"])
        self.assertIn("Employer Snapshot", view["body"])
        self.assertIn("Save Draft", view["body"])
        self.assertIn("Submit Application", view["body"])

    def test_application_workspace_employer_selector_only_lists_active_portals(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=admin&password=user")
        cookie = merge_cookies(cookie, login["headers"])

        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Active+Workspace+Employer&contact_name=Jamie&work_email=jamie%40activeworkspace.com&phone=555"
                "&company_size=10&industry=Services&website=https%3A%2F%2Factiveworkspace.com&state=TX"
            ),
            cookie_header=cookie,
        )
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Inactive+Workspace+Employer&contact_name=Taylor&work_email=taylor%40inactiveworkspace.com&phone=555"
                "&company_size=10&industry=Services&website=https%3A%2F%2Finactiveworkspace.com&state=TX"
            ),
            cookie_header=cookie,
        )

        db = self.app.db()
        db.execute(
            "UPDATE users SET is_active = 0 WHERE id = (SELECT linked_user_id FROM employers WHERE legal_name = 'Inactive Workspace Employer')"
        )
        db.commit()
        db.close()

        view = call_app(self.app, method="GET", path="/", query_string="view=application", cookie_header=cookie)
        self.assertIn("Active Workspace Employer", view["body"])
        self.assertNotIn("Inactive Workspace Employer", view["body"])
        self.assertIn("DevOps Note: only employers with an active portal account appear in this workspace selector.", view["body"])

    def test_application_view_supports_new_employer_setup_form_sub_nav(self):
        cookie = ""
        login = call_app(self.app, method="POST", path="/login", body="username=admin&password=user")
        cookie = merge_cookies(cookie, login["headers"])

        view = call_app(self.app, method="GET", path="/", query_string="view=application&artifact_view=form", cookie_header=cookie)
        self.assertIn("New Employer Setup Form", view["body"])
        self.assertIn("same intake form available on the login page", view["body"])
        self.assertIn("action='/signup'", view["body"])
        self.assertIn("Employer Legal Name", view["body"])

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


    def test_public_broker_signup_creates_unassigned_broker(self):
        response = call_app(
            self.app,
            method="POST",
            path="/signup/broker",
            body="brokerage_name=Public+Brokerage&contact_name=Taylor&work_email=taylor%40broker.com&phone=555",
        )
        self.assertEqual(dict(response["headers"]).get("Location"), "/login")

        db = self.app.db()
        broker = db.execute("SELECT username, role, team_id FROM users WHERE display_name = 'Taylor' AND role = 'broker' ORDER BY id DESC LIMIT 1").fetchone()
        db.close()
        self.assertIsNotNone(broker)
        self.assertEqual(broker["role"], "broker")
        self.assertIsNone(broker["team_id"])

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



    def test_employer_can_access_forms_and_applications_workspace(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Workspace+Co&contact_name=Will&work_email=will%40workspace.com&phone=555"
                "&company_size=10&industry=Retail&website=https%3A%2F%2Fworkspace.com&state=WA"
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
        dashboard = call_app(self.app, method="GET", path="/", cookie_header=employer_cookie)
        self.assertIn("ICHRA Setup Workspace", dashboard["body"])

        workspace = call_app(self.app, method="GET", path="/", query_string="view=application", cookie_header=employer_cookie)
        self.assertIn("ICHRA Setup Workspace", workspace["body"])
        self.assertNotIn("New Employer Setup Form", workspace["body"])

    def test_employer_applications_link_to_workspace(self):
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
        self.assertIn("/?view=application&employer_id=", view["body"])
        self.assertIn("/db/ichra_applications", view["body"])

    def test_super_admin_team_management_forms_present(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        view = call_app(self.app, method="GET", path="/", query_string="view=team", cookie_header=cookie)
        self.assertIn("Team Workspace", view["body"])
        self.assertIn("/teams/create", view["body"])
        self.assertIn("/teams/assign-admin", view["body"])

    def test_team_administration_shows_active_team_table_and_member_modal_trigger(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        view = call_app(self.app, method="GET", path="/", query_string="view=team", cookie_header=cookie)
        self.assertIn("Team in Focus", view["body"])
        self.assertIn("Team Super Admin", view["body"])
        self.assertIn("Focus Team", view["body"])

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

    def test_deactivated_admin_hidden_from_team_administration_dropdown(self):
        super_cookie = ""
        super_cookie = merge_cookies(super_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=inactiveadmin&password=user&role=admin",
            cookie_header=super_cookie,
        )

        user_row = self.app.get_user("inactiveadmin")
        call_app(
            self.app,
            method="POST",
            path="/admin/users/update",
            body=f"user_id={user_row['id']}&username=inactiveadmin&role=admin&is_active=0&password=",
            cookie_header=super_cookie,
        )

        team_view = call_app(self.app, method="GET", path="/", query_string="view=team&team_section=administration", cookie_header=super_cookie)
        self.assertNotIn("inactiveadmin", team_view["body"])

    def test_deactivated_broker_hidden_from_system_lists(self):
        super_cookie = ""
        super_cookie = merge_cookies(super_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=hiddenbroker&password=user&role=broker",
            cookie_header=super_cookie,
        )

        user_row = self.app.get_user("hiddenbroker")
        call_app(
            self.app,
            method="POST",
            path="/admin/users/update",
            body=f"user_id={user_row['id']}&username=hiddenbroker&role=broker&is_active=0&password=",
            cookie_header=super_cookie,
        )

        login_page = call_app(self.app, method="GET", path="/login")
        self.assertNotIn("hiddenbroker", login_page["body"])

        notification_view = call_app(self.app, method="GET", path="/", query_string="view=notifications", cookie_header=super_cookie)
        self.assertNotIn("hiddenbroker (broker)", notification_view["body"])

    def test_team_scoping_limits_admin_visibility_in_team_views(self):
        super_cookie = ""
        super_cookie = merge_cookies(super_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])

        create_team = call_app(
            self.app,
            method="POST",
            path="/teams/create",
            body="name=West+Ops",
            cookie_header=super_cookie,
        )
        self.assertEqual(dict(create_team["headers"]).get("Location"), "/?view=team")

        db = self.app.db()
        west_team = db.execute("SELECT id FROM teams WHERE name='West Ops'").fetchone()
        alex = db.execute("SELECT id FROM users WHERE username='alex'").fetchone()
        db.close()

        assign = call_app(
            self.app,
            method="POST",
            path="/teams/assign-admin",
            body=f"admin_user_id={alex['id']}&team_id={west_team['id']}",
            cookie_header=super_cookie,
        )
        self.assertEqual(dict(assign["headers"]).get("Location"), "/?view=team")

        sam_cookie = ""
        sam_cookie = merge_cookies(sam_cookie, call_app(self.app, method="POST", path="/login", body="username=sam&password=user")["headers"])
        sam_team = call_app(self.app, method="GET", path="/", query_string="view=team&team_section=completion", cookie_header=sam_cookie)
        self.assertNotIn("alex", sam_team["body"])

        alex_cookie = ""
        alex_cookie = merge_cookies(alex_cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])
        alex_team = call_app(self.app, method="GET", path="/", query_string="view=team&team_section=completion", cookie_header=alex_cookie)
        self.assertIn("alex", alex_team["body"])
        self.assertNotIn("sam", alex_team["body"])

    def test_super_admin_can_assign_any_user_to_team_with_sub_group_tool(self):
        super_cookie = ""
        super_cookie = merge_cookies(super_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])

        call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=subbroker&password=user&role=broker",
            cookie_header=super_cookie,
        )

        db = self.app.db()
        subbroker = db.execute("SELECT id FROM users WHERE username='subbroker'").fetchone()
        db.close()

        call_app(
            self.app,
            method="POST",
            path="/teams/create",
            body="name=East+Ops",
            cookie_header=super_cookie,
        )
        db = self.app.db()
        east_team = db.execute("SELECT id FROM teams WHERE name='East Ops'").fetchone()
        db.close()

        move = call_app(
            self.app,
            method="POST",
            path="/teams/assign-user",
            body=f"user_id={subbroker['id']}&team_id={east_team['id']}",
            cookie_header=super_cookie,
        )
        self.assertEqual(dict(move["headers"]).get("Location"), "/?view=team")

        db = self.app.db()
        moved = db.execute("SELECT team_id FROM users WHERE id=?", (subbroker["id"],)).fetchone()
        db.close()
        self.assertEqual(moved["team_id"], east_team["id"])


    def test_employer_dashboard_uses_forms_workspace_not_legacy_applications_tab(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Nav+Check&contact_name=Robin&work_email=robin%40nav.com&phone=555"
                "&company_size=8&industry=Retail&website=https%3A%2F%2Fnav.com&state=WA"
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
        dashboard = call_app(self.app, method="GET", path="/", cookie_header=employer_cookie)
        self.assertIn("/?view=application", dashboard["body"])
        self.assertNotIn("href='/?view=applications'", dashboard["body"])

    def test_submitted_ichra_workspace_locks_until_admin_or_broker_renews(self):
        admin_cookie = ""
        admin_cookie = merge_cookies(admin_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Lock+Co&contact_name=Jan&work_email=jan%40lock.com&phone=555"
                "&company_size=10&industry=Retail&website=https%3A%2F%2Flock.com&state=WA"
            ),
            cookie_header=admin_cookie,
        )
        db = self.app.db()
        employer = db.execute("SELECT id, linked_user_id FROM employers WHERE legal_name='Lock Co'").fetchone()
        employer_user = db.execute("SELECT username FROM users WHERE id = ?", (employer["linked_user_id"],)).fetchone()
        db.close()

        employer_cookie = ""
        employer_cookie = merge_cookies(
            employer_cookie,
            call_app(self.app, method="POST", path="/login", body=f"username={employer_user['username']}&password=user")["headers"],
        )

        submit = call_app(
            self.app,
            method="POST",
            path="/applications/ichra/save",
            body=(
                f"employer_id={employer['id']}&artifact_action=submit&desired_start_date=2026-01-01"
                "&service_type=ICHRA+Documents+Only&primary_first_name=Jan&primary_last_name=Stone"
                "&primary_email=jan%40lock.com&primary_phone=555-111-2222&legal_name=Lock+Co"
                "&nature_of_business=Retail&total_employee_count=10&physical_state=WA"
                "&reimbursement_option=Standard&employee_class_assistance=Yes"
                "&planned_contribution=400&claim_option=Employer+Managed&agent_support=Broker"
            ),
            cookie_header=employer_cookie,
        )
        self.assertEqual(dict(submit["headers"]).get("Location"), f"/?view=application&employer_id={employer['id']}")

        locked_save = call_app(
            self.app,
            method="POST",
            path="/applications/ichra/save",
            body=f"employer_id={employer['id']}&artifact_action=save&legal_name=Lock+Co",
            cookie_header=employer_cookie,
        )
        self.assertEqual(dict(locked_save["headers"]).get("Location"), f"/?view=application&employer_id={employer['id']}")

        admin_renew = call_app(
            self.app,
            method="POST",
            path="/applications/ichra/renew",
            body=f"employer_id={employer['id']}",
            cookie_header=admin_cookie,
        )
        self.assertEqual(dict(admin_renew["headers"]).get("Location"), f"/?view=application&employer_id={employer['id']}")

        db = self.app.db()
        artifact = db.execute("SELECT access_token_status, artifact_status FROM ichra_applications WHERE employer_id = ?", (employer["id"],)).fetchone()
        db.close()
        self.assertEqual(artifact["access_token_status"], "active")
        self.assertEqual(artifact["artifact_status"], "draft")

    def test_each_team_has_single_team_super_admin_flag(self):
        db = self.app.db()
        team_id = db.execute("SELECT id FROM teams WHERE name = 'Core Admin Team'").fetchone()["id"]
        flagged = db.execute(
            "SELECT id FROM users WHERE team_id = ? AND is_team_super_admin = 1 AND role IN ('admin','broker') AND is_active = 1",
            (team_id,),
        ).fetchall()
        db.close()
        self.assertEqual(len(flagged), 1)

    def test_super_admin_can_reassign_team_super_admin(self):
        super_cookie = ""
        super_cookie = merge_cookies(super_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])

        create_broker = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=teamsuperbroker&role=broker&team_id=1",
            cookie_header=super_cookie,
        )
        self.assertEqual(dict(create_broker["headers"]).get("Location"), "/")
        broker = next(u for u in self.app.get_users_with_completion() if u["username"] == "teamsuperbroker")

        assign = call_app(
            self.app,
            method="POST",
            path="/teams/assign-team-super-admin",
            body=f"team_id=1&user_id={broker['id']}",
            cookie_header=super_cookie,
        )
        self.assertEqual(dict(assign["headers"]).get("Location"), "/?view=team")

        db = self.app.db()
        current = db.execute(
            "SELECT username FROM users WHERE team_id = 1 AND is_team_super_admin = 1 AND role IN ('admin','broker')"
        ).fetchall()
        db.close()
        self.assertEqual(len(current), 1)
        self.assertEqual(current[0]["username"], "teamsuperbroker")

    def test_team_super_admin_broker_can_create_team_admin_user(self):
        super_cookie = ""
        super_cookie = merge_cookies(super_cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=tierbroker&role=broker&team_id=1",
            cookie_header=super_cookie,
        )
        broker_user = next(u for u in self.app.get_users_with_completion() if u["username"] == "tierbroker")
        call_app(
            self.app,
            method="POST",
            path="/teams/assign-team-super-admin",
            body=f"team_id=1&user_id={broker_user['id']}",
            cookie_header=super_cookie,
        )

        broker_cookie = ""
        broker_cookie = merge_cookies(
            broker_cookie,
            call_app(self.app, method="POST", path="/login", body="username=tierbroker&password=user")["headers"],
        )
        create_admin = call_app(
            self.app,
            method="POST",
            path="/admin/users/create",
            body="username=teamadmin2&role=admin",
            cookie_header=broker_cookie,
        )
        self.assertEqual(dict(create_admin["headers"]).get("Location"), "/")

        relogin = call_app(self.app, method="POST", path="/login", body="username=teamadmin2&password=user")
        self.assertEqual(dict(relogin["headers"]).get("Location"), "/")
    def test_system_nav_item_routes_to_subnav_sections(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie, query_string="view=dashboard")
        self.assertIn("href='/?view=system'", dashboard["body"])

        system_view = call_app(self.app, method="GET", path="/", cookie_header=cookie, query_string="view=system&system_view=logs")
        self.assertIn("Permissions", system_view["body"])
        self.assertIn("Activity Log", system_view["body"])
        self.assertIn("Dev Log", system_view["body"])

    def test_employer_can_update_own_settings(self):
        admin_cookie = ""
        admin_cookie = merge_cookies(admin_cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])
        call_app(
            self.app,
            method="POST",
            path="/employers/create",
            body=(
                "legal_name=Settings+Co&contact_name=Elle&work_email=elle%40settings.com&phone=555"
                "&company_size=10&industry=Retail&website=https%3A%2F%2Fsettings.com&state=WA"
            ),
            cookie_header=admin_cookie,
        )

        db = self.app.db()
        employer_user = db.execute("SELECT username FROM users WHERE role='employer' ORDER BY id DESC LIMIT 1").fetchone()
        db.close()

        employer_cookie = ""
        employer_cookie = merge_cookies(
            employer_cookie,
            call_app(self.app, method="POST", path="/login", body=f"username={employer_user['username']}&password=user")["headers"],
        )

        update = call_app(
            self.app,
            method="POST",
            path="/settings/profile",
            body=f"username={employer_user['username']}2&password=newpass",
            cookie_header=employer_cookie,
        )
        self.assertEqual(dict(update["headers"]).get("Location"), "/")

        relogin = call_app(self.app, method="POST", path="/login", body=f"username={employer_user['username']}2&password=newpass")
        self.assertEqual(dict(relogin["headers"]).get("Location"), "/")


    def test_super_admin_sees_new_ui_toggle_only_on_dashboard(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie, query_string="view=dashboard")
        self.assertIn("action='/settings/ui-mode'", dashboard["body"])
        self.assertIn("New UI", dashboard["body"])

        users_view = call_app(self.app, method="GET", path="/", cookie_header=cookie, query_string="view=application")
        self.assertNotIn("action='/settings/ui-mode'", users_view["body"])

    def test_non_super_admin_never_sees_new_ui_toggle(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=alex&password=user")["headers"])

        dashboard = call_app(self.app, method="GET", path="/", cookie_header=cookie, query_string="view=dashboard")
        self.assertNotIn("action='/settings/ui-mode'", dashboard["body"])

    def test_super_admin_can_toggle_new_ui_and_preference_persists(self):
        cookie = ""
        cookie = merge_cookies(cookie, call_app(self.app, method="POST", path="/login", body="username=admin&password=user")["headers"])

        toggle_on = call_app(
            self.app,
            method="POST",
            path="/settings/ui-mode",
            body="view=dashboard&ui_mode=NEW",
            cookie_header=cookie,
        )
        self.assertEqual(dict(toggle_on["headers"]).get("Location"), "/?view=dashboard")

        dashboard_new = call_app(self.app, method="GET", path="/", cookie_header=cookie, query_string="view=dashboard")
        self.assertIn("new-ui-shell", dashboard_new["body"])

        db = self.app.db()
        user = db.execute("SELECT ui_mode FROM users WHERE username = 'admin'").fetchone()
        db.close()
        self.assertEqual(user["ui_mode"], "NEW")



if __name__ == "__main__":
    unittest.main()
