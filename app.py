from __future__ import annotations

import hashlib
import hmac
import html
import os
import sqlite3
from http import cookies
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "app.db"
PROCESS_SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
ALLOWED_THEMES = {"default", "sunset", "midnight"}
ALLOWED_DENSITIES = {"comfortable", "compact"}

DEV_LOG_ENTRIES = [
    {"pr": 1, "change": "Built the first monolith task tracker shell.", "result": "Shipped an initial login + task completion flow as a runnable baseline.", "why": "Establish a deployable product foundation before layering in infrastructure and roles."},
    {"pr": 2, "change": "Added guidance for connecting the repository to Linode.", "result": "Deployment setup became documented and repeatable.", "why": "Reduce onboarding friction and avoid one-off deploy knowledge."},
    {"pr": 3, "change": "Fixed missing requirements.txt path issues.", "result": "Build/install steps stopped failing during environment setup.", "why": "Unblock runtime provisioning and prevent startup errors."},
    {"pr": 4, "change": "Repaired nginx service startup configuration.", "result": "Web service boot reliability improved.", "why": "Address infra-level blocker causing the app to stay unavailable."},
    {"pr": 5, "change": "Fixed another 502 failure on the webpage.", "result": "Traffic routed correctly again.", "why": "Stabilize user access after proxy/runtime mismatch."},
    {"pr": 6, "change": "Added additional 502 remediation for the monolith app.", "result": "Production routing became more resilient.", "why": "Harden service uptime across deploy attempts."},
    {"pr": 7, "change": "Completed a final 502-focused fix pass.", "result": "Resolved recurring gateway errors in the live stack.", "why": "Close repeated incident pattern before feature expansion."},
    {"pr": 8, "change": "Introduced manual trigger support for code push workflows.", "result": "Operators could run CI/CD on demand.", "why": "Improve release control for urgent fixes and validation."},
    {"pr": 9, "change": "Extended/refined manual trigger behavior in the pipeline.", "result": "Workflow controls became easier to execute consistently.", "why": "Make deployment operations safer and more predictable."},
    {"pr": 10, "change": "Created CI/CD workflow for Linode deployment.", "result": "Automated deploy path replaced manual-only steps.", "why": "Speed delivery and reduce drift between environments."},
    {"pr": 11, "change": "Updated the login screen experience.", "result": "Authentication entry point became clearer for users.", "why": "Improve first-touch usability in the app."},
    {"pr": 12, "change": "Added a GitHub Actions CI/CD pipeline.", "result": "Build and deployment checks became standardized in repo automation.", "why": "Increase confidence in merges and deployment repeatability."},
    {"pr": 13, "change": "Debugged production login issues.", "result": "Authentication reliability improved in deployed environments.", "why": "Solve real-user login blockers before scaling usage."},
    {"pr": 14, "change": "Fixed login flows and password management behavior.", "result": "Session/auth handling became more dependable.", "why": "Eliminate user lockout and inconsistent credential behavior."},
    {"pr": 15, "change": "Changed seeded user passwords to password123.", "result": "Demo/test account expectations were aligned.", "why": "Provide a consistent default during stabilization."},
    {"pr": 16, "change": "Resolved login loop caused by session key issues.", "result": "Successful login persisted correctly across redirects.", "why": "Fix a critical auth/session regression."},
    {"pr": 17, "change": "Fixed multi-cookie parsing for session validation.", "result": "Session detection became accurate with richer cookie headers.", "why": "Handle real browser cookie behavior safely."},
    {"pr": 18, "change": "Cleaned code and fixed task completion form parsing scope.", "result": "Task completion no longer stalled unexpectedly.", "why": "Address correctness and maintainability together."},
    {"pr": 19, "change": "Added user settings and a super admin role with stronger dashboard styling.", "result": "System gained administrative user lifecycle controls.", "why": "Support role-based administration as product complexity increased."},
    {"pr": 20, "change": "Introduced employer onboarding workflow with role-scoped visibility.", "result": "Employer account creation and scoped views were available.", "why": "Expand from internal task tracking to onboarding operations."},
    {"pr": 21, "change": "Reverted PR #20.", "result": "Prior behavior was restored.", "why": "Rollback risk while iterating toward a safer onboarding implementation."},
    {"pr": 22, "change": "Reintroduced employer onboarding while preserving existing dashboard features.", "result": "Onboarding returned without regressing prior functionality.", "why": "Deliver onboarding needs with lower disruption."},
    {"pr": 23, "change": "Added navigation-driven dashboard and rebuilt a full ICHRA application form.", "result": "UI became tabbed and workflow-oriented.", "why": "Improve information architecture as feature surface grew."},
    {"pr": 24, "change": "Added broker and employer role-specific experiences.", "result": "Role-tailored dashboards and permissions became first class.", "why": "Match product behavior to real participant responsibilities."},
    {"pr": 25, "change": "Added employer settings editing, DB-backed login hints, and admin activity logs.", "result": "Operational visibility and account support tooling improved.", "why": "Increase admin traceability and self-service controls."},
    {"pr": 26, "change": "Improved employer settings flow, log filter UX, and password policy.", "result": "Settings and audit workflows became easier and safer.", "why": "Polish day-to-day admin workflows after initial rollout."},
    {"pr": 27, "change": "Split employer setup from ICHRA app and added notifications.", "result": "Workflow boundaries became clearer and users gained update visibility.", "why": "Reduce confusion and proactively surface important events."},
    {"pr": 28, "change": "Adjusted setup toggle flow and redesigned employer settings dashboard.", "result": "Settings UI changed significantly.", "why": "Improve responsiveness and clarity in employer configuration."},
    {"pr": 29, "change": "Reverted PR #28.", "result": "Dashboard/settings behavior returned to known-stable implementation.", "why": "Rollback after issues with the redesign/toggle behavior."},
    {"pr": 30, "change": "Fixed employer app toggles and delivered an updated settings dashboard layout.", "result": "Redesign landed with corrected behavior.", "why": "Reapply UX improvements without the regressions that triggered the prior revert."},
]


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


class TaskTrackerApp:
    def __init__(self, db_path: str | None = None, secret_key: str | None = None):
        self.db_path = db_path or str(DEFAULT_DB)
        runtime_secret = secret_key or PROCESS_SECRET_KEY
        self.secret_key = runtime_secret.encode("utf-8")
        self.init_db()

    def init_db(self) -> None:
        db = sqlite3.connect(self.db_path)
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_hint TEXT NOT NULL DEFAULT 'user',
                role TEXT NOT NULL DEFAULT 'admin',
                theme TEXT NOT NULL DEFAULT 'default',
                density TEXT NOT NULL DEFAULT 'comfortable',
                created_by_user_id INTEGER,
                last_login_at TEXT,
                must_change_password INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS task_completions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(task_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS employers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                legal_name TEXT NOT NULL,
                contact_name TEXT NOT NULL,
                work_email TEXT NOT NULL,
                phone TEXT NOT NULL,
                company_size TEXT NOT NULL,
                industry TEXT NOT NULL,
                website TEXT NOT NULL,
                state TEXT NOT NULL,
                onboarding_task TEXT NOT NULL,
                ichra_started INTEGER NOT NULL DEFAULT 0,
                application_complete INTEGER NOT NULL DEFAULT 0,
                linked_user_id INTEGER NOT NULL UNIQUE,
                created_by_user_id INTEGER NOT NULL,
                broker_user_id INTEGER,
                primary_user_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                seen INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_user_id INTEGER,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id INTEGER,
                target_label TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        columns = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "role" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")
        if "password_hint" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN password_hint TEXT NOT NULL DEFAULT 'user'")
        if "theme" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'default'")
        if "density" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN density TEXT NOT NULL DEFAULT 'comfortable'")
        if "created_by_user_id" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN created_by_user_id INTEGER")
        if "last_login_at" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN last_login_at TEXT")
        if "must_change_password" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 1")

        db.executemany(
            """
            INSERT OR IGNORE INTO users (username, display_name, password_hash, password_hint, role)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                ("alex", "Alex", hash_password("user"), "user", "admin"),
                ("sam", "Sam", hash_password("user"), "user", "admin"),
                ("admin", "Super Admin", hash_password("user"), "user", "super_admin"),
            ],
        )
        db.executemany(
            """
            UPDATE users
            SET password_hash = ?
            WHERE username = ?
            """,
            [
                (hash_password("user"), "alex"),
                (hash_password("user"), "sam"),
                (hash_password("user"), "admin"),
            ],
        )
        db.executemany(
            """
            UPDATE users
            SET password_hint = ?
            WHERE username = ?
            """,
            [
                ("user", "alex"),
                ("user", "sam"),
                ("user", "admin"),
            ],
        )
        db.execute("UPDATE users SET role = 'admin' WHERE role = 'user'")
        db.execute("UPDATE users SET role = 'super_admin', created_by_user_id = NULL WHERE username = 'admin'")

        employer_columns = {row[1] for row in db.execute("PRAGMA table_info(employers)").fetchall()}
        if "application_complete" not in employer_columns:
            db.execute("ALTER TABLE employers ADD COLUMN application_complete INTEGER NOT NULL DEFAULT 0")
        if "ichra_started" not in employer_columns:
            db.execute("ALTER TABLE employers ADD COLUMN ichra_started INTEGER NOT NULL DEFAULT 0")
        if "broker_user_id" not in employer_columns:
            db.execute("ALTER TABLE employers ADD COLUMN broker_user_id INTEGER")
        if "primary_user_id" not in employer_columns:
            db.execute("ALTER TABLE employers ADD COLUMN primary_user_id INTEGER")
        db.execute(
            """
            INSERT OR IGNORE INTO tasks (id, title, description)
            VALUES (1, 'Deployment Readiness Task', 'Confirm the app works in Codespaces and on Linode.')
            """
        )
        db.commit()
        db.close()

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "/")
        method = environ.get("REQUEST_METHOD", "GET")
        query = parse_qs(environ.get("QUERY_STRING", ""))
        cookie = self.parse_cookies(environ.get("HTTP_COOKIE", ""))
        session_user = self.read_session_user(cookie)

        if path.startswith("/static/"):
            return self.serve_static(path, start_response)

        if path == "/":
            if not session_user:
                return self.redirect(start_response, "/login")
            return self.render_dashboard(start_response, session_user, self.consume_flash(cookie), query.get("view", ["dashboard"])[0], query)

        if path == "/login" and method == "GET":
            return self.render_login(start_response, self.consume_flash(cookie))

        if path == "/login" and method == "POST":
            return self.handle_login(start_response, self.parse_form(environ))

        if path == "/signup" and method == "POST":
            return self.handle_public_employer_signup(start_response, self.parse_form(environ))

        if path == "/logout" and method == "POST":
            return self.handle_logout(start_response)

        if path == "/task/complete" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] == "employer":
                return self.redirect(start_response, "/", flash=("error", "Employer accounts are read-only."))
            self.complete_for_user(session_user["id"], 1)
            self.log_action(session_user["id"], "task_completed", "task", 1, "Deployment Readiness Task", "Marked complete")
            return self.redirect(start_response, "/", flash=("success", "Task marked complete. Everyone can now see your status."))

        if path == "/settings/profile" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] == "employer":
                return self.redirect(start_response, "/", flash=("error", "Employer accounts are read-only."))
            return self.handle_profile_settings(start_response, session_user, self.parse_form(environ))

        if path == "/settings/style" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] == "employer":
                return self.redirect(start_response, "/", flash=("error", "Employer accounts are read-only."))
            return self.handle_style_settings(start_response, session_user, self.parse_form(environ))

        if path == "/admin/users/create" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] not in {"super_admin", "admin", "broker"}:
                return self.redirect(start_response, "/", flash=("error", "Only super admins, admins, and brokers can create users."))
            return self.handle_admin_create_user(start_response, session_user, self.parse_form(environ))

        if path == "/admin/users/update" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] not in {"super_admin", "admin", "broker"}:
                return self.redirect(start_response, "/", flash=("error", "Only super admins, admins, and brokers can modify users."))
            return self.handle_admin_update_user(start_response, session_user, self.parse_form(environ))

        if path == "/employers/create" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            return self.handle_create_employer(start_response, session_user, self.parse_form(environ))

        if path == "/employers/application" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] != "employer":
                return self.redirect(start_response, "/", flash=("error", "Only employer accounts can update applications."))
            complete = self.parse_form(environ).get("status", "") == "complete"
            self.mark_employer_application(session_user["id"], complete)
            self.log_action(session_user["id"], "application_status_changed", "employer", session_user["id"], session_user["username"], f"status={'complete' if complete else 'incomplete'}")
            return self.redirect(start_response, "/", flash=("success", "ICHRA setup status updated."))

        if path == "/employers/start-ichra" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] != "employer":
                return self.redirect(start_response, "/", flash=("error", "Only employer accounts can start ICHRA setup."))
            self.start_employer_ichra(session_user["id"])
            self.log_action(session_user["id"], "ichra_started", "employer", session_user["id"], session_user["username"], "Employer started ICHRA setup")
            return self.redirect(start_response, "/?view=applications", flash=("success", "ICHRA setup application started."))

        if path == "/employers/refer" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] != "broker":
                return self.redirect(start_response, "/", flash=("error", "Only brokers can refer clients."))
            return self.handle_broker_refer_client(start_response, session_user, self.parse_form(environ))

        if path == "/notifications/seen" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            return self.handle_mark_notification_seen(start_response, session_user, self.parse_form(environ))

        if path == "/employers/settings" and method == "GET":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] not in {"super_admin", "admin", "broker"}:
                return self.redirect(start_response, "/", flash=("error", "You do not have permission to edit employer settings."))
            try:
                employer_id = int(query.get("id", [""])[0])
            except ValueError:
                return self.redirect(start_response, "/?view=employers", flash=("error", "Invalid employer selected."))
            return self.render_employer_settings_page(start_response, session_user, employer_id, self.consume_flash(cookie))

        if path == "/employers/update" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] not in {"super_admin", "admin", "broker"}:
                return self.redirect(start_response, "/", flash=("error", "You do not have permission to edit employer settings."))
            return self.handle_update_employer(start_response, session_user, self.parse_form(environ))

        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Not found"]

    def parse_cookies(self, cookie_header: str):
        jar = cookies.SimpleCookie()
        if cookie_header:
            jar.load(cookie_header)
        return jar

    def parse_form(self, environ):
        raw_length = environ.get("CONTENT_LENGTH", "")
        body = b""
        try:
            size = int(raw_length) if raw_length else 0
        except ValueError:
            size = 0

        if size > 0:
            body = environ["wsgi.input"].read(size)
        elif environ.get("REQUEST_METHOD") == "POST":
            body = environ["wsgi.input"].read()

        data = parse_qs(body.decode("utf-8")) if body else {}
        return {k: v[0] for k, v in data.items()}

    def db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_user(self, username: str):
        db = self.db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        db.close()
        return user

    def get_user_by_id(self, user_id: int):
        db = self.db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        db.close()
        return user

    def get_users_with_completion(self):
        db = self.db()
        rows = db.execute(
            """
            SELECT u.id, u.username, u.display_name, u.role, u.created_by_user_id,
                   CASE WHEN tc.id IS NULL THEN 0 ELSE 1 END AS completed
            FROM users u
            LEFT JOIN task_completions tc
                ON tc.user_id = u.id AND tc.task_id = 1
            WHERE u.role != 'employer'
            ORDER BY u.id
            """
        ).fetchall()
        db.close()
        return rows

    def get_login_demo_accounts(self):
        db = self.db()
        rows = db.execute(
            """
            SELECT username, role, password_hint
            FROM users
            WHERE role IN ('super_admin', 'admin', 'broker')
            ORDER BY role, last_login_at DESC, id DESC
            """
        ).fetchall()
        db.close()

        picks = {}
        for row in rows:
            if row["role"] not in picks:
                picks[row["role"]] = row
        ordered_roles = ["super_admin", "admin", "broker"]
        return [picks[r] for r in ordered_roles if r in picks]

    def log_action(self, actor_user_id: int | None, action: str, entity_type: str, entity_id: int | None, target_label: str, details: str = ""):
        db = self.db()
        db.execute(
            """
            INSERT INTO activity_logs (actor_user_id, action, entity_type, entity_id, target_label, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (actor_user_id, action, entity_type, entity_id, target_label, details),
        )
        db.commit()
        db.close()

    def list_activity_logs(self, filters: dict[str, list[str]]):
        where = []
        params = []
        role = filters.get("role", [""])[0]
        action = filters.get("action", [""])[0]
        search = filters.get("q", [""])[0].strip().lower()

        if role:
            where.append("actor.role = ?")
            params.append(role)
        if action:
            where.append("l.action = ?")
            params.append(action)
        if search:
            where.append("(LOWER(l.target_label) LIKE ? OR LOWER(l.details) LIKE ? OR LOWER(COALESCE(actor.username, 'system')) LIKE ?)")
            pattern = f"%{search}%"
            params.extend([pattern, pattern, pattern])

        sql = """
            SELECT l.*, COALESCE(actor.username, 'system') AS actor_username, COALESCE(actor.role, 'system') AS actor_role
            FROM activity_logs l
            LEFT JOIN users actor ON actor.id = l.actor_user_id
        """
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY l.created_at DESC, l.id DESC LIMIT 200"

        db = self.db()
        rows = db.execute(sql, params).fetchall()
        db.close()
        return rows

    def list_visible_employers(self, session_user):
        db = self.db()
        if session_user["role"] == "super_admin":
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username,
                       broker.username AS broker_username
                FROM employers e
                JOIN users u ON u.id = e.linked_user_id
                LEFT JOIN users broker ON broker.id = e.broker_user_id
                ORDER BY e.created_at DESC
                """
            ).fetchall()
        elif session_user["role"] == "admin":
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username,
                       broker.username AS broker_username
                FROM employers e
                JOIN users u ON u.id = e.linked_user_id
                LEFT JOIN users broker ON broker.id = e.broker_user_id
                WHERE e.created_by_user_id = ?
                   OR e.primary_user_id = ?
                   OR e.broker_user_id IN (SELECT id FROM users WHERE created_by_user_id = ? AND role = 'broker')
                ORDER BY e.created_at DESC
                """,
                (session_user["id"], session_user["id"], session_user["id"]),
            ).fetchall()
        elif session_user["role"] == "broker":
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username,
                       broker.username AS broker_username
                FROM employers e
                JOIN users u ON u.id = e.linked_user_id
                LEFT JOIN users broker ON broker.id = e.broker_user_id
                WHERE e.broker_user_id = ?
                   OR e.created_by_user_id = ?
                ORDER BY e.created_at DESC
                """,
                (session_user["id"], session_user["id"]),
            ).fetchall()
        elif session_user["role"] == "employer":
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username,
                       broker.username AS broker_username
                FROM employers e
                JOIN users u ON u.id = e.linked_user_id
                LEFT JOIN users broker ON broker.id = e.broker_user_id
                WHERE e.linked_user_id = ?
                ORDER BY e.created_at DESC
                """,
                (session_user["id"],),
            ).fetchall()
        else:
            rows = []
        db.close()
        return rows

    def get_manageable_brokers(self, session_user):
        db = self.db()
        if session_user["role"] == "super_admin":
            rows = db.execute("SELECT id, username, display_name FROM users WHERE role = 'broker' ORDER BY username").fetchall()
        elif session_user["role"] == "admin":
            rows = db.execute(
                """
                SELECT id, username, display_name
                FROM users
                WHERE role = 'broker' AND created_by_user_id = ?
                ORDER BY username
                """,
                (session_user["id"],),
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT id, username, display_name
                FROM users
                WHERE role = 'broker' AND id = ?
                ORDER BY username
                """,
                (session_user["id"],),
            ).fetchall()
        db.close()
        return rows

    def list_notifications(self, user_id: int):
        db = self.db()
        rows = db.execute(
            "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC, id DESC",
            (user_id,),
        ).fetchall()
        db.close()
        return rows

    def create_notification(self, user_id: int, message: str):
        db = self.db()
        db.execute("INSERT INTO notifications (user_id, message) VALUES (?, ?)", (user_id, message))
        db.commit()
        db.close()

    def mark_notification_seen(self, user_id: int, notification_id: int):
        db = self.db()
        db.execute("UPDATE notifications SET seen = 1 WHERE id = ? AND user_id = ?", (notification_id, user_id))
        db.commit()
        db.close()

    def find_default_primary_user_id(self, db, creator_user_id: int, broker_user_id: int | None):
        if broker_user_id:
            row = db.execute("SELECT id FROM users WHERE id = ?", (broker_user_id,)).fetchone()
            if row:
                return row["id"]
        row = db.execute("SELECT id FROM users WHERE id = ?", (creator_user_id,)).fetchone()
        if row:
            return row["id"]
        admin = db.execute("SELECT id FROM users WHERE role = 'super_admin' ORDER BY id LIMIT 1").fetchone()
        return admin["id"] if admin else None

    def mark_employer_application(self, employer_user_id: int, complete: bool):
        db = self.db()
        db.execute("UPDATE employers SET ichra_started = 1, application_complete = ? WHERE linked_user_id = ?", (1 if complete else 0, employer_user_id))
        employer = db.execute("SELECT legal_name, primary_user_id FROM employers WHERE linked_user_id = ?", (employer_user_id,)).fetchone()
        db.commit()
        db.close()
        if complete and employer and employer["primary_user_id"]:
            self.create_notification(employer["primary_user_id"], f"ICHRA setup completed by {employer['legal_name']}.")

    def start_employer_ichra(self, employer_user_id: int):
        db = self.db()
        db.execute("UPDATE employers SET ichra_started = 1 WHERE linked_user_id = ?", (employer_user_id,))
        db.commit()
        db.close()

    def refer_client_ichra(self, employer_id: int):
        db = self.db()
        employer = db.execute("SELECT id, legal_name, linked_user_id FROM employers WHERE id = ?", (employer_id,)).fetchone()
        if not employer:
            db.close()
            return None
        db.execute("UPDATE employers SET ichra_started = 1 WHERE id = ?", (employer_id,))
        db.commit()
        db.close()
        return employer

    def complete_for_user(self, user_id: int, task_id: int):
        db = self.db()
        db.execute("INSERT OR IGNORE INTO task_completions (task_id, user_id) VALUES (?, ?)", (task_id, user_id))
        db.commit()
        db.close()

    def update_user_profile(self, user_id: int, username: str, password: str):
        db = self.db()
        current = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        new_password = hash_password(password) if password else current["password_hash"]
        db.execute(
            "UPDATE users SET username = ?, display_name = ?, password_hash = ?, password_hint = ?, must_change_password = ? WHERE id = ?",
            (username, username.capitalize(), new_password, password or current["password_hint"], 0 if password else current["must_change_password"], user_id),
        )
        db.commit()
        db.close()

    def update_user_style(self, user_id: int, theme: str, density: str):
        db = self.db()
        db.execute("UPDATE users SET theme = ?, density = ? WHERE id = ?", (theme, density, user_id))
        db.commit()
        db.close()

    def create_user(self, username: str, password: str, role: str, created_by_user_id: int | None = None):
        db = self.db()
        db.execute(
            "INSERT INTO users (username, display_name, password_hash, password_hint, role, created_by_user_id, must_change_password) VALUES (?, ?, ?, ?, ?, ?, 1)",
            (username, username.capitalize(), hash_password(password), password, role, created_by_user_id),
        )
        db.commit()
        db.close()

    def admin_update_user(self, user_id: int, username: str, role: str, password: str):
        db = self.db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            db.close()
            raise ValueError("User not found")
        password_hash = hash_password(password) if password else user["password_hash"]
        db.execute(
            "UPDATE users SET username = ?, display_name = ?, role = ?, password_hash = ?, password_hint = ?, must_change_password = ? WHERE id = ?",
            (username, username.capitalize(), role, password_hash, password or user["password_hint"], 0 if password else user["must_change_password"], user_id),
        )
        db.commit()
        db.close()

    def build_employer_username(self, db, legal_name: str) -> str:
        seed = "".join(ch for ch in legal_name.lower() if ch.isalnum())[:12] or "employer"
        count = db.execute("SELECT COUNT(*) AS n FROM users WHERE username LIKE ?", (f"{seed}%",)).fetchone()["n"]
        return f"{seed}{count + 1}"

    def create_employer(self, creator_user_id: int, form: dict[str, str], broker_user_id: int | None = None) -> str:
        db = self.db()
        username = self.build_employer_username(db, form["legal_name"])
        display_name = form["contact_name"].strip() or form["legal_name"].strip()
        db.execute(
            """
            INSERT INTO users (username, display_name, password_hash, password_hint, role, created_by_user_id)
            VALUES (?, ?, ?, ?, 'employer', ?)
            """,
            (username, display_name, hash_password("user"), "user", creator_user_id),
        )
        linked_user_id = db.execute("SELECT last_insert_rowid() AS i").fetchone()["i"]

        primary_user_id = self.find_default_primary_user_id(db, creator_user_id, broker_user_id)

        db.execute(
            """
            INSERT INTO employers (
                legal_name, contact_name, work_email, phone, company_size,
                industry, website, state, onboarding_task, ichra_started, application_complete, linked_user_id, created_by_user_id, broker_user_id, primary_user_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                form["legal_name"].strip(),
                form["contact_name"].strip(),
                form["work_email"].strip().lower(),
                form["phone"].strip(),
                form["company_size"].strip(),
                form["industry"].strip(),
                form["website"].strip(),
                form["state"].strip(),
                "Complete benefits roster import and confirm renewal month.",
                0,
                0,
                linked_user_id,
                creator_user_id,
                broker_user_id,
                primary_user_id,
            ),
        )
        db.commit()
        db.close()
        return username

    def update_employer_settings(self, employer_id: int, form: dict[str, str]):
        db = self.db()
        broker_user_id = int(form["broker_user_id"]) if form.get("broker_user_id") else None
        primary_user_id = int(form["primary_user_id"]) if form.get("primary_user_id") else None
        db.execute(
            """
            UPDATE employers
            SET legal_name = ?, contact_name = ?, work_email = ?, phone = ?,
                company_size = ?, industry = ?, website = ?, state = ?, onboarding_task = ?,
                broker_user_id = ?, primary_user_id = ?
            WHERE id = ?
            """,
            (
                form["legal_name"],
                form["contact_name"],
                form["work_email"],
                form["phone"],
                form["company_size"],
                form["industry"],
                form["website"],
                form["state"],
                form["onboarding_task"],
                broker_user_id,
                primary_user_id,
                employer_id,
            ),
        )
        employer_row = db.execute("SELECT linked_user_id FROM employers WHERE id = ?", (employer_id,)).fetchone()
        if employer_row:
            linked_user_id = employer_row["linked_user_id"]
            current_user = db.execute("SELECT * FROM users WHERE id = ?", (linked_user_id,)).fetchone()
            new_username = form["portal_username"].strip().lower()
            new_password = form.get("portal_password", "")
            password_hash = hash_password(new_password) if new_password else current_user["password_hash"]
            password_hint = new_password or current_user["password_hint"]
            must_change = 0 if new_password else current_user["must_change_password"]
            db.execute(
                "UPDATE users SET username = ?, display_name = ?, password_hash = ?, password_hint = ?, must_change_password = ? WHERE id = ?",
                (new_username, form["contact_name"], password_hash, password_hint, must_change, linked_user_id),
            )
        db.commit()
        db.close()

    def get_visible_employer_by_id(self, session_user, employer_id: int):
        rows = self.list_visible_employers(session_user)
        for row in rows:
            if row["id"] == employer_id:
                return row
        return None

    def sign(self, value: str) -> str:
        sig = hmac.new(self.secret_key, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{value}|{sig}"

    def unsign(self, value: str | None) -> str | None:
        if not value or "|" not in value:
            return None
        raw, sig = value.rsplit("|", 1)
        expected = hmac.new(self.secret_key, raw.encode("utf-8"), hashlib.sha256).hexdigest()
        return raw if hmac.compare_digest(sig, expected) else None

    def read_session_user(self, cookie: cookies.SimpleCookie):
        signed = cookie.get("session")
        if not signed:
            return None
        raw = self.unsign(signed.value)
        if not raw or not raw.startswith("uid:"):
            return None
        return self.get_user_by_id(int(raw.replace("uid:", "")))

    def consume_flash(self, cookie: cookies.SimpleCookie):
        flash_cookie = cookie.get("flash")
        raw = self.unsign(flash_cookie.value) if flash_cookie else None
        if not raw or ":" not in raw:
            return None
        category, message = raw.split(":", 1)
        return category, message

    def handle_login(self, start_response, form):
        user = self.get_user(form.get("username", "").strip())
        password = form.get("password", "")
        if not user or user["password_hash"] != hash_password(password):
            return self.redirect(start_response, "/login", flash=("error", "Invalid username or password."))

        db = self.db()
        db.execute("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", (user["id"],))
        db.commit()
        db.close()
        self.log_action(user["id"], "login", "user", user["id"], user["username"], "User signed in")

        headers = [
            ("Location", "/"),
            ("Set-Cookie", self.cookie_header("session", self.sign(f"uid:{user['id']}"))),
            ("Set-Cookie", self.cookie_header("flash", self.sign(f"success:Welcome, {user['display_name']}!"))),
        ]
        start_response("302 Found", headers)
        return [b""]

    def handle_profile_settings(self, start_response, session_user, form):
        username = form.get("username", "").strip().lower()
        password = form.get("password", "")

        if len(username) < 3:
            return self.redirect(start_response, "/", flash=("error", "Username must be at least 3 characters."))
        if password and len(password) < 6:
            return self.redirect(start_response, "/", flash=("error", "Password must be at least 6 characters."))

        try:
            self.update_user_profile(session_user["id"], username, password)
            self.log_action(session_user["id"], "profile_updated", "user", session_user["id"], username, "Updated profile settings")
        except sqlite3.IntegrityError:
            return self.redirect(start_response, "/", flash=("error", "That username is already in use."))
        return self.redirect(start_response, "/", flash=("success", "Profile updated."))

    def handle_style_settings(self, start_response, session_user, form):
        theme = form.get("theme", "default")
        density = form.get("density", "comfortable")
        if theme not in ALLOWED_THEMES or density not in ALLOWED_DENSITIES:
            return self.redirect(start_response, "/", flash=("error", "Invalid style settings."))
        self.update_user_style(session_user["id"], theme, density)
        self.log_action(session_user["id"], "style_updated", "user", session_user["id"], session_user["username"], f"theme={theme},density={density}")
        return self.redirect(start_response, "/", flash=("success", "Dashboard style saved."))

    def handle_admin_create_user(self, start_response, session_user, form):
        username = form.get("username", "").strip().lower()
        role = form.get("role", "admin")
        allowed_roles = {"admin", "broker", "employer", "super_admin"} if session_user["role"] == "super_admin" else {"broker", "employer"}
        if role not in allowed_roles:
            role = "admin"
        if len(username) < 3:
            return self.redirect(start_response, "/", flash=("error", "New users need a username (3+)."))
        try:
            self.create_user(username, "user", role, created_by_user_id=session_user["id"])
            self.log_action(session_user["id"], "user_created", "user", None, username, f"role={role}")
        except sqlite3.IntegrityError:
            return self.redirect(start_response, "/", flash=("error", "Unable to create user. Username may already exist."))
        return self.redirect(start_response, "/", flash=("success", "User created with temporary password: user."))

    def handle_admin_update_user(self, start_response, session_user, form):
        try:
            user_id = int(form.get("user_id", ""))
        except ValueError:
            return self.redirect(start_response, "/", flash=("error", "Invalid user selected."))
        username = form.get("username", "").strip().lower()
        role = form.get("role", "admin")
        password = form.get("password", "")
        allowed_roles = {"admin", "broker", "employer", "super_admin"} if session_user["role"] == "super_admin" else {"broker", "employer"}
        if role not in allowed_roles:
            role = "admin"
        if len(username) < 3:
            return self.redirect(start_response, "/", flash=("error", "Username must be at least 3 characters."))

        try:
            self.admin_update_user(user_id, username, role, password)
            self.log_action(session_user["id"], "user_updated", "user", user_id, username, f"role={role}")
        except ValueError:
            return self.redirect(start_response, "/", flash=("error", "User no longer exists."))
        except sqlite3.IntegrityError:
            return self.redirect(start_response, "/", flash=("error", "Cannot update user to that username."))
        return self.redirect(start_response, "/", flash=("success", "User updated."))

    def handle_create_employer(self, start_response, session_user, form):
        if session_user["role"] == "employer":
            return self.redirect(start_response, "/", flash=("error", "Employer accounts are read-only."))
        mode = form.get("setup_mode", "basic")

        if mode == "ichra":
            try:
                existing_employer_id = int(form.get("existing_employer_id", ""))
            except ValueError:
                return self.redirect(start_response, "/?view=application", flash=("error", "Select an existing employer for ICHRA setup."))
            employer = self.get_visible_employer_by_id(session_user, existing_employer_id)
            if not employer:
                return self.redirect(start_response, "/?view=application", flash=("error", "Employer not found in your access scope."))
            self.start_employer_ichra(employer["linked_user_id"])
            self.mark_employer_application(employer["linked_user_id"], False)
            self.log_action(session_user["id"], "employer_updated", "employer", employer["id"], employer["legal_name"], "ICHRA setup application submitted")
            self.create_notification(session_user["id"], f"{employer['legal_name']} ICHRA setup application submitted.")
            return self.redirect(
                start_response,
                "/?view=employers",
                flash=("success", f"ICHRA setup submitted for {employer['legal_name']}.")
            )

        if not form.get("contact_name", "").strip():
            primary_first = form.get("primary_first_name", "").strip()
            primary_last = form.get("primary_last_name", "").strip()
            form["contact_name"] = f"{primary_first} {primary_last}".strip()
        form["work_email"] = form.get("work_email") or form.get("primary_email", "")
        form["phone"] = form.get("phone") or form.get("primary_phone", "")
        form["company_size"] = form.get("company_size") or form.get("total_employee_count", "")
        form["industry"] = form.get("industry") or form.get("nature_of_business", "")
        form["website"] = form.get("website") or "Not provided"
        form["state"] = form.get("state") or form.get("physical_state", "")

        required = ["legal_name", "contact_name", "work_email", "phone", "company_size", "industry", "website", "state"]
        if any(not form.get(name, "").strip() for name in required):
            return self.redirect(start_response, "/?view=application", flash=("error", "Please complete all required application fields."))

        broker_user_id = session_user["id"] if session_user["role"] == "broker" else None
        username = self.create_employer(session_user["id"], form, broker_user_id=broker_user_id)
        self.log_action(session_user["id"], "employer_created", "employer", None, form["legal_name"].strip(), f"portal_username={username}")
        self.create_notification(session_user["id"], f"{form['legal_name'].strip()} basic employer setup submitted.")
        return self.redirect(
            start_response,
            "/?view=employers",
            flash=("success", f"Employer created from Basic Employer Setup. Portal username: {username}, temporary password: user"),
        )

    def handle_broker_refer_client(self, start_response, session_user, form):
        try:
            employer_id = int(form.get("employer_id", ""))
        except ValueError:
            return self.redirect(start_response, "/", flash=("error", "Select an employer to refer."))
        employer = self.get_visible_employer_by_id(session_user, employer_id)
        if not employer:
            return self.redirect(start_response, "/", flash=("error", "Employer not found for your broker portfolio."))
        employer_row = self.refer_client_ichra(employer_id)
        if not employer_row:
            return self.redirect(start_response, "/", flash=("error", "Employer not found."))
        self.create_notification(employer_row["linked_user_id"], "Your ICHRA setup application is ready and waiting for you to finish.")
        self.log_action(session_user["id"], "ichra_referred", "employer", employer_id, employer_row["legal_name"], "Broker referred client for ICHRA setup")
        return self.redirect(start_response, "/", flash=("success", f"Invitation sent to {employer_row['legal_name']}."))

    def handle_update_employer(self, start_response, session_user, form):
        try:
            employer_id = int(form.get("employer_id", ""))
        except ValueError:
            return self.redirect(start_response, "/?view=employers", flash=("error", "Invalid employer selected."))

        employer = self.get_visible_employer_by_id(session_user, employer_id)
        if not employer:
            return self.redirect(start_response, "/?view=employers", flash=("error", "Employer not found for your access scope."))

        required = ["legal_name", "contact_name", "work_email", "phone", "company_size", "industry", "website", "state", "onboarding_task", "portal_username"]
        clean = {key: form.get(key, "").strip() for key in required}
        if any(not clean[key] for key in required):
            return self.redirect(start_response, f"/employers/settings?id={employer_id}", flash=("error", "All employer settings fields are required."))

        if len(clean["portal_username"]) < 3:
            return self.redirect(start_response, f"/employers/settings?id={employer_id}", flash=("error", "Employer username must be at least 3 characters."))
        portal_password = form.get("portal_password", "")
        if portal_password and len(portal_password) < 4:
            return self.redirect(start_response, f"/employers/settings?id={employer_id}", flash=("error", "Employer password must be at least 4 characters."))
        clean["portal_password"] = portal_password

        clean["broker_user_id"] = form.get("broker_user_id", "").strip()
        clean["primary_user_id"] = form.get("primary_user_id", "").strip()

        self.update_employer_settings(employer_id, clean)
        self.log_action(session_user["id"], "employer_updated", "employer", employer_id, clean["legal_name"], "Employer settings updated")
        return self.redirect(start_response, f"/employers/settings?id={employer_id}", flash=("success", "Employer settings updated."))

    def handle_public_employer_signup(self, start_response, form):
        form["contact_name"] = form.get("prospect_name", "")
        form["work_email"] = form.get("prospect_email", "")
        form["phone"] = form.get("prospect_phone", "") or "Not provided"
        form["company_size"] = form.get("company_size", "") or "Unknown"
        form["industry"] = form.get("industry", "") or "Unknown"
        form["website"] = form.get("website", "") or "Not provided"
        form["state"] = form.get("state", "") or "Unknown"

        required = ["legal_name", "contact_name", "work_email"]
        if any(not form.get(name, "").strip() for name in required):
            return self.redirect(start_response, "/login", flash=("error", "Please complete employer name, contact, and email."))

        portal_username = self.create_employer(creator_user_id=1, form=form, broker_user_id=None)
        self.log_action(None, "employer_signup_requested", "employer", None, form["legal_name"].strip(), f"portal_username={portal_username}")
        return self.redirect(
            start_response,
            "/login",
            flash=("success", "Employer request submitted. Use provided portal credentials after ICHRA setup is completed."),
        )

    def handle_mark_notification_seen(self, start_response, session_user, form):
        try:
            notification_id = int(form.get("notification_id", ""))
        except ValueError:
            return self.redirect(start_response, "/?view=notifications", flash=("error", "Invalid notification."))
        self.mark_notification_seen(session_user["id"], notification_id)
        return self.redirect(start_response, "/?view=notifications", flash=("success", "Notification marked as seen."))

    def handle_logout(self, start_response):
        headers = [
            ("Location", "/login"),
            ("Set-Cookie", self.expire_cookie_header("session")),
            ("Set-Cookie", self.cookie_header("flash", self.sign("success:You have been logged out."))),
        ]
        start_response("302 Found", headers)
        return [b""]

    def redirect(self, start_response, location: str, flash: tuple[str, str] | None = None):
        headers = [("Location", location)]
        if flash:
            headers.append(("Set-Cookie", self.cookie_header("flash", self.sign(f"{flash[0]}:{flash[1]}"))))
        start_response("302 Found", headers)
        return [b""]

    def cookie_header(self, name: str, value: str):
        jar = cookies.SimpleCookie()
        jar[name] = value
        morsel = jar[name]
        morsel["path"] = "/"
        morsel["httponly"] = True
        morsel["samesite"] = "Lax"
        return morsel.OutputString()

    def expire_cookie_header(self, name: str):
        jar = cookies.SimpleCookie()
        jar[name] = ""
        morsel = jar[name]
        morsel["path"] = "/"
        morsel["max-age"] = 0
        morsel["httponly"] = True
        morsel["samesite"] = "Lax"
        return morsel.OutputString()

    def render_login(self, start_response, flash_message):
        demo_accounts = self.get_login_demo_accounts()
        demo_rows = "".join(
            f"<li><code>{html.escape(row['username'])}</code> / <code>{html.escape(row['password_hint'])}</code> <small>({html.escape(row['role'])})</small></li>"
            for row in demo_accounts
        )
        html_body = self.flash_html(flash_message) + f"""
            <section class="card auth-card">
              <p class="eyebrow">Monolith Workspace</p>
              <h1>Log in to continue</h1>
              <p class="subtitle">Choose your account and keep the deployment checklist moving.</p>
              <form method="post" action="/login" class="form-grid">
                <label>Username <input type="text" name="username" placeholder="alex" required /></label>
                <label>Password <input type="password" name="password" placeholder="user" required /></label>
                <button type="submit">Log In to Continue</button>
              </form>
              <div class="hint"><strong>Active demo accounts (DB-backed):</strong>
                <ul>{demo_rows or '<li>No active users found.</li>'}</ul>
              </div>
              <hr />
              <section class="section-block panel-card welcome-panel">
                <h2>New Employer Setup</h2>
                <p class="subtitle">Start your employer journey with a quick intake. We'll guide your team from first step to launch.</p>
                <button type="button" class="secondary" data-modal-open="new-employer-modal">Open New Employer Setup</button>
              </section>
            </section>
            <div class="modal" id="new-employer-modal" aria-hidden="true">
              <div class="modal-backdrop" data-modal-close="new-employer-modal"></div>
              <section class="modal-card card">
                <button type="button" class="modal-close" aria-label="Close" data-modal-close="new-employer-modal">×</button>
                <p class="eyebrow">Welcome aboard</p>
                <h2>Prospective Employer Sign Up</h2>
                <p class="subtitle">Tell us about your company and we will prepare your personalized onboarding workspace.</p>
                <form method="post" action="/signup" class="form-grid">
                  <label>Employer Legal Name <input type="text" name="legal_name" required /></label>
                  <label>Contact Name <input type="text" name="prospect_name" required /></label>
                  <label>Work Email <input type="email" name="prospect_email" required /></label>
                  <label>Phone <input type="text" name="prospect_phone" /></label>
                  <button type="submit">Submit Employer Request</button>
                </form>
              </section>
            </div>
            """
        html_doc = self.html_page("Monolith Task Tracker", html_body)
        headers = [("Content-Type", "text/html; charset=utf-8"), ("Set-Cookie", self.expire_cookie_header("flash"))]
        start_response("200 OK", headers)
        return [html_doc.encode("utf-8")]

    def render_dashboard(self, start_response, user, flash_message, active_view="dashboard", query=None):
        query = query or {}
        rows = self.get_users_with_completion()
        status_rows = "".join(
            (
                f"<li><span>{html.escape(row['display_name'])}"
                f" <small>({html.escape(row['username'])})</small></span>"
                f"<span class='pill {'complete' if row['completed'] else 'pending'}'>"
                f"{'Completed' if row['completed'] else 'Pending'}</span></li>"
            )
            for row in rows
        )

        role = user["role"]
        employers = self.list_visible_employers(user)
        employer_rows = "".join(
            f"""
            <tr>
              <td>{html.escape(row['legal_name'])}</td>
              <td>{html.escape(row['contact_name'])}</td>
              <td>{html.escape(row['work_email'])}</td>
              <td>{html.escape(row['portal_username'])}</td>
              <td>{html.escape(row['broker_username'] or 'Unassigned')}</td>
              <td>{'Complete' if row['application_complete'] else 'In progress'}</td>
              <td>{html.escape(row['onboarding_task'])}</td>
              <td>{self.render_employer_settings_link(row, role)}</td>
            </tr>
            """
            for row in employers
        )
        if not employer_rows:
            employer_rows = "<tr><td colspan='8'>No employers available for this account yet.</td></tr>"
        role_title = {
            "super_admin": "Admin Operations Dashboard",
            "broker": "Broker Portfolio Dashboard",
            "employer": "Employer Workspace",
            "admin": "Admin Team Dashboard",
        }.get(role, "Dashboard")

        role_banner = {
            "super_admin": "Manage broker accounts and system-wide visibility.",
            "broker": "Create employers and monitor all applications assigned to your book.",
            "employer": "Review your application and complete outstanding onboarding tasks.",
            "admin": "Create and oversee brokers and employers assigned to your organization.",
        }.get(role, "")

        show_application = role in {"super_admin", "admin", "broker"}
        show_settings = role in {"super_admin", "admin", "broker", "employer"}
        show_logs = role == "super_admin"

        notifications = self.list_notifications(user["id"])
        unseen_count = sum(1 for item in notifications if not item["seen"])
        employer_profile = employers[0] if role == "employer" and employers else None

        nav_links = [("dashboard", "Dashboard")]
        if role in {"super_admin", "admin", "broker"}:
            nav_links.append(("employers", "Employers"))
        if role == "employer":
            nav_links.append(("applications", "Applications"))
        if show_application:
            nav_links.insert(1, ("application", "ICHRA Setup Application"))
        nav_links.append(("team", "Team"))
        nav_links.append(("notifications", f"Notifications {'⚠️' if unseen_count else ''}"))
        nav_links.append(("devlog", "Dev Log"))
        if show_settings:
            nav_links.append(("settings", "Settings"))
        if show_logs:
            nav_links.append(("logs", "Activity Log"))

        nav_html = "".join(
            f"<a class='nav-link {'active' if active_view == key else ''}' href='/?view={key}'>{label}</a>"
            for key, label in nav_links
        )

        task_section = ""
        if role in {"super_admin", "admin", "broker"}:
            task_section = """
              <article class='task-card'>
                <h2>Workflow Focus</h2>
                <p>Use this dashboard to monitor key progress and take your highest-impact next step.</p>
              </article>
            """

        broker_refer_cta = ""
        if role == "broker":
            referable = [row for row in employers if not row["application_complete"]]
            options = "".join(
                f"<option value='{row['id']}'>{html.escape(row['legal_name'])}</option>"
                for row in referable
            )
            broker_refer_cta = f"""
              <section class='section-block'>
                <h3>Client Referrals</h3>
                <p class='subtitle'>Send an ICHRA setup invitation to an employer in your book.</p>
                <form method='post' action='/employers/refer' class='inline-form'>
                  <select name='employer_id' {'disabled' if not options else ''}>
                    {options or "<option value=''>No eligible employers</option>"}
                  </select>
                  <button type='submit' {'disabled' if not options else ''}>Refer a Client</button>
                </form>
              </section>
            """

        employer_workspace = ""

        broker_admin_section = ""
        if role in {"super_admin", "admin", "broker"}:
            users_for_admin = [row for row in rows if row["role"] != "super_admin"]
            if role == "admin":
                users_for_admin = [row for row in users_for_admin if row["role"] == "broker" and row["created_by_user_id"] == user["id"]]
            elif role == "broker":
                users_for_admin = [row for row in users_for_admin if row["role"] == "broker" and (row["id"] == user["id"] or row["created_by_user_id"] == user["id"])]
            user_rows = "".join(
                f"""
                <tr>
                  <td>{html.escape(row['username'])}</td>
                  <td>{html.escape(row['role'])}</td>
                  <td>
                    <form method='post' action='/admin/users/update' class='inline-form'>
                      <input type='hidden' name='user_id' value='{row['id']}' />
                      <input name='username' value='{html.escape(row['username'])}' required minlength='3' />
                      <select name='role'>
                        <option value='admin' {'selected' if row['role'] == 'admin' else ''}>admin</option>
                        <option value='broker' {'selected' if row['role'] == 'broker' else ''}>broker</option>
                        {"<option value='super_admin' {'selected' if row['role'] == 'super_admin' else ''}>super_admin</option>" if role == 'super_admin' else ""}
                      </select>
                      <input name='password' type='password' placeholder='new password (optional)' />
                      <button type='submit' class='secondary'>Save</button>
                    </form>
                  </td>
                </tr>
                """
                for row in users_for_admin
            )
            create_role_options = "<option value='broker'>broker</option><option value='employer'>employer</option>"
            if role == "super_admin":
                create_role_options = "<option value='admin'>admin</option><option value='broker'>broker</option><option value='employer'>employer</option><option value='super_admin'>super_admin</option>"
            broker_admin_section = f"""
              <section class='section-block'>
                <h3>{'Super Admin · Account Management' if role == 'super_admin' else ('Admin · Assigned Organizations' if role == 'admin' else 'Broker · Team Accounts')}</h3>
                <form method='post' action='/admin/users/create' class='inline-form'>
                  <input name='username' placeholder='new username' required minlength='3' />
                  <select name='role'>{create_role_options}</select>
                  <button type='submit'>Create User</button>
                </form>
                <div class='table-wrap'><table class='user-table'>
                  <thead><tr><th>Username</th><th>Role</th><th>Modify</th></tr></thead>
                  <tbody>{user_rows}</tbody>
                </table></div>
              </section>
            """

        settings_section = "<section class='section-block'><p class='subtitle'>This account has no editable settings.</p></section>"
        if role in {"super_admin", "admin", "broker"}:
            settings_section = f"""
              <section class='section-block settings-grid'>
                <div>
                  <h3>User Settings</h3>
                  <form method='post' action='/settings/profile' class='form-grid'>
                    <label>Change Username
                      <input type='text' name='username' value='{html.escape(user['username'])}' required minlength='3' />
                    </label>
                    <label>Change Password
                      <input type='password' name='password' placeholder='leave blank to keep current password' />
                    </label>
                    <button type='submit'>Save Account Settings</button>
                  </form>
                </div>
                <div>
                  <h3>Dashboard Styling</h3>
                  <form method='post' action='/settings/style' class='form-grid'>
                    <label>Theme
                      <select name='theme'>
                        <option value='default' {'selected' if user['theme'] == 'default' else ''}>Default</option>
                        <option value='sunset' {'selected' if user['theme'] == 'sunset' else ''}>Sunset</option>
                        <option value='midnight' {'selected' if user['theme'] == 'midnight' else ''}>Midnight</option>
                      </select>
                    </label>
                    <label>Density
                      <select name='density'>
                        <option value='comfortable' {'selected' if user['density'] == 'comfortable' else ''}>Comfortable</option>
                        <option value='compact' {'selected' if user['density'] == 'compact' else ''}>Compact</option>
                      </select>
                    </label>
                    <button type='submit'>Apply Styling</button>
                  </form>
                </div>
              </section>
            """

        notification_rows = "".join(
            f"""
            <li>
              <form method='post' action='/notifications/seen' class='notification-item'>
                <input type='hidden' name='notification_id' value='{row['id']}' />
                <label class='check-row'>
                  <input type='checkbox' name='seen' {'checked' if row['seen'] else ''} {'disabled' if row['seen'] else ''} onchange='if(!this.disabled) this.form.submit()' />
                  <span>{html.escape(row['message'])}</span>
                </label>
                <small>{html.escape(row['created_at'])}</small>
              </form>
            </li>
            """
            for row in notifications
        )
        if not notification_rows:
            notification_rows = "<li class='subtitle'>No notifications yet.</li>"

        notifications_panel = f"""
            <section class='section-block'>
              <h3>Notifications</h3>
              <ul class='status-list notifications-list'>{notification_rows}</ul>
            </section>
        """

        employers_panel = f"""
            <section class='section-block'>
              <h3>{'My ICHRA Setup Application' if role == 'employer' else 'Employer Accounts'}</h3>
              <div class='table-wrap'><table class='user-table'>
                <thead><tr><th>Employer</th><th>Contact</th><th>Email</th><th>Portal Username</th><th>Broker Owner</th><th>Application</th><th>Assigned Task</th><th>Settings</th></tr></thead>
                <tbody>{employer_rows}</tbody>
              </table></div>
            </section>
        """

        team_panel = f"""
            <section class='section-block'>
              <h3>Team Completion Status</h3>
              <ul class='status-list'>{status_rows}</ul>
            </section>
            {broker_admin_section}
        """

        employer_applications_panel = ""
        header_primary_cta = ""
        if role == "employer" and employer_profile:
            ichra_status = "Complete" if employer_profile["application_complete"] else ("In progress" if employer_profile["ichra_started"] else "Not started")
            employer_applications_panel = f"""
                <section class='section-block'>
                  <h3>Applications</h3>
                  <div class='table-wrap'><table class='user-table'>
                    <thead><tr><th>Application</th><th>Status</th><th>Current Action</th></tr></thead>
                    <tbody>
                      <tr><td>Initial Employer Setup</td><td>Submitted</td><td>Review details in Dev Log and Notifications.</td></tr>
                      <tr><td>ICHRA Setup Application</td><td>{ichra_status}</td><td>{html.escape(employer_profile['onboarding_task'])}</td></tr>
                    </tbody>
                  </table></div>
                </section>
                <section class='section-block'>
                  <h3>Application Workflow</h3>
                  <form method='post' action='/employers/application' class='inline-form'>
                    <input type='hidden' name='status' value='incomplete' />
                    <button type='submit' class='secondary'>Mark Application Incomplete</button>
                  </form>
                  <form method='post' action='/employers/application' class='inline-form'>
                    <input type='hidden' name='status' value='complete' />
                    <button type='submit'>Complete Application</button>
                  </form>
                </section>
            """

            if not employer_profile["ichra_started"]:
                header_primary_cta = """
                    <form method='post' action='/employers/start-ichra'>
                      <button type='submit'>Start ICHRA Setup Application</button>
                    </form>
                """
            elif not employer_profile["application_complete"]:
                header_primary_cta = """
                    <a class='nav-link active' href='/?view=applications'>Finish ICHRA Setup Application</a>
                """
            else:
                header_primary_cta = "<span class='nav-link active'>ICHRA Setup Complete</span>"

        if role == "broker":
            header_primary_cta = "<a class='nav-link active' href='/?view=dashboard'>Refer a Client</a>"

        logs = self.list_activity_logs(query) if show_logs else []
        log_rows = "".join(
            f"<tr><td>{html.escape(row['created_at'])}</td><td>{html.escape(row['actor_username'])}</td><td>{html.escape(row['actor_role'])}</td><td>{html.escape(row['action'])}</td><td>{html.escape(row['target_label'])}</td><td>{html.escape(row['details'] or '')}</td></tr>"
            for row in logs
        )
        if not log_rows:
            log_rows = "<tr><td colspan='6'>No activity matched the selected filters.</td></tr>"

        logs_panel = f"""
            <section class='section-block'>
              <h3>Admin Activity Log</h3>
              <form method='get' action='/' class='inline-form'>
                <input type='hidden' name='view' value='logs' />
                <label>Role
                  <select name='role'>
                    <option value=''>All roles</option>
                    <option value='super_admin' {'selected' if query.get('role', [''])[0] == 'super_admin' else ''}>super_admin</option>
                    <option value='broker' {'selected' if query.get('role', [''])[0] == 'broker' else ''}>broker</option>
                    <option value='admin' {'selected' if query.get('role', [''])[0] == 'admin' else ''}>admin</option>
                    <option value='employer' {'selected' if query.get('role', [''])[0] == 'employer' else ''}>employer</option>
                  </select>
                </label>
                <label>Action
                  <select name='action'>
                    <option value=''>All actions</option>
                    <option value='login' {'selected' if query.get('action', [''])[0] == 'login' else ''}>login</option>
                    <option value='employer_created' {'selected' if query.get('action', [''])[0] == 'employer_created' else ''}>employer_created</option>
                    <option value='employer_updated' {'selected' if query.get('action', [''])[0] == 'employer_updated' else ''}>employer_updated</option>
                    <option value='user_created' {'selected' if query.get('action', [''])[0] == 'user_created' else ''}>user_created</option>
                    <option value='user_updated' {'selected' if query.get('action', [''])[0] == 'user_updated' else ''}>user_updated</option>
                    <option value='task_completed' {'selected' if query.get('action', [''])[0] == 'task_completed' else ''}>task_completed</option>
                  </select>
                </label>
                <label>Search <input name='q' value='{html.escape(query.get('q', [''])[0])}' placeholder='target or details' /></label>
                <button type='submit'>Apply Filters</button>
                <a class='nav-link' href='/?view=logs'>Clear Filters</a>
              </form>
              <div class='table-wrap'><table class='user-table'>
                <thead><tr><th>Timestamp</th><th>Actor</th><th>Role</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
                <tbody>{log_rows}</tbody>
              </table></div>
            </section>
        """

        devlog_rows = "".join(
            f"<tr><td>PR #{entry['pr']}</td><td>{html.escape(entry['change'])}</td><td>{html.escape(entry['result'])}</td><td>{html.escape(entry['why'])}</td></tr>"
            for entry in sorted(DEV_LOG_ENTRIES, key=lambda item: item["pr"])
        )
        devlog_panel = f"""
            <section class='section-block'>
              <h3>Development Log</h3>
              <p class='subtitle'>A running history of merged PRs, what changed, outcomes, and rationale. Add a new entry for each successful merge going forward.</p>
              <div class='table-wrap'><table class='user-table'>
                <thead><tr><th>PR</th><th>What Changed</th><th>Result</th><th>Why</th></tr></thead>
                <tbody>{devlog_rows}</tbody>
              </table></div>
            </section>
        """

        dashboard_panel = f"""
            {task_section}
            {broker_refer_cta}
            <section class='section-block'>
              <h3>Workflow Snapshot</h3>
              <div class='stats-grid'>
                <article><h4>Employers</h4><p>{len(employers)}</p></article>
                <article><h4>Applications Complete</h4><p>{sum(1 for row in employers if row['application_complete'])}</p></article>
                <article><h4>Unread Notifications</h4><p>{unseen_count}</p></article>
              </div>
            </section>
            {employer_workspace}
        """

        panel_lookup = {
            "dashboard": dashboard_panel,
            "team": team_panel,
            "application": self.render_ichra_application_form(user) if show_application else "",
            "employers": employers_panel,
            "applications": employer_applications_panel if role == "employer" else employers_panel,
            "notifications": notifications_panel,
            "devlog": devlog_panel,
            "settings": settings_section,
            "logs": logs_panel if show_logs else "",
        }
        active_panel = panel_lookup.get(active_view, dashboard_panel)

        password_banner = ""
        if user["must_change_password"]:
            password_banner = "<div class='flash-stack'><div class='flash error persistent-banner'>Security notice: your temporary password is still active. Please update your password in Settings.</div></div>"

        html_body = password_banner + self.flash_html(flash_message) + f"""
            <section class='card dashboard role-{role} theme-{user['theme']} density-{user['density']}'>
              <div class='welcome-banner'>{html.escape(role_banner)}</div>
              <header class='dashboard-header'>
                <div>
                  <h1>{html.escape(role_title)}</h1>
                  <p class='subtitle'>Welcome, {html.escape(user['display_name'])}</p>
                </div>
                {header_primary_cta}
                <form method='post' action='/logout'><button class='secondary' type='submit'>Log Out</button></form>
              </header>
              <nav class='dashboard-nav'>{nav_html}</nav>
              {active_panel}
            </section>
            """
        html_doc = self.html_page("Dashboard", html_body)
        headers = [("Content-Type", "text/html; charset=utf-8"), ("Set-Cookie", self.expire_cookie_header("flash"))]
        start_response("200 OK", headers)
        return [html_doc.encode("utf-8")]

    def render_ichra_application_form(self, user):
        visible_employers = self.list_visible_employers(user)
        employer_options = "".join(
            f"<option value='{row['id']}'>{html.escape(row['legal_name'])} ({html.escape(row['portal_username'])})</option>"
            for row in visible_employers
        )
        return f"""
        <section class='section-block panel-card'>
          <h3>ICHRA Setup Application Center</h3>
          <p class='subtitle'>Choose the workflow you want to launch.</p>
          <div class='toggle-row'>
            <button type='button' class='setup-toggle active' data-setup-mode='ichra'>ICHRA Application</button>
            <button type='button' class='setup-toggle' data-setup-mode='basic'>Basic Employer Application</button>
          </div>

          <div class='setup-panel' data-panel-mode='ichra'>
            <h4>ICHRA Application</h4>
            <p class='subtitle'>This workflow must be mapped to an existing employer account.</p>
            <form method='post' action='/employers/create' class='form-grid'>
              <input type='hidden' name='setup_mode' value='ichra' />
              <label>Desired ICHRA Start Date *<input type='date' name='ichra_start_date' required /></label>
              <label>Existing Employer *
                <select name='existing_employer_id' required>
                  <option value=''>Select an active employer</option>
                  {employer_options}
                </select>
              </label>
              <label>Service Type *
                <select name='service_type' required>
                  <option value='ICHRA Documents + Monthly Administration'>ICHRA Documents + Monthly Administration</option>
                  <option value='ICHRA Documents Only'>ICHRA Documents Only</option>
                </select>
              </label>
              <label>Primary Contact First Name *<input name='primary_first_name' required /></label>
              <label>Primary Contact Last Name *<input name='primary_last_name' required /></label>
              <label>Primary Contact Email *<input type='email' name='primary_email' required /></label>
              <label>Primary Contact Phone *<input name='primary_phone' required /></label>
              <label>Legal Business Name *<input name='legal_name' required /></label>
              <label>Nature of Business *<input name='nature_of_business' required /></label>
              <label>Total Employee Count *<input type='number' name='total_employee_count' required /></label>
              <label>Physical State *<input name='physical_state' required /></label>
              <label>Reimbursement Option *<input name='reimbursement_option' required /></label>
              <label>Employee Class Assistance *<input name='employee_class_assistance' required /></label>
              <label>Planned Contribution *<input name='planned_contribution' required /></label>
              <label>Claim Option *<input name='claim_option' required /></label>
              <label>Agent Support *<input name='agent_support' required /></label>
              <button type='submit'>Finalize and Submit ICHRA Application</button>
            </form>
          </div>

          <div class='setup-panel' data-panel-mode='basic' hidden>
            <h4>Basic Employer Application</h4>
            <p class='subtitle'>Use this for standard employer setup without the full ICHRA workflow.</p>
            <form method='post' action='/employers/create' class='form-grid'>
              <input type='hidden' name='setup_mode' value='basic' />
              <label>Employer Legal Name *<input name='legal_name' required /></label>
              <label>Primary Contact Name *<input name='contact_name' required /></label>
              <label>Work Email *<input type='email' name='work_email' required /></label>
              <label>Phone *<input name='phone' required /></label>
              <label>Company Size *<input name='company_size' required /></label>
              <label>Industry *<input name='industry' required /></label>
              <label>Website *<input name='website' required /></label>
              <label>State *<input name='state' required /></label>
              <button type='submit'>Submit Basic Employer Setup</button>
            </form>
          </div>
        </section>
        """

    def render_employer_settings_link(self, employer_row, role: str) -> str:
        if role not in {"super_admin", "admin", "broker"}:
            return "<span class='subtitle'>Read-only</span>"
        return f"<a class='table-link' href='/employers/settings?id={employer_row['id']}'>Open settings</a>"

    def render_employer_settings_page(self, start_response, session_user, employer_id: int, flash_message):
        employer = self.get_visible_employer_by_id(session_user, employer_id)
        if not employer:
            return self.redirect(start_response, "/?view=employers", flash=("error", "Employer not found for your access scope."))

        broker_options = "".join(
            f"<option value='{row['id']}' {'selected' if employer['broker_user_id'] == row['id'] else ''}>{html.escape(row['username'])}</option>"
            for row in self.get_manageable_brokers(session_user)
        )
        primary_candidates = [row for row in self.get_users_with_completion() if row["role"] in {"super_admin", "admin", "broker"}]
        primary_options = "".join(
            f"<option value='{row['id']}' {'selected' if employer['primary_user_id'] == row['id'] else ''}>{html.escape(row['username'])} ({html.escape(row['role'])})</option>"
            for row in primary_candidates
        )

        body = self.flash_html(flash_message) + f"""
            <section class='card dashboard role-{session_user['role']} theme-{session_user['theme']} density-{session_user['density']}'>
              <header class='dashboard-header'>
                <div>
                  <h1>Employer Settings</h1>
                  <p class='subtitle'>Company dashboard for profile, ownership, and portal settings.</p>
                </div>
                <a class='nav-link' href='/?view=employers'>Back to Employers</a>
              </header>
              <section class='section-block panel-card'>
                <h3>Company Snapshot</h3>
                <div class='stats-grid'>
                  <article><h4>Legal Name</h4><p>{html.escape(employer['legal_name'])}</p></article>
                  <article><h4>Primary Contact</h4><p>{html.escape(employer['contact_name'])}</p></article>
                  <article><h4>Company Size</h4><p>{html.escape(employer['company_size'])}</p></article>
                  <article><h4>State</h4><p>{html.escape(employer['state'])}</p></article>
                </div>
              </section>
              <section class='section-block panel-card'>
                {self.render_employer_edit_form(employer, broker_options, primary_options)}
              </section>
            </section>
        """
        html_doc = self.html_page("Employer Settings", body)
        headers = [("Content-Type", "text/html; charset=utf-8"), ("Set-Cookie", self.expire_cookie_header("flash"))]
        start_response("200 OK", headers)
        return [html_doc.encode("utf-8")]

    def render_employer_edit_form(self, employer_row, broker_options: str, primary_options: str) -> str:
        return f"""
        <form method='post' action='/employers/update' class='form-grid employer-settings-form'>
          <h3>Employer Profile</h3>
          <input type='hidden' name='employer_id' value='{employer_row['id']}' />
          <label>Legal Name<input name='legal_name' value='{html.escape(employer_row['legal_name'])}' required /></label>
          <label>Contact<input name='contact_name' value='{html.escape(employer_row['contact_name'])}' required /></label>
          <label>Email<input name='work_email' type='email' value='{html.escape(employer_row['work_email'])}' required /></label>
          <label>Phone<input name='phone' value='{html.escape(employer_row['phone'])}' required /></label>
          <label>Size<input name='company_size' value='{html.escape(employer_row['company_size'])}' required /></label>
          <label>Industry<input name='industry' value='{html.escape(employer_row['industry'])}' required /></label>
          <label>Website<input name='website' value='{html.escape(employer_row['website'])}' required /></label>
          <label>State<input name='state' value='{html.escape(employer_row['state'])}' required /></label>
          <label>Onboarding Task<textarea name='onboarding_task' required>{html.escape(employer_row['onboarding_task'])}</textarea></label>
          <h3>Ownership Assignment</h3>
          <label>Assign Broker
            <select name='broker_user_id'>
              <option value=''>Unassigned</option>
              {broker_options}
            </select>
          </label>
          <label>Assign Primary User
            <select name='primary_user_id'>
              <option value=''>Unassigned</option>
              {primary_options}
            </select>
          </label>
          <h3>Employer Portal Access</h3>
          <label>Portal Username<input name='portal_username' value='{html.escape(employer_row['portal_username'])}' required minlength='3' /></label>
          <label>Portal Password<input name='portal_password' type='password' placeholder='leave blank to keep current password' /></label>
          <button type='submit' class='secondary'>Update Employer</button>
        </form>
        """

    def serve_static(self, path: str, start_response):
        file_path = BASE_DIR / path.lstrip("/")
        if not file_path.exists():
            start_response("404 Not Found", [("Content-Type", "text/plain")])
            return [b"Not found"]

        mime = "text/css" if file_path.suffix == ".css" else "text/plain"
        start_response("200 OK", [("Content-Type", mime)])
        return [file_path.read_bytes()]

    def flash_html(self, flash_message):
        if not flash_message:
            return ""
        category, message = flash_message
        return f"<div class='flash-stack'><div class='flash {category}'>{html.escape(message)}</div></div>"

    def html_page(self, title: str, body: str):
        return f"""<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>{title}</title>
  <link rel='stylesheet' href='/static/styles.css' />
</head>
<body>
  <main class='container'>{body}</main>
  <script>
    document.querySelectorAll('[data-modal-open]').forEach((button) => {{
      button.addEventListener('click', () => {{
        const modal = document.getElementById(button.getAttribute('data-modal-open'));
        if (modal) {{
          modal.classList.add('is-open');
          modal.setAttribute('aria-hidden', 'false');
        }}
      }});
    }});
    document.querySelectorAll('[data-modal-close]').forEach((button) => {{
      button.addEventListener('click', () => {{
        const modal = document.getElementById(button.getAttribute('data-modal-close'));
        if (modal) {{
          modal.classList.remove('is-open');
          modal.setAttribute('aria-hidden', 'true');
        }}
      }});
    }});
    document.querySelectorAll('[data-setup-mode]').forEach((trigger) => {{
      trigger.addEventListener('click', () => {{
        const mode = trigger.getAttribute('data-setup-mode');
        document.querySelectorAll('.setup-toggle').forEach((item) => item.classList.remove('active'));
        trigger.classList.add('active');
        document.querySelectorAll('.setup-panel').forEach((panel) => {{
          panel.hidden = panel.getAttribute('data-panel-mode') !== mode;
        }});
      }});
    }});
  </script>
</body>
</html>
"""


def run_server() -> None:
    app = TaskTrackerApp()
    port = int(os.environ.get("PORT", "8000"))
    with make_server("0.0.0.0", port, app) as server:
        print(f"Server running on http://0.0.0.0:{port}")
        server.serve_forever()


if __name__ == "__main__":
    run_server()
