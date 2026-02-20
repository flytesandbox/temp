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
ROLE_LEVELS = {"employer": 0, "broker": 1, "admin": 2, "super_admin": 3}


def db_connect(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

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
    {"pr": 31, "change": "Made dashboard headers sticky with a scroll-condensed state and added a PR checklist reminder for Dev Log updates.", "result": "Long pages now keep context visible while scrolling and the merge process has an explicit Dev Log checkpoint.", "why": "Improve usability across long forms/lists and prevent Development Log drift from missed entries."},
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
        db = db_connect(self.db_path)
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
                must_change_password INTEGER NOT NULL DEFAULT 1,
                is_active INTEGER NOT NULL DEFAULT 1
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

            CREATE TABLE IF NOT EXISTS teams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                created_by_user_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS team_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL UNIQUE,
                role_scope TEXT NOT NULL DEFAULT 'admin',
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
        if "is_active" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
        if "team_id" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN team_id INTEGER")

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

        default_team = db.execute("SELECT id FROM teams WHERE name = 'Core Admin Team'").fetchone()
        if not default_team:
            db.execute("INSERT INTO teams (name, created_by_user_id) VALUES ('Core Admin Team', 1)")
            default_team_id = db.execute("SELECT last_insert_rowid() AS i").fetchone()[0]
        else:
            default_team_id = default_team["id"] if hasattr(default_team, "keys") else default_team[0]
        db.execute(
            """
            UPDATE users
            SET team_id = ?
            WHERE team_id IS NULL AND role IN ('super_admin', 'admin', 'broker')
            """,
            (default_team_id,),
        )
        db.execute(
            """
            INSERT OR IGNORE INTO team_members (team_id, user_id, role_scope)
            SELECT team_id, id, 'admin'
            FROM users
            WHERE role = 'admin' AND team_id IS NOT NULL
            """
        )

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

        if path == "/employers/start-ichra" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] != "employer":
                return self.redirect(start_response, "/", flash=("error", "Only employer accounts can start ICHRA setup."))
            employer_before = self.list_visible_employers(session_user)
            was_started = bool(employer_before and employer_before[0]["ichra_started"])
            self.start_employer_ichra(session_user["id"])
            if was_started:
                self.complete_employer_application(session_user["id"])
                self.log_action(session_user["id"], "application_status_changed", "employer", session_user["id"], session_user["username"], "status=complete")
                return self.redirect(start_response, "/?view=applications", flash=("success", "Application marked complete."))
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

        if path == "/notifications/create" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] not in {"super_admin", "admin"}:
                return self.redirect(start_response, "/", flash=("error", "Only admin roles can create notifications."))
            return self.handle_create_notification(start_response, session_user, self.parse_form(environ))

        if path == "/teams/create" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] != "super_admin":
                return self.redirect(start_response, "/?view=team", flash=("error", "Only super admins can create teams."))
            return self.handle_create_team(start_response, session_user, self.parse_form(environ))

        if path == "/teams/assign-admin" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] != "super_admin":
                return self.redirect(start_response, "/?view=team", flash=("error", "Only super admins can assign admins to teams."))
            return self.handle_assign_admin_to_team(start_response, session_user, self.parse_form(environ))

        if path == "/teams/assign-user" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] != "super_admin":
                return self.redirect(start_response, "/?view=team", flash=("error", "Only super admins can assign users to teams."))
            return self.handle_assign_user_to_team(start_response, session_user, self.parse_form(environ))

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
        return db_connect(self.db_path)

    def get_user(self, username: str):
        db = self.db()
        user = db.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)).fetchone()
        db.close()
        return user

    def get_user_by_id(self, user_id: int):
        db = self.db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        db.close()
        return user

    def get_users_with_completion(self, session_user=None):
        db = self.db()
        rows = db.execute(
            """
            SELECT u.id, u.username, u.display_name, u.role, u.created_by_user_id, u.team_id,
                   u.is_active,
                   CASE WHEN tc.id IS NULL THEN 0 ELSE 1 END AS completed
            FROM users u
            LEFT JOIN task_completions tc
                ON tc.user_id = u.id AND tc.task_id = 1
            WHERE u.role != 'employer' AND u.is_active = 1
            ORDER BY u.id
            """
        ).fetchall()
        db.close()
        if session_user:
            rows = self.filter_users_for_scope(session_user, rows, include_super_admin=(session_user['role'] == 'super_admin'))
        return rows

    def filter_users_for_scope(self, session_user, rows, include_super_admin: bool = False):
        if session_user['role'] == 'super_admin':
            return [row for row in rows if include_super_admin or row['role'] != 'super_admin']
        if session_user['role'] == 'employer':
            return [row for row in rows if row['id'] == session_user['id']]
        return [
            row
            for row in rows
            if row['team_id'] == session_user['team_id']
            and (include_super_admin or row['role'] != 'super_admin')
        ]

    def get_users_for_account_management(self, session_user=None):
        db = self.db()
        rows = db.execute(
            """
            SELECT id, username, role, is_active, team_id
            FROM users
            WHERE role != 'super_admin'
            ORDER BY is_active DESC, username ASC
            """
        ).fetchall()
        db.close()
        if session_user:
            rows = self.filter_users_for_scope(session_user, rows)
        return rows

    def get_login_demo_accounts(self):
        db = self.db()
        rows = db.execute(
            """
            SELECT username, role, password_hint
            FROM users
            WHERE role IN ('super_admin', 'admin', 'broker') AND is_active = 1
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

    def get_team_for_user(self, user_id: int):
        db = self.db()
        row = db.execute(
            """
            SELECT t.id, t.name
            FROM teams t
            JOIN users u ON u.team_id = t.id
            WHERE u.id = ?
            """,
            (user_id,),
        ).fetchone()
        db.close()
        return row

    def list_teams(self):
        db = self.db()
        rows = db.execute(
            """
            SELECT t.id, t.name, t.created_at,
                   COALESCE(SUM(CASE WHEN u.role = 'admin' THEN 1 ELSE 0 END), 0) AS admin_count,
                   COALESCE(SUM(CASE WHEN u.role = 'broker' THEN 1 ELSE 0 END), 0) AS broker_count,
                   COALESCE(SUM(CASE WHEN u.role = 'employer' THEN 1 ELSE 0 END), 0) AS employer_count
            FROM teams t
            LEFT JOIN users u ON u.team_id = t.id AND u.is_active = 1
            GROUP BY t.id
            ORDER BY t.name
            """
        ).fetchall()
        db.close()
        return rows

    def list_assignable_admins(self):
        db = self.db()
        rows = db.execute("SELECT id, username, team_id FROM users WHERE role = 'admin' AND is_active = 1 ORDER BY username").fetchall()
        db.close()
        return rows

    def list_assignable_users(self):
        db = self.db()
        rows = db.execute(
            "SELECT id, username, role, team_id FROM users WHERE role != 'super_admin' AND is_active = 1 ORDER BY role, username"
        ).fetchall()
        db.close()
        return rows

    def create_team(self, name: str, created_by_user_id: int):
        db = self.db()
        db.execute("INSERT INTO teams (name, created_by_user_id) VALUES (?, ?)", (name, created_by_user_id))
        db.commit()
        db.close()

    def assign_admin_to_team(self, admin_user_id: int, team_id: int):
        db = self.db()
        admin = db.execute("SELECT id FROM users WHERE id = ? AND role = 'admin' AND is_active = 1", (admin_user_id,)).fetchone()
        team = db.execute("SELECT id FROM teams WHERE id = ?", (team_id,)).fetchone()
        if not admin or not team:
            db.close()
            raise ValueError("Invalid admin or team.")
        db.execute("UPDATE users SET team_id = ? WHERE id = ?", (team_id, admin_user_id))
        db.execute(
            "INSERT OR IGNORE INTO team_members (team_id, user_id, role_scope) VALUES (?, ?, 'admin')",
            (team_id, admin_user_id),
        )
        db.execute(
            """
            UPDATE users
            SET team_id = ?
            WHERE role = 'broker' AND (created_by_user_id = ? OR id IN (SELECT broker_user_id FROM employers WHERE primary_user_id = ?))
            """,
            (team_id, admin_user_id, admin_user_id),
        )
        db.execute(
            """
            UPDATE users
            SET team_id = ?
            WHERE role = 'employer' AND id IN (
              SELECT linked_user_id FROM employers
              WHERE primary_user_id = ?
                 OR broker_user_id IN (SELECT id FROM users WHERE role = 'broker' AND team_id = ?)
            )
            """,
            (team_id, admin_user_id, team_id),
        )
        db.commit()
        db.close()

    def assign_user_to_team(self, user_id: int, team_id: int):
        db = self.db()
        target = db.execute("SELECT id, role FROM users WHERE id = ? AND role != 'super_admin' AND is_active = 1", (user_id,)).fetchone()
        team = db.execute("SELECT id FROM teams WHERE id = ?", (team_id,)).fetchone()
        if not target or not team:
            db.close()
            raise ValueError("Invalid user or team.")

        db.execute("UPDATE users SET team_id = ? WHERE id = ?", (team_id, user_id))
        if target["role"] == "admin":
            db.execute(
                "INSERT OR IGNORE INTO team_members (team_id, user_id, role_scope) VALUES (?, ?, 'admin')",
                (team_id, user_id),
            )
            db.execute(
                """
                UPDATE users
                SET team_id = ?
                WHERE role = 'broker' AND (created_by_user_id = ? OR id IN (SELECT broker_user_id FROM employers WHERE primary_user_id = ?))
                """,
                (team_id, user_id, user_id),
            )
            db.execute(
                """
                UPDATE users
                SET team_id = ?
                WHERE role = 'employer' AND id IN (
                  SELECT linked_user_id FROM employers
                  WHERE primary_user_id = ?
                     OR broker_user_id IN (SELECT id FROM users WHERE role = 'broker' AND team_id = ?)
                )
                """,
                (team_id, user_id, team_id),
            )
        db.commit()
        db.close()

    def list_visible_employers(self, session_user):
        db = self.db()
        if session_user["role"] == "super_admin":
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username,
                       broker.username AS broker_username
                FROM employers e
                JOIN users u ON u.id = e.linked_user_id AND u.is_active = 1
                LEFT JOIN users broker ON broker.id = e.broker_user_id AND broker.is_active = 1
                ORDER BY e.created_at DESC
                """
            ).fetchall()
        elif session_user["role"] in {"admin", "broker"}:
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username,
                       broker.username AS broker_username
                FROM employers e
                JOIN users u ON u.id = e.linked_user_id AND u.is_active = 1
                LEFT JOIN users broker ON broker.id = e.broker_user_id AND broker.is_active = 1
                LEFT JOIN users owner_admin ON owner_admin.id = e.primary_user_id AND owner_admin.is_active = 1
                LEFT JOIN users employer_user ON employer_user.id = e.linked_user_id AND employer_user.is_active = 1
                WHERE (
                    e.primary_user_id = ?
                    OR e.broker_user_id = ?
                    OR (owner_admin.team_id IS NOT NULL AND owner_admin.team_id = ?)
                    OR (broker.team_id IS NOT NULL AND broker.team_id = ?)
                    OR (employer_user.team_id IS NOT NULL AND employer_user.team_id = ?)
                )
                ORDER BY e.created_at DESC
                """,
                (session_user["id"], session_user["id"], session_user["team_id"], session_user["team_id"], session_user["team_id"]),
            ).fetchall()
        elif session_user["role"] == "employer":
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username,
                       broker.username AS broker_username
                FROM employers e
                JOIN users u ON u.id = e.linked_user_id AND u.is_active = 1
                LEFT JOIN users broker ON broker.id = e.broker_user_id AND broker.is_active = 1
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
            rows = db.execute("SELECT id, username, display_name FROM users WHERE role = 'broker' AND is_active = 1 ORDER BY username").fetchall()
        elif session_user["role"] == "admin":
            rows = db.execute(
                """
                SELECT id, username, display_name
                FROM users
                WHERE role = 'broker' AND team_id = ? AND is_active = 1
                ORDER BY username
                """,
                (session_user["team_id"],),
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT id, username, display_name
                FROM users
                WHERE role = 'broker' AND id = ? AND is_active = 1
                ORDER BY username
                """,
                (session_user["id"],),
            ).fetchall()
        db.close()
        return rows

    def can_manage_user(self, session_user, target_user):
        if not target_user or not target_user["is_active"]:
            return False
        if session_user["role"] == "super_admin":
            return target_user["role"] != "super_admin"
        if session_user["role"] == "broker":
            return target_user["id"] == session_user["id"]
        if session_user["role"] == "admin":
            return target_user["team_id"] == session_user["team_id"] and target_user["role"] in {"admin", "broker", "employer"}
        return target_user["id"] == session_user["id"]

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

    def complete_employer_application(self, employer_user_id: int):
        db = self.db()
        db.execute("UPDATE employers SET ichra_started = 1, application_complete = 1 WHERE linked_user_id = ?", (employer_user_id,))
        employer = db.execute("SELECT legal_name, primary_user_id FROM employers WHERE linked_user_id = ?", (employer_user_id,)).fetchone()
        db.commit()
        db.close()
        if employer and employer["primary_user_id"]:
            self.create_notification(employer["primary_user_id"], f"ICHRA setup completed by {employer['legal_name']}.")

    def set_employer_application_in_progress(self, employer_user_id: int):
        db = self.db()
        db.execute("UPDATE employers SET ichra_started = 1, application_complete = 0 WHERE linked_user_id = ?", (employer_user_id,))
        db.commit()
        db.close()

    def start_employer_ichra(self, employer_user_id: int):
        db = self.db()
        employer = db.execute("SELECT ichra_started FROM employers WHERE linked_user_id = ?", (employer_user_id,)).fetchone()
        if not employer:
            db.close()
            return
        if employer["ichra_started"]:
            db.execute("UPDATE employers SET application_complete = 1 WHERE linked_user_id = ?", (employer_user_id,))
        else:
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

    def create_user(self, username: str, password: str, role: str, created_by_user_id: int | None = None, team_id: int | None = None):
        db = self.db()
        db.execute(
            "INSERT INTO users (username, display_name, password_hash, password_hint, role, created_by_user_id, must_change_password, team_id) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (username, username.capitalize(), hash_password(password), password, role, created_by_user_id, team_id),
        )
        db.commit()
        db.close()

    def admin_update_user(self, user_id: int, username: str, role: str, password: str, is_active: int):
        db = self.db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            db.close()
            raise ValueError("User not found")
        password_hash = hash_password(password) if password else user["password_hash"]
        db.execute(
            "UPDATE users SET username = ?, display_name = ?, role = ?, password_hash = ?, password_hint = ?, must_change_password = ?, is_active = ? WHERE id = ?",
            (username, username.capitalize(), role, password_hash, password or user["password_hint"], 0 if password else user["must_change_password"], is_active, user_id),
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
            INSERT INTO users (username, display_name, password_hash, password_hint, role, created_by_user_id, team_id)
            VALUES (?, ?, ?, ?, 'employer', ?, (SELECT team_id FROM users WHERE id = ?))
            """,
            (username, display_name, hash_password("user"), "user", creator_user_id, creator_user_id),
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
        try:
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

                duplicate_username = db.execute(
                    "SELECT id FROM users WHERE username = ? AND id != ?",
                    (new_username, linked_user_id),
                ).fetchone()
                if duplicate_username:
                    raise ValueError("Employer username is already in use.")

                new_password = form.get("portal_password", "")
                password_hash = hash_password(new_password) if new_password else current_user["password_hash"]
                password_hint = new_password or current_user["password_hint"]
                must_change = 0 if new_password else current_user["must_change_password"]
                db.execute(
                    "UPDATE users SET username = ?, display_name = ?, password_hash = ?, password_hint = ?, must_change_password = ? WHERE id = ?",
                    (new_username, form["contact_name"], password_hash, password_hint, must_change, linked_user_id),
                )
            db.commit()
        except sqlite3.IntegrityError as exc:
            db.rollback()
            raise ValueError("Employer username is already in use.") from exc
        except Exception:
            db.rollback()
            raise
        finally:
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
        user = self.get_user_by_id(int(raw.replace("uid:", "")))
        if not user or not user["is_active"]:
            return None
        return user

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
        if not user["is_active"]:
            return self.redirect(start_response, "/login", flash=("error", "This account is deactivated. Contact your administrator."))

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
        creator_level = ROLE_LEVELS.get(session_user["role"], -1)
        if ROLE_LEVELS.get(role, -1) >= creator_level:
            return self.redirect(start_response, "/", flash=("error", "You can only create users below your role level."))
        if len(username) < 3:
            return self.redirect(start_response, "/", flash=("error", "New users need a username (3+)."))
        team_id = session_user["team_id"] if session_user["role"] != "super_admin" else form.get("team_id")
        if team_id in {"", None}:
            team_id = session_user["team_id"]
        if team_id not in {None}:
            try:
                team_id = int(team_id)
            except (TypeError, ValueError):
                return self.redirect(start_response, "/", flash=("error", "Select a valid team."))

        try:
            self.create_user(username, "user", role, created_by_user_id=session_user["id"], team_id=team_id)
            self.log_action(session_user["id"], "user_created", "user", None, username, f"role={role},team_id={team_id}")
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
        is_active = 1 if form.get("is_active", "1") == "1" else 0
        actor_level = ROLE_LEVELS.get(session_user["role"], -1)
        target_level = ROLE_LEVELS.get(role, -1)
        if target_level < 0 or target_level >= actor_level:
            return self.redirect(start_response, "/", flash=("error", "You can only assign roles below your own."))

        target_user = self.get_user_by_id(user_id)
        if not self.can_manage_user(session_user, target_user):
            return self.redirect(start_response, "/", flash=("error", "That user is outside your team scope."))
        if len(username) < 3:
            return self.redirect(start_response, "/", flash=("error", "Username must be at least 3 characters."))

        try:
            self.admin_update_user(user_id, username, role, password, is_active)
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
            self.set_employer_application_in_progress(employer["linked_user_id"])
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
            flash=("success", f"Employer created from Employer Setup Form. Portal username: {username}, temporary password: user"),
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

        try:
            self.update_employer_settings(employer_id, clean)
        except ValueError as exc:
            return self.redirect(start_response, f"/employers/settings?id={employer_id}", flash=("error", str(exc)))
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

    def handle_create_notification(self, start_response, session_user, form):
        message = form.get("message", "").strip()
        try:
            user_id = int(form.get("user_id", ""))
        except ValueError:
            return self.redirect(start_response, "/?view=notifications", flash=("error", "Select a valid user."))
        if not message:
            return self.redirect(start_response, "/?view=notifications", flash=("error", "Notification message is required."))
        target = self.get_user_by_id(user_id)
        if not target:
            return self.redirect(start_response, "/?view=notifications", flash=("error", "Target user not found."))
        if not target["is_active"]:
            return self.redirect(start_response, "/?view=notifications", flash=("error", "Target user is deactivated."))
        if not self.can_manage_user(session_user, target):
            return self.redirect(start_response, "/?view=notifications", flash=("error", "You can only send notifications inside your team scope."))
        self.create_notification(user_id, message)
        self.log_action(session_user["id"], "notification_created", "user", user_id, target["username"], message)
        return self.redirect(start_response, "/?view=notifications", flash=("success", "Notification sent."))

    def handle_create_team(self, start_response, session_user, form):
        name = form.get("name", "").strip()
        if len(name) < 3:
            return self.redirect(start_response, "/?view=team", flash=("error", "Team name must be at least 3 characters."))
        try:
            self.create_team(name, session_user["id"])
            self.log_action(session_user["id"], "team_created", "team", None, name, "Team created")
        except sqlite3.IntegrityError:
            return self.redirect(start_response, "/?view=team", flash=("error", "Team name already exists."))
        return self.redirect(start_response, "/?view=team", flash=("success", "Team created."))

    def handle_assign_admin_to_team(self, start_response, session_user, form):
        try:
            admin_user_id = int(form.get("admin_user_id", ""))
            team_id = int(form.get("team_id", ""))
        except ValueError:
            return self.redirect(start_response, "/?view=team", flash=("error", "Select an admin and a team."))
        try:
            self.assign_admin_to_team(admin_user_id, team_id)
        except ValueError:
            return self.redirect(start_response, "/?view=team", flash=("error", "Invalid team assignment."))
        target = self.get_user_by_id(admin_user_id)
        self.log_action(session_user["id"], "team_assignment_updated", "user", admin_user_id, target["username"] if target else "admin", f"team_id={team_id}")
        return self.redirect(start_response, "/?view=team", flash=("success", "Admin reassigned to team."))

    def handle_assign_user_to_team(self, start_response, session_user, form):
        try:
            user_id = int(form.get("user_id", ""))
            team_id = int(form.get("team_id", ""))
        except ValueError:
            return self.redirect(start_response, "/?view=team", flash=("error", "Select a user and a team."))
        try:
            self.assign_user_to_team(user_id, team_id)
        except ValueError:
            return self.redirect(start_response, "/?view=team", flash=("error", "Invalid team assignment."))
        target = self.get_user_by_id(user_id)
        self.log_action(session_user["id"], "team_assignment_updated", "user", user_id, target["username"] if target else "user", f"team_id={team_id}")
        return self.redirect(start_response, "/?view=team", flash=("success", "User reassigned to team."))

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
        rows = self.get_users_with_completion(user)
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
            nav_links.insert(1, ("application", "Setup Applications"))
        nav_links.append(("team", "Team"))
        nav_links.append(("notifications", f"Notifications {'⚠️' if unseen_count else ''}"))
        if show_settings:
            nav_links.append(("settings", "Settings"))
        if show_logs:
            nav_links.append(("logs", "Activity Log"))
        nav_links.append(("devlog", "Dev Log"))

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
            users_for_admin = self.get_users_for_account_management(user)

            user_settings_modals = ""
            user_rows = "".join(
                f"""
                <tr>
                  <td>{html.escape(row['username'])}</td>
                  <td>{html.escape(row['role'])}</td>
                  <td>{'Active' if row['is_active'] else 'Deactivated'}</td>
                  <td>
                    <button type='button' class='table-link as-button' data-modal-open='user-settings-{row['id']}'>Open settings</button>
                  </td>
                </tr>
                """
                for row in users_for_admin
            )
            user_settings_modals = "".join(
                f"""
                <div class='modal' id='user-settings-{row['id']}' aria-hidden='true'>
                  <div class='modal-backdrop' data-modal-close='user-settings-{row['id']}'></div>
                  <section class='modal-card card'>
                    <button type='button' class='modal-close' aria-label='Close' data-modal-close='user-settings-{row['id']}'>×</button>
                    <h3>User Settings · {html.escape(row['username'])}</h3>
                    <form method='post' action='/admin/users/update' class='form-grid'>
                      <input type='hidden' name='user_id' value='{row['id']}' />
                      <label>Username
                        <input name='username' value='{html.escape(row['username'])}' required minlength='3' />
                      </label>
                      <label>Role
                        <select name='role'>
                          <option value='admin' {'selected' if row['role'] == 'admin' else ''}>admin</option>
                          <option value='broker' {'selected' if row['role'] == 'broker' else ''}>broker</option>
                          <option value='employer' {'selected' if row['role'] == 'employer' else ''}>employer</option>
                        </select>
                      </label>
                      <label>Status
                        <select name='is_active'>
                          <option value='1' {'selected' if row['is_active'] else ''}>active</option>
                          <option value='0' {'selected' if not row['is_active'] else ''}>deactivated</option>
                        </select>
                      </label>
                      <label>New Password
                        <input name='password' type='password' placeholder='optional password reset' />
                      </label>
                      <button type='submit' class='secondary'>Save</button>
                    </form>
                  </section>
                </div>
                """
                for row in users_for_admin
            )
            create_role_options = "<option value='admin'>admin</option><option value='broker'>broker</option><option value='employer'>employer</option>"
            create_team_options = "".join(f"<option value='{row['id']}'>{html.escape(row['name'])}</option>" for row in self.list_teams())
            create_team_select = f"<select name='team_id' required><option value=''>Select team</option>{create_team_options}</select>" if role == "super_admin" else ""
            broker_admin_section = f"""
              <section class='section-block'>
                <h3>{'Super Admin · Account Management' if role == 'super_admin' else ('Admin · Assigned Organizations' if role == 'admin' else 'Broker · Team Accounts')}</h3>
                <form method='post' action='/admin/users/create' class='inline-form'>
                  <input name='username' placeholder='new username' required minlength='3' />
                  <select name='role'>{create_role_options}</select>
                  {create_team_select}
                  <button type='submit'>Create User</button>
                </form>
                <div class='table-wrap'><table class='user-table'>
                  <thead><tr><th>Username</th><th>Role</th><th>Status</th><th>Modify</th></tr></thead>
                  <tbody>{user_rows}</tbody>
                </table></div>
              </section>
              {user_settings_modals}
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

        team = self.get_team_for_user(user["id"])
        teams = self.list_teams()
        assignable_admins = self.list_assignable_admins()
        team_options = "".join(f"<option value='{row['id']}'>{html.escape(row['name'])}</option>" for row in teams)
        admin_options = "".join(f"<option value='{row['id']}'>{html.escape(row['username'])}</option>" for row in assignable_admins)
        assignable_users = self.list_assignable_users()
        assignable_user_options = "".join(
            f"<option value='{row['id']}'>{html.escape(row['username'])} ({html.escape(row['role'])})</option>"
            for row in assignable_users
        )
        notification_targets = self.get_users_with_completion(user)
        notification_target_options = "".join(f"<option value='{row['id']}'>{html.escape(row['username'])} ({html.escape(row['role'])})</option>" for row in notification_targets)
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

        compose_notification_panel = ""
        if role in {"super_admin", "admin"}:
            compose_notification_panel = f"""
            <section class='section-block panel-card'>
              <h3>Create Notification</h3>
              <form method='post' action='/notifications/create' class='form-grid'>
                <label>Assign To<select name='user_id' required><option value=''>Select user</option>{notification_target_options}</select></label>
                <label>Message<textarea name='message' required></textarea></label>
                <button type='submit'>Send Notification</button>
              </form>
            </section>
            """

        notifications_panel = f"""
            <section class='section-block'>
              <h3>Notifications</h3>
              <ul class='status-list notifications-list'>{notification_rows}</ul>
            </section>
            {compose_notification_panel}
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

        super_admin_team_panel = ""
        if role == "super_admin":
            super_admin_team_panel = f"""
            <section class='section-block panel-card'>
              <h3>Team Administration</h3>
              <form method='post' action='/teams/create' class='inline-form'>
                <input name='name' placeholder='new team name' required minlength='3' />
                <button type='submit'>Create Team</button>
              </form>
              <form method='post' action='/teams/assign-admin' class='inline-form'>
                <select name='admin_user_id' required><option value=''>Select admin</option>{admin_options}</select>
                <select name='team_id' required><option value=''>Select team</option>{team_options}</select>
                <button type='submit'>Assign Admin to Team</button>
              </form>
              <form method='post' action='/teams/assign-user' class='inline-form'>
                <select name='user_id' required><option value=''>Select user</option>{assignable_user_options}</select>
                <select name='team_id' required><option value=''>Select team</option>{team_options}</select>
                <button type='submit'>Assign User to Team</button>
              </form>
            </section>
            """

        team_sections = [
            ("completion", "Team Completion Status"),
            ("administration", "Team Administration") if role == "super_admin" else None,
            ("account-management", "Super Admin - Account Management") if role in {"super_admin", "admin", "broker"} else None,
        ]
        team_sections = [section for section in team_sections if section]
        requested_team_section = (query.get("team_section", [""])[0] or "").strip().lower()
        available_team_section_keys = {key for key, _ in team_sections}
        active_team_section = requested_team_section if requested_team_section in available_team_section_keys else team_sections[0][0]
        team_sub_nav = "".join(
            f"<a class='nav-link {'active' if active_team_section == key else ''}' href='/?view=team&team_section={key}'>{label}</a>"
            for key, label in team_sections
        )

        team_section_content = ""
        if active_team_section == "completion":
            team_section_content = f"""
            <section class='section-block'>
              <h3>Team Completion Status · {html.escape(team['name']) if team else 'Unassigned'}</h3>
              <ul class='status-list'>{status_rows}</ul>
            </section>
            """
        elif active_team_section == "administration":
            team_section_content = super_admin_team_panel
        elif active_team_section == "account-management":
            team_section_content = broker_admin_section

        team_panel = f"""
            <nav class='dashboard-nav sub-nav'>{team_sub_nav}</nav>
            {team_section_content}
        """

        employer_applications_panel = ""
        header_primary_cta = ""
        employer_application_modal = ""
        if role == "employer" and employer_profile:
            ichra_status = "Complete" if employer_profile["application_complete"] else ("In progress" if employer_profile["ichra_started"] else "Not started")
            employer_applications_panel = f"""
                <section class='section-block'>
                  <h3>Applications</h3>
                  <div class='table-wrap'><table class='user-table'>
                    <thead><tr><th>Application</th><th>Status</th><th>Open</th></tr></thead>
                    <tbody>
                      <tr><td>Initial Employer Setup</td><td>Submitted</td><td><a class='table-link' href='/?view=employers'>Open</a></td></tr>
                      <tr><td>ICHRA Setup Application</td><td>{ichra_status}</td><td><button type='button' class='table-link as-button' data-modal-open='ichra-application-modal'>Open</button></td></tr>
                    </tbody>
                  </table></div>
                </section>
            """
            employer_application_modal = f"""
                <div class='modal' id='ichra-application-modal' aria-hidden='true'>
                  <div class='modal-backdrop' data-modal-close='ichra-application-modal'></div>
                  <section class='modal-card card'>
                    <button type='button' class='modal-close' aria-label='Close' data-modal-close='ichra-application-modal'>×</button>
                    <h3>ICHRA Setup Application</h3>
                    <p class='subtitle'>Status: {ichra_status}. Use the button below to continue your ICHRA workflow.</p>
                    <form method='post' action='/employers/start-ichra' class='form-grid'>
                      <button type='submit'>{'Complete ICHRA Setup Application' if employer_profile['ichra_started'] else 'Start ICHRA Setup Application'}</button>
                    </form>
                  </section>
                </div>
            """

            if not employer_profile["ichra_started"]:
                header_primary_cta = """
                    <button type='button' data-modal-open='ichra-application-modal'>Open ICHRA Setup</button>
                """
            elif not employer_profile["application_complete"]:
                header_primary_cta = """
                    <button type='button' class='nav-link active as-button' data-modal-open='ichra-application-modal'>Finish ICHRA Setup Application</button>
                """
            else:
                header_primary_cta = "<span class='nav-link active'>Application Complete</span>"
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
            {employer_application_modal}
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
            <button type='button' class='setup-toggle' data-setup-mode='basic'>Employer Setup Form</button>
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
            <h4>Employer Setup Form</h4>
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
              <button type='submit'>Submit Employer Setup Form</button>
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
        primary_candidates = [row for row in self.get_users_with_completion(session_user) if row["role"] in {"super_admin", "admin", "broker"}]
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

    const stickyHeaders = document.querySelectorAll('.dashboard-header');
    const syncHeaderState = () => {{
      const condensed = window.scrollY > 36;
      stickyHeaders.forEach((header) => header.classList.toggle('is-condensed', condensed));
    }};
    syncHeaderState();
    window.addEventListener('scroll', syncHeaderState, {{ passive: true }});
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
