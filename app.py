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
                role TEXT NOT NULL DEFAULT 'user',
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
                application_complete INTEGER NOT NULL DEFAULT 0,
                linked_user_id INTEGER NOT NULL UNIQUE,
                created_by_user_id INTEGER NOT NULL,
                broker_user_id INTEGER,
                primary_user_id INTEGER,
<<<<<<< codex/fix-button-responsiveness-in-tables-wcdrdh
                ichra_start_date TEXT,
                service_type TEXT,
                claim_option TEXT,
                agent_support TEXT,
=======
>>>>>>> main
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
            db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
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
                ("alex", "Alex", hash_password("user"), "user", "user"),
                ("sam", "Sam", hash_password("user"), "user", "user"),
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
        db.execute("UPDATE users SET role = 'super_admin', created_by_user_id = NULL WHERE username = 'admin'")

        employer_columns = {row[1] for row in db.execute("PRAGMA table_info(employers)").fetchall()}
        if "application_complete" not in employer_columns:
            db.execute("ALTER TABLE employers ADD COLUMN application_complete INTEGER NOT NULL DEFAULT 0")
        if "broker_user_id" not in employer_columns:
            db.execute("ALTER TABLE employers ADD COLUMN broker_user_id INTEGER")
        if "primary_user_id" not in employer_columns:
            db.execute("ALTER TABLE employers ADD COLUMN primary_user_id INTEGER")
<<<<<<< codex/fix-button-responsiveness-in-tables-wcdrdh
        if "ichra_start_date" not in employer_columns:
            db.execute("ALTER TABLE employers ADD COLUMN ichra_start_date TEXT")
        if "service_type" not in employer_columns:
            db.execute("ALTER TABLE employers ADD COLUMN service_type TEXT")
        if "claim_option" not in employer_columns:
            db.execute("ALTER TABLE employers ADD COLUMN claim_option TEXT")
        if "agent_support" not in employer_columns:
            db.execute("ALTER TABLE employers ADD COLUMN agent_support TEXT")
=======
>>>>>>> main
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
            if session_user["role"] not in {"super_admin", "broker"}:
                return self.redirect(start_response, "/", flash=("error", "Only admins and brokers can create users."))
            return self.handle_admin_create_user(start_response, session_user, self.parse_form(environ))

        if path == "/admin/users/update" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] not in {"super_admin", "broker"}:
                return self.redirect(start_response, "/", flash=("error", "Only admins and brokers can modify users."))
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

        if path == "/notifications/seen" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            return self.handle_mark_notification_seen(start_response, session_user, self.parse_form(environ))

        if path == "/employers/settings" and method == "GET":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] not in {"super_admin", "broker", "user"}:
                return self.redirect(start_response, "/", flash=("error", "You do not have permission to edit employer settings."))
            try:
                employer_id = int(query.get("id", [""])[0])
            except ValueError:
                return self.redirect(start_response, "/?view=employers", flash=("error", "Invalid employer selected."))
            return self.render_employer_settings_page(start_response, session_user, employer_id, self.consume_flash(cookie))

        if path == "/employers/update" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] not in {"super_admin", "broker", "user"}:
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
            SELECT u.id, u.username, u.display_name, u.role,
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
            WHERE role IN ('super_admin', 'broker', 'user')
            ORDER BY role, last_login_at DESC, id DESC
            """
        ).fetchall()
        db.close()

        picks = {}
        for row in rows:
            if row["role"] not in picks:
                picks[row["role"]] = row
        ordered_roles = ["super_admin", "broker", "user"]
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
        elif session_user["role"] == "broker":
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username,
                       broker.username AS broker_username
                FROM employers e
                JOIN users u ON u.id = e.linked_user_id
                LEFT JOIN users broker ON broker.id = e.broker_user_id
                WHERE e.broker_user_id = ?
                ORDER BY e.created_at DESC
                """,
                (session_user["id"],),
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
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username,
                       broker.username AS broker_username
                FROM employers e
                JOIN users u ON u.id = e.linked_user_id
                LEFT JOIN users broker ON broker.id = e.broker_user_id
                WHERE e.created_by_user_id = ?
                ORDER BY e.created_at DESC
                """,
                (session_user["id"],),
            ).fetchall()
        db.close()
        return rows

    def get_manageable_brokers(self, session_user):
        db = self.db()
        if session_user["role"] == "super_admin":
            rows = db.execute("SELECT id, username, display_name FROM users WHERE role = 'broker' ORDER BY username").fetchall()
        else:
            rows = db.execute(
                """
                SELECT id, username, display_name
                FROM users
                WHERE role = 'broker' AND (id = ? OR created_by_user_id = ?)
                ORDER BY username
                """,
                (session_user["id"], session_user["id"]),
            ).fetchall()
        db.close()
        return rows

<<<<<<< codex/fix-button-responsiveness-in-tables-wcdrdh
    def get_assignable_primary_users(self, session_user):
        db = self.db()
        if session_user["role"] == "super_admin":
            rows = db.execute(
                "SELECT id, username, role FROM users WHERE role IN ('user', 'broker', 'super_admin') ORDER BY role, username"
            ).fetchall()
        elif session_user["role"] == "broker":
            rows = db.execute(
                "SELECT id, username, role FROM users WHERE id = ? OR (created_by_user_id = ? AND role = 'user') ORDER BY role, username",
                (session_user["id"], session_user["id"]),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT id, username, role FROM users WHERE id = ? OR role = 'super_admin' ORDER BY role, username",
                (session_user["id"],),
            ).fetchall()
        db.close()
        return rows

=======
>>>>>>> main
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
        db.execute("UPDATE employers SET application_complete = ? WHERE linked_user_id = ?", (1 if complete else 0, employer_user_id))
        employer = db.execute("SELECT legal_name, primary_user_id FROM employers WHERE linked_user_id = ?", (employer_user_id,)).fetchone()
        db.commit()
        db.close()
        if complete and employer and employer["primary_user_id"]:
            self.create_notification(employer["primary_user_id"], f"ICHRA setup completed by {employer['legal_name']}.")

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
<<<<<<< codex/fix-button-responsiveness-in-tables-wcdrdh
                industry, website, state, onboarding_task, application_complete, linked_user_id, created_by_user_id, broker_user_id, primary_user_id,
                ichra_start_date, service_type, claim_option, agent_support
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
=======
                industry, website, state, onboarding_task, application_complete, linked_user_id, created_by_user_id, broker_user_id, primary_user_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
>>>>>>> main
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
                linked_user_id,
                creator_user_id,
                broker_user_id,
                primary_user_id,
<<<<<<< codex/fix-button-responsiveness-in-tables-wcdrdh
                form.get("ichra_start_date", "").strip(),
                form.get("service_type", "").strip(),
                form.get("claim_option", "").strip(),
                form.get("agent_support", "").strip(),
=======
>>>>>>> main
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
        role = form.get("role", "user")
        allowed_roles = {"user", "broker", "employer", "super_admin"} if session_user["role"] == "super_admin" else {"user", "employer"}
        if role not in allowed_roles:
            role = "user"
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
        role = form.get("role", "user")
        password = form.get("password", "")
        allowed_roles = {"user", "broker", "employer", "super_admin"} if session_user["role"] == "super_admin" else {"user", "employer"}
        if role not in allowed_roles:
            role = "user"
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
<<<<<<< codex/fix-button-responsiveness-in-tables-wcdrdh
        mode = form.get("setup_mode", "basic")
=======
        mode = form.get("setup_mode", "ichra")
>>>>>>> main

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
        if mode == "ichra":
            required.extend(["ichra_start_date", "service_type", "claim_option", "agent_support"])
        if any(not form.get(name, "").strip() for name in required):
            return self.redirect(start_response, "/?view=application", flash=("error", "Please complete all required fields for the selected setup type."))

        if mode == "basic":
            form["ichra_start_date"] = ""
            form["service_type"] = ""
            form["claim_option"] = ""
            form["agent_support"] = ""

        broker_user_id = session_user["id"] if session_user["role"] == "broker" else None
        username = self.create_employer(session_user["id"], form, broker_user_id=broker_user_id)
        self.log_action(session_user["id"], "employer_created", "employer", None, form["legal_name"].strip(), f"portal_username={username}")
        self.create_notification(session_user["id"], f"{form['legal_name'].strip()} {('ICHRA setup application' if mode == 'ichra' else 'basic employer setup')} submitted.")
        return self.redirect(
            start_response,
            "/?view=employers",
            flash=("success", f"Employer created from {'ICHRA Setup Application' if mode == 'ichra' else 'Basic Employer Setup'}. Portal username: {username}, temporary password: user"),
        )

    def handle_update_employer(self, start_response, session_user, form):
        try:
            employer_id = int(form.get("employer_id", ""))
        except ValueError:
            return self.redirect(start_response, "/?view=employers", flash=("error", "Invalid employer selected."))

        employer = self.get_visible_employer_by_id(session_user, employer_id)
        if not employer:
            return self.redirect(start_response, "/?view=employers", flash=("error", "Employer not found for your access scope."))

        required = [
            "legal_name",
            "contact_name",
            "work_email",
            "phone",
            "company_size",
            "industry",
            "website",
            "state",
            "onboarding_task",
            "portal_username",
        ]
        clean = {key: form.get(key, "").strip() for key in required}
        if any(not clean[key] for key in required):
            return self.redirect(start_response, f"/employers/settings?id={employer_id}", flash=("error", "All employer settings fields are required."))

        broker_value = form.get("broker_user_id", "").strip()
        if broker_value:
            try:
                int(broker_value)
            except ValueError:
                return self.redirect(start_response, f"/employers/settings?id={employer_id}", flash=("error", "Invalid broker assignment."))
        clean["broker_user_id"] = broker_value

        primary_raw = form.get("primary_user_id", "").strip()
        if not primary_raw:
            primary_raw = str(employer["primary_user_id"] or "")
        if not primary_raw:
            return self.redirect(start_response, f"/employers/settings?id={employer_id}", flash=("error", "Primary assignment is required."))

        try:
            primary_user_id = int(primary_raw)
        except ValueError:
            return self.redirect(start_response, f"/employers/settings?id={employer_id}", flash=("error", "Invalid primary assignment."))

        allowed_primary_ids = {row["id"] for row in self.get_assignable_primary_users(session_user)}
        if primary_user_id not in allowed_primary_ids:
            return self.redirect(start_response, f"/employers/settings?id={employer_id}", flash=("error", "Selected primary is outside your allowed scope."))

        clean["primary_user_id"] = str(primary_user_id)

        if len(clean["portal_username"]) < 3:
            return self.redirect(start_response, f"/employers/settings?id={employer_id}", flash=("error", "Employer username must be at least 3 characters."))
        portal_password = form.get("portal_password", "")
        if portal_password and len(portal_password) < 4:
            return self.redirect(start_response, f"/employers/settings?id={employer_id}", flash=("error", "Employer password must be at least 4 characters."))
        clean["portal_password"] = portal_password

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
                <label>Password <input type="password" name="password" placeholder="password" required /></label>
                <button type="submit">Log In to Continue</button>
              </form>
              <div class="hint"><strong>Active demo accounts (DB-backed):</strong>
                <ul>{demo_rows or '<li>No active users found.</li>'}</ul>
              </div>
              <hr />
<<<<<<< codex/fix-button-responsiveness-in-tables-wcdrdh
              <div class="welcome-cta">
                <h2>New Employer Setup</h2>
                <p class="subtitle">New here? Start with a short setup request and we’ll help you get enrolled.</p>
                <button type="button" class="secondary" onclick="document.getElementById('signup-modal').showModal()">Start New Employer Setup</button>
              </div>
              <dialog id="signup-modal" class="signup-modal">
                <form method="dialog" class="modal-close-row">
                  <button class="secondary" type="submit">Close</button>
                </form>
                <h2>Welcome, future employer 👋</h2>
                <p class="subtitle">Tell us about your company and we’ll get your basic employer profile started.</p>
                <form method="post" action="/signup" class="form-grid">
                  <label>Employer Legal Name <input type="text" name="legal_name" required /></label>
                  <label>Contact Name <input type="text" name="prospect_name" required /></label>
                  <label>Work Email <input type="email" name="prospect_email" required /></label>
                  <label>Phone <input type="text" name="prospect_phone" /></label>
                  <button type="submit">Submit Employer Request</button>
                </form>
              </dialog>
=======
              <h2>Prospective Employer Sign Up</h2>
              <p class="subtitle">Public form for employers needing a basic employer setup request.</p>
              <form method="post" action="/signup" class="form-grid">
                <label>Employer Legal Name <input type="text" name="legal_name" required /></label>
                <label>Contact Name <input type="text" name="prospect_name" required /></label>
                <label>Work Email <input type="email" name="prospect_email" required /></label>
                <label>Phone <input type="text" name="prospect_phone" /></label>
                <button type="submit" class="secondary">Submit Employer Request</button>
              </form>
>>>>>>> main
            </section>
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
            "user": "Team Contributor Dashboard",
        }.get(role, "Dashboard")

        role_banner = {
            "super_admin": "Manage broker accounts and system-wide visibility.",
            "broker": "Create employers and monitor all applications assigned to your book.",
            "employer": "Review your application and complete outstanding onboarding tasks.",
            "user": "Track deployment progress and support employer setup requests.",
        }.get(role, "")

        show_application = role in {"super_admin", "broker", "user"}
        show_settings = role in {"super_admin", "broker", "user"}
        show_logs = role == "super_admin"

        notifications = self.list_notifications(user["id"])
        unseen_count = sum(1 for item in notifications if not item["seen"])

        nav_links = [("dashboard", "Dashboard"), ("employers", "Employers"), ("notifications", f"Notifications {'⚠️' if unseen_count else ''}")]
        if show_application:
            nav_links.insert(1, ("application", "ICHRA Setup Application"))
        if show_settings:
            nav_links.append(("settings", "Settings"))
        if show_logs:
            nav_links.append(("logs", "Activity Log"))

        nav_html = "".join(
            f"<a class='nav-link {'active' if active_view == key else ''}' href='/?view={key}'>{label}</a>"
            for key, label in nav_links
        )

        task_section = ""
        if role in {"super_admin", "broker", "user"}:
            task_section = """
              <article class='task-card'>
                <h2>Deployment Readiness Task</h2>
                <p>Confirm the app works in Codespaces and on Linode.</p>
                <form method='post' action='/task/complete'><button type='submit'>Mark My Task Complete</button></form>
              </article>
            """

        employer_workspace = ""
        if role == "employer":
            employer_workspace = """
              <section class='section-block'>
                <h3>Application Workflow</h3>
                <p class='subtitle'>Use these actions to keep your employer application up to date.</p>
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

        broker_admin_section = ""
        if role in {"super_admin", "broker"}:
            users_for_admin = [row for row in rows if row["role"] != "employer"]
            if role == "broker":
                users_for_admin = [row for row in users_for_admin if row["role"] == "user"]
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
                        <option value='user' {'selected' if row['role'] == 'user' else ''}>user</option>
                        <option value='broker' {'selected' if row['role'] == 'broker' else ''}>broker</option>
                        <option value='super_admin' {'selected' if row['role'] == 'super_admin' else ''}>super_admin</option>
                      </select>
                      <input name='password' type='password' placeholder='new password (optional)' />
                      <button type='submit' class='secondary'>Save</button>
                    </form>
                  </td>
                </tr>
                """
                for row in users_for_admin
            )
            create_role_options = "<option value='user'>user</option><option value='employer'>employer</option>"
            if role == "super_admin":
                create_role_options = create_role_options + "<option value='broker'>broker</option><option value='super_admin'>super_admin</option>"
            broker_admin_section = f"""
              <section class='section-block'>
                <h3>{'Admin · Account Management' if role == 'super_admin' else 'Broker · Team Accounts'}</h3>
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
        if show_settings:
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
                    <option value='user' {'selected' if query.get('role', [''])[0] == 'user' else ''}>user</option>
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

        dashboard_panel = f"""
            {task_section}
            <section class='section-block'>
              <h3>Team Completion Status</h3>
              <ul class='status-list'>{status_rows}</ul>
            </section>
            {employer_workspace}
            {broker_admin_section}
        """

        panel_lookup = {
            "dashboard": dashboard_panel,
            "application": self.render_ichra_application_form() if show_application else "",
            "employers": employers_panel,
            "notifications": notifications_panel,
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

    def render_ichra_application_form(self):
        return """
        <section class='section-block'>
          <h3>ICHRA Setup Application</h3>
          <p class='subtitle'>(takes 5 - 10 minutes to complete)</p>
          <p class='subtitle'>Used to sign an employer up for ICHRA once the employer record already exists.</p>
          <form method='post' action='/employers/create' class='form-grid'>
            <label>Setup Type *
              <select name='setup_mode'>
                <option value='ichra'>ICHRA Setup Application</option>
                <option value='basic'>Basic Employer Setup</option>
              </select>
            </label>
<<<<<<< codex/fix-button-responsiveness-in-tables-wcdrdh
            <details class='field-log'>
              <summary>Need only a basic employer profile?</summary>
              <p>Choose <strong>Basic Employer Setup</strong> and complete only company information fields before submitting.</p>
            </details>
=======
>>>>>>> main
            <h4>Desired ICHRA Start Date *</h4><input type='date' name='ichra_start_date' required />
            <div class='ichra-only'>
              <h4>Which service are you signing up for? *</h4>
              <label><input type='radio' name='service_type' value='ICHRA Documents + Monthly Administration' required /> ICHRA Documents + Monthly Administration</label>
              <label><input type='radio' name='service_type' value='ICHRA Documents Only' /> ICHRA Documents Only</label>
            </div>

            <h4>Primary and ICHRA Setup Contact</h4>
            <label>Primary Contact First Name *<input name='primary_first_name' required /></label>
            <label>Primary Contact Last Name *<input name='primary_last_name' required /></label>
            <label>Phone *<input name='primary_phone' required /></label>
            <label>Email *<input type='email' name='primary_email' required /></label>
            <h4>What type of contact is this? (please check all that apply) *</h4>
            <label><input type='checkbox' name='primary_main' value='yes' /> Main</label>
            <label><input type='checkbox' name='primary_payroll' value='yes' /> Payroll</label>
            <label><input type='checkbox' name='primary_compliance' value='yes' /> Compliance</label>
            <label><input type='checkbox' name='primary_billing' value='yes' /> Billing</label>

            <h4>Secondary Contact (Click Next to skip)</h4>
            <label>First<input name='secondary_first_name' /></label>
            <label>Last<input name='secondary_last_name' /></label>
            <label>Phone<input name='secondary_phone' /></label>
            <label>Email<input type='email' name='secondary_email' /></label>

            <h4>ICHRA Welcome Call</h4>
            <label>Select number of participants<input type='number' min='1' name='welcome_call_participants' /></label>

            <h4>Company Information</h4>
            <label>Legal Business Name *<input name='legal_name' required /></label>
            <label>Doing Business As (if applicable)<input name='doing_business_as' /></label>
            <label>Phone *<input name='phone' required /></label>
            <label>Nature of Business *<input name='nature_of_business' required /></label>
            <label>Total Employee Count *<input type='number' name='total_employee_count' required /></label>
            <label>Total Eligible Employees *<input type='number' name='total_eligible_employees' required /></label>
            <label>Federal EIN *<input name='federal_ein' required /></label>
            <label>Corporation Type *<input name='corporation_type' required /></label>
            <label>LLC Filed As<input name='llc_filed_as' /></label>

            <h4>Address</h4>
            <label>Physical Address Line 1 *<input name='physical_address_1' required /></label>
            <label>Physical Address Line 2<input name='physical_address_2' /></label>
            <label>Physical City *<input name='physical_city' required /></label>
            <label>Physical State *<input name='physical_state' required /></label>
            <label>Physical Zip Code *<input name='physical_zip' required /></label>
            <label>Mailing Address Line 1<input name='mailing_address_1' /></label>
            <label>Mailing Address Line 2<input name='mailing_address_2' /></label>
            <label>Mailing City<input name='mailing_city' /></label>
            <label>Mailing State<input name='mailing_state' /></label>
            <label>Mailing Zip Code<input name='mailing_zip' /></label>
            <label>Other participating entities/companies<input name='participating_entities' /></label>

            <div class='ichra-only'>
              <h4>ICHRA Setup - Step 1 of 4 - Reimbursements</h4>
              <label>Which reimbursement option do you want to offer? *<input name='reimbursement_option' required /></label>

              <h4>ICHRA Setup - 2 of 4 - Eligibility</h4>
              <label>Do you need assistance with employee classes? *<input name='employee_class_assistance' required /></label>
              <label>New hire eligibility period *<input name='new_hire_eligibility_period' required /></label>

              <h4>ICHRA Setup - 3 of 4 - Contributions</h4>
              <label>What are you planning to contribute? *<input name='planned_contribution' required /></label>
              <label>Spouse/Dependent/Family contributions<input name='dependent_contributions' /></label>

              <h4>ICHRA Setup - 4 of 4 - Claim Options</h4>
              <label>Which claim option would you like to use? *<input name='claim_option' required /></label>

              <h4>Agent Information</h4>
              <label>Are you working with a health insurance agent? *<input name='agent_support' required /></label>
            </div>

            <h4>Plan Fee and Ongoing Reimbursements</h4>
            <label>Please upload completed Bank Authorization (for reference only in this demo)<input type='file' name='bank_authorization_upload' /></label>
            <label><input type='checkbox' name='terms_agreed' value='yes' required /> I agree to the terms and conditions *</label>
            <label>Do you have any questions for us?<textarea name='questions_for_team'></textarea></label>

            <button type='submit'>Finalize and Submit ICHRA Application</button>
          </form>
          <details class='field-log'>
            <summary>Field inventory captured from provided source form</summary>
            <p>Desired start date, service type, primary/secondary contacts, welcome call participants, company information, physical/mailing addresses,
            participating entities, reimbursement setup, eligibility, contributions, claim options, agent details, bank authorization upload, terms acceptance,
            final questions, and submit action.</p>
          </details>
          <script>
            (function () {
              const form = document.currentScript.closest('section').querySelector('form');
              const modeSelect = form.querySelector("select[name='setup_mode']");
              const ichraBlocks = form.querySelectorAll('.ichra-only');
              const toggle = () => {
                const basic = modeSelect.value === 'basic';
                ichraBlocks.forEach((el) => {
                  el.style.display = basic ? 'none' : 'block';
                  el.querySelectorAll('input').forEach((input) => {
                    if (input.name === 'service_type' || input.name === 'claim_option' || input.name === 'agent_support') {
                      input.required = !basic;
                    }
                  });
                });
              };
              modeSelect.addEventListener('change', toggle);
              toggle();
            })();
          </script>
        </section>
        """

    def render_employer_settings_link(self, employer_row, role: str) -> str:
        if role not in {"super_admin", "broker", "user"}:
            return "<span class='subtitle'>Read-only</span>"
        return f"<a class='settings-link' href='/employers/settings?id={employer_row['id']}'>Open settings</a>"

    def render_employer_settings_page(self, start_response, session_user, employer_id: int, flash_message):
        employer = self.get_visible_employer_by_id(session_user, employer_id)
        if not employer:
            return self.redirect(start_response, "/?view=employers", flash=("error", "Employer not found for your access scope."))

        broker_options = "".join(
            f"<option value='{row['id']}' {'selected' if employer['broker_user_id'] == row['id'] else ''}>{html.escape(row['username'])}</option>"
            for row in self.get_manageable_brokers(session_user)
        )
        primary_options = "".join(
            f"<option value='{row['id']}' {'selected' if employer['primary_user_id'] == row['id'] else ''}>{html.escape(row['username'])} ({html.escape(row['role'])})</option>"
            for row in self.get_assignable_primary_users(session_user)
        )

        body = self.flash_html(flash_message) + f"""
            <section class='card dashboard role-{session_user['role']} theme-{session_user['theme']} density-{session_user['density']}'>
              <header class='dashboard-header'>
                <div>
                  <h1>Employer Settings Dashboard</h1>
                  <p class='subtitle'>Company profile, assignments, and ICHRA setup details in one place.</p>
                </div>
                <a class='nav-link' href='/?view=employers'>Back to Employers</a>
              </header>
              <section class='section-block settings-dashboard-grid'>
                <article class='task-card'>
                  <h3>Company Data</h3>
                  {self.render_employer_edit_form(employer, broker_options, primary_options)}
                </article>
                <article class='task-card'>
                  <h3>ICHRA Application Data</h3>
                  <div class='details-grid'>
                    <p><strong>ICHRA Start Date:</strong> {html.escape(employer['ichra_start_date'] or 'Not provided')}</p>
                    <p><strong>Service Type:</strong> {html.escape(employer['service_type'] or 'Not provided')}</p>
                    <p><strong>Claim Option:</strong> {html.escape(employer['claim_option'] or 'Not provided')}</p>
                    <p><strong>Agent Support:</strong> {html.escape(employer['agent_support'] or 'Not provided')}</p>
                    <p><strong>Application Status:</strong> {'Complete' if employer['application_complete'] else 'In progress'}</p>
                  </div>
                </article>
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
          <input type='hidden' name='employer_id' value='{employer_row['id']}' />
          <label>Legal Name<input name='legal_name' value='{html.escape(employer_row['legal_name'])}' required /></label>
          <label>Contact<input name='contact_name' value='{html.escape(employer_row['contact_name'])}' required /></label>
          <label>Email<input name='work_email' type='email' value='{html.escape(employer_row['work_email'])}' required /></label>
          <label>Phone<input name='phone' value='{html.escape(employer_row['phone'])}' required /></label>
          <label>Size<input name='company_size' value='{html.escape(employer_row['company_size'])}' required /></label>
          <label>Industry<input name='industry' value='{html.escape(employer_row['industry'])}' required /></label>
          <label>Website<input name='website' value='{html.escape(employer_row['website'])}' required /></label>
          <label>State<input name='state' value='{html.escape(employer_row['state'])}' required /></label>
          <label>Assigned Broker
            <select name='broker_user_id'>
              <option value=''>Unassigned</option>
              {broker_options}
            </select>
          </label>
          <label>Primary Owner *
            <select name='primary_user_id' required>
              {primary_options}
            </select>
          </label>
          <label>Onboarding Task<textarea name='onboarding_task' required>{html.escape(employer_row['onboarding_task'])}</textarea></label>
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
