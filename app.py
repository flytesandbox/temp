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
                role TEXT NOT NULL DEFAULT 'user',
                created_by_user_id INTEGER
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
                linked_user_id INTEGER NOT NULL UNIQUE,
                created_by_user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        user_columns = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "created_by_user_id" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN created_by_user_id INTEGER")

        db.executemany(
            """
            INSERT OR IGNORE INTO users (username, display_name, password_hash, role, created_by_user_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                ("alex", "Alex", hash_password("password123"), "user", None),
                ("sam", "Sam", hash_password("password123"), "user", None),
                ("admin", "Super Admin", hash_password("admin123"), "super_admin", None),
            ],
        )
        db.commit()
        db.close()

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "/")
        method = environ.get("REQUEST_METHOD", "GET")
        cookie = self.parse_cookies(environ.get("HTTP_COOKIE", ""))
        session_user = self.read_session_user(cookie)

        if path.startswith("/static/"):
            return self.serve_static(path, start_response)

        if path == "/":
            if not session_user:
                return self.redirect(start_response, "/login")
            return self.render_dashboard(start_response, session_user, self.consume_flash(cookie))

        if path == "/login" and method == "GET":
            return self.render_login(start_response, self.consume_flash(cookie))

        if path == "/login" and method == "POST":
            return self.handle_login(start_response, self.parse_form(environ))

        if path == "/logout" and method == "POST":
            return self.handle_logout(start_response)

        if path == "/employers/create" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            return self.handle_create_employer(start_response, session_user, self.parse_form(environ))

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

    def build_employer_username(self, db, legal_name: str) -> str:
        seed = "".join(ch for ch in legal_name.lower() if ch.isalnum())[:12] or "employer"
        count = db.execute("SELECT COUNT(*) AS n FROM users WHERE username LIKE ?", (f"{seed}%",)).fetchone()["n"]
        return f"{seed}{count + 1}"

    def create_employer(self, creator_user_id: int, form: dict[str, str]):
        db = self.db()
        username = self.build_employer_username(db, form["legal_name"])
        display_name = form["contact_name"].strip() or form["legal_name"].strip()
        db.execute(
            """
            INSERT INTO users (username, display_name, password_hash, role, created_by_user_id)
            VALUES (?, ?, ?, 'employer', ?)
            """,
            (username, display_name, hash_password("employer123"), creator_user_id),
        )
        linked_user_id = db.execute("SELECT last_insert_rowid() AS i").fetchone()["i"]

        db.execute(
            """
            INSERT INTO employers (
                legal_name, contact_name, work_email, phone, company_size,
                industry, website, state, onboarding_task, linked_user_id, created_by_user_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                linked_user_id,
                creator_user_id,
            ),
        )
        db.commit()
        db.close()
        return username

    def list_visible_employers(self, session_user):
        db = self.db()
        if session_user["role"] == "employer":
            owner_id = session_user["created_by_user_id"]
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username
                FROM employers e
                JOIN users u ON u.id = e.linked_user_id
                WHERE e.created_by_user_id = ?
                ORDER BY e.created_at DESC
                """,
                (owner_id,),
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username
                FROM employers e
                JOIN users u ON u.id = e.linked_user_id
                WHERE e.created_by_user_id = ?
                ORDER BY e.created_at DESC
                """,
                (session_user["id"],),
            ).fetchall()
        db.close()
        return rows

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

        headers = [
            ("Location", "/"),
            ("Set-Cookie", self.cookie_header("session", self.sign(f"uid:{user['id']}"))),
            ("Set-Cookie", self.cookie_header("flash", self.sign(f"success:Welcome, {user['display_name']}!"))),
        ]
        start_response("302 Found", headers)
        return [b""]

    def handle_create_employer(self, start_response, session_user, form):
        if session_user["role"] == "employer":
            return self.redirect(start_response, "/", flash=("error", "Employer accounts are read-only."))

        required = [
            "legal_name",
            "contact_name",
            "work_email",
            "phone",
            "company_size",
            "industry",
            "website",
            "state",
        ]
        if any(not form.get(name, "").strip() for name in required):
            return self.redirect(start_response, "/", flash=("error", "Please complete all employer onboarding fields."))

        username = self.create_employer(session_user["id"], form)
        return self.redirect(
            start_response,
            "/",
            flash=("success", f"Employer onboarded. Portal username: {username}, temporary password: employer123"),
        )

    def handle_logout(self, start_response):
        headers = [
            ("Location", "/login"),
            ("Set-Cookie", self.expire_cookie_header("session")),
            ("Set-Cookie", self.expire_cookie_header("flash")),
        ]
        start_response("302 Found", headers)
        return [b""]

    def cookie_header(self, name: str, value: str, max_age: int = 60 * 60 * 24):
        morsel = cookies.SimpleCookie()
        morsel[name] = value
        morsel[name]["path"] = "/"
        morsel[name]["max-age"] = str(max_age)
        morsel[name]["httponly"] = True
        morsel[name]["samesite"] = "Lax"
        return morsel.output(header="").strip()

    def expire_cookie_header(self, name: str):
        morsel = cookies.SimpleCookie()
        morsel[name] = ""
        morsel[name]["path"] = "/"
        morsel[name]["max-age"] = "0"
        morsel[name]["httponly"] = True
        morsel[name]["samesite"] = "Lax"
        return morsel.output(header="").strip()

    def redirect(self, start_response, location: str, flash: tuple[str, str] | None = None):
        headers = [("Location", location)]
        if flash:
            headers.append(("Set-Cookie", self.cookie_header("flash", self.sign(f"{flash[0]}:{flash[1]}"), max_age=30)))
        start_response("302 Found", headers)
        return [b""]

    def render_login(self, start_response, flash_message):
        html_body = self.flash_html(flash_message) + """
            <section class='card auth-card'>
              <p class='eyebrow'>Employer Onboarding App</p>
              <h1>Sign in</h1>
              <p class='subtitle'>Use your account to onboard employers and assign their first task.</p>
              <form method='post' action='/login' class='form-grid'>
                <label>Username<input type='text' name='username' required /></label>
                <label>Password<input type='password' name='password' required /></label>
                <button type='submit'>Log in</button>
              </form>
              <div class='hint'><strong>Demo:</strong> alex/password123, sam/password123, admin/admin123</div>
            </section>
        """
        html_doc = self.html_page("Employer Onboarding · Login", html_body)
        headers = [("Content-Type", "text/html; charset=utf-8"), ("Set-Cookie", self.expire_cookie_header("flash"))]
        start_response("200 OK", headers)
        return [html_doc.encode("utf-8")]

    def render_dashboard(self, start_response, user, flash_message):
        employers = self.list_visible_employers(user)
        employer_rows = "".join(
            f"""
            <tr>
              <td>{html.escape(row['legal_name'])}</td>
              <td>{html.escape(row['contact_name'])}</td>
              <td>{html.escape(row['work_email'])}</td>
              <td>{html.escape(row['portal_username'])}</td>
              <td>{html.escape(row['onboarding_task'])}</td>
            </tr>
            """
            for row in employers
        )
        if not employer_rows:
            employer_rows = "<tr><td colspan='5'>No employers onboarded yet.</td></tr>"

        form_section = ""
        if user["role"] != "employer":
            form_section = """
            <section class='card form-card'>
              <h2>Employer onboarding form</h2>
              <p class='subtitle'>Reimagined from a long-form marketing intake. Completing this form creates a new Employer account.</p>
              <form method='post' action='/employers/create' class='onboarding-grid'>
                <label>Legal business name<input name='legal_name' required /></label>
                <label>Primary contact<input name='contact_name' required /></label>
                <label>Work email<input type='email' name='work_email' required /></label>
                <label>Phone number<input name='phone' required /></label>
                <label>Company size
                  <select name='company_size' required>
                    <option value=''>Select...</option>
                    <option>1-24</option><option>25-49</option><option>50-99</option><option>100+</option>
                  </select>
                </label>
                <label>Industry<input name='industry' required /></label>
                <label>Website<input name='website' placeholder='https://example.com' required /></label>
                <label>Headquarters state<input name='state' required /></label>
                <button type='submit'>Complete form & create Employer</button>
              </form>
            </section>
            """

        role_note = (
            "Employer accounts are read-only. You can only view employers created by your onboarding manager."
            if user["role"] == "employer"
            else "All non-employer users can submit onboarding forms to create Employers."
        )

        html_body = self.flash_html(flash_message) + f"""
            <section class='card dashboard'>
              <header class='dashboard-header'>
                <div>
                  <p class='eyebrow'>Employer Onboarding Workspace</p>
                  <h1>Welcome, {html.escape(user['display_name'])}</h1>
                  <p class='subtitle'>{html.escape(role_note)}</p>
                </div>
                <form method='post' action='/logout'><button class='secondary' type='submit'>Log out</button></form>
              </header>
            </section>
            {form_section}
            <section class='card'>
              <h2>Visible Employers</h2>
              <table class='user-table'>
                <thead><tr><th>Employer</th><th>Contact</th><th>Email</th><th>Portal Username</th><th>Assigned task</th></tr></thead>
                <tbody>{employer_rows}</tbody>
              </table>
            </section>
        """
        html_doc = self.html_page("Employer Onboarding", html_body)
        headers = [("Content-Type", "text/html; charset=utf-8"), ("Set-Cookie", self.expire_cookie_header("flash"))]
        start_response("200 OK", headers)
        return [html_doc.encode("utf-8")]

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
