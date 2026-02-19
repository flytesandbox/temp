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
                role TEXT NOT NULL DEFAULT 'user',
                theme TEXT NOT NULL DEFAULT 'default',
                density TEXT NOT NULL DEFAULT 'comfortable',
                created_by_user_id INTEGER
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
                linked_user_id INTEGER NOT NULL UNIQUE,
                created_by_user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        columns = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "role" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        if "theme" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'default'")
        if "density" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN density TEXT NOT NULL DEFAULT 'comfortable'")
        if "created_by_user_id" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN created_by_user_id INTEGER")

        db.executemany(
            """
            INSERT OR IGNORE INTO users (username, display_name, password_hash, role)
            VALUES (?, ?, ?, ?)
            """,
            [
                ("alex", "Alex", hash_password("password123"), "user"),
                ("sam", "Sam", hash_password("password123"), "user"),
                ("admin", "Super Admin", hash_password("admin123"), "super_admin"),
            ],
        )
        db.executemany(
            """
            UPDATE users
            SET password_hash = ?
            WHERE username = ?
            """,
            [
                (hash_password("password123"), "alex"),
                (hash_password("password123"), "sam"),
                (hash_password("admin123"), "admin"),
            ],
        )
        db.execute("UPDATE users SET role = 'super_admin', created_by_user_id = NULL WHERE username = 'admin'")
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

        if path == "/task/complete" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] == "employer":
                return self.redirect(start_response, "/", flash=("error", "Employer accounts are read-only."))
            self.complete_for_user(session_user["id"], 1)
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
            if session_user["role"] != "super_admin":
                return self.redirect(start_response, "/", flash=("error", "Only the super admin can create users."))
            return self.handle_admin_create_user(start_response, self.parse_form(environ))

        if path == "/admin/users/update" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] != "super_admin":
                return self.redirect(start_response, "/", flash=("error", "Only the super admin can modify users."))
            return self.handle_admin_update_user(start_response, self.parse_form(environ))

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

    def list_visible_employers(self, session_user):
        db = self.db()
        creator_id = session_user["id"] if session_user["role"] != "employer" else session_user["created_by_user_id"]
        rows = db.execute(
            """
            SELECT e.*, u.username AS portal_username
            FROM employers e
            JOIN users u ON u.id = e.linked_user_id
            WHERE e.created_by_user_id = ?
            ORDER BY e.created_at DESC
            """,
            (creator_id,),
        ).fetchall()
        db.close()
        return rows

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
            "UPDATE users SET username = ?, display_name = ?, password_hash = ? WHERE id = ?",
            (username, username.capitalize(), new_password, user_id),
        )
        db.commit()
        db.close()

    def update_user_style(self, user_id: int, theme: str, density: str):
        db = self.db()
        db.execute("UPDATE users SET theme = ?, density = ? WHERE id = ?", (theme, density, user_id))
        db.commit()
        db.close()

    def create_user(self, username: str, password: str, role: str):
        db = self.db()
        db.execute(
            "INSERT INTO users (username, display_name, password_hash, role, created_by_user_id) VALUES (?, ?, ?, ?, NULL)",
            (username, username.capitalize(), hash_password(password), role),
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
            "UPDATE users SET username = ?, display_name = ?, role = ?, password_hash = ? WHERE id = ?",
            (username, username.capitalize(), role, password_hash, user_id),
        )
        db.commit()
        db.close()

    def build_employer_username(self, db, legal_name: str) -> str:
        seed = "".join(ch for ch in legal_name.lower() if ch.isalnum())[:12] or "employer"
        count = db.execute("SELECT COUNT(*) AS n FROM users WHERE username LIKE ?", (f"{seed}%",)).fetchone()["n"]
        return f"{seed}{count + 1}"

    def create_employer(self, creator_user_id: int, form: dict[str, str]) -> str:
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

    def handle_profile_settings(self, start_response, session_user, form):
        username = form.get("username", "").strip().lower()
        password = form.get("password", "")

        if len(username) < 3:
            return self.redirect(start_response, "/", flash=("error", "Username must be at least 3 characters."))
        if password and len(password) < 6:
            return self.redirect(start_response, "/", flash=("error", "Password must be at least 6 characters."))

        try:
            self.update_user_profile(session_user["id"], username, password)
        except sqlite3.IntegrityError:
            return self.redirect(start_response, "/", flash=("error", "That username is already in use."))
        return self.redirect(start_response, "/", flash=("success", "Profile updated."))

    def handle_style_settings(self, start_response, session_user, form):
        theme = form.get("theme", "default")
        density = form.get("density", "comfortable")
        if theme not in ALLOWED_THEMES or density not in ALLOWED_DENSITIES:
            return self.redirect(start_response, "/", flash=("error", "Invalid style settings."))
        self.update_user_style(session_user["id"], theme, density)
        return self.redirect(start_response, "/", flash=("success", "Dashboard style saved."))

    def handle_admin_create_user(self, start_response, form):
        username = form.get("username", "").strip().lower()
        password = form.get("password", "")
        role = form.get("role", "user")
        if role not in {"user", "super_admin"}:
            role = "user"
        if len(username) < 3 or len(password) < 6:
            return self.redirect(start_response, "/", flash=("error", "New users need a username (3+) and password (6+)."))
        try:
            self.create_user(username, password, role)
        except sqlite3.IntegrityError:
            return self.redirect(start_response, "/", flash=("error", "Unable to create user. Username may already exist."))
        return self.redirect(start_response, "/", flash=("success", "User created."))

    def handle_admin_update_user(self, start_response, form):
        try:
            user_id = int(form.get("user_id", ""))
        except ValueError:
            return self.redirect(start_response, "/", flash=("error", "Invalid user selected."))
        username = form.get("username", "").strip().lower()
        role = form.get("role", "user")
        password = form.get("password", "")
        if role not in {"user", "super_admin"}:
            role = "user"
        if len(username) < 3:
            return self.redirect(start_response, "/", flash=("error", "Username must be at least 3 characters."))

        try:
            self.admin_update_user(user_id, username, role, password)
        except ValueError:
            return self.redirect(start_response, "/", flash=("error", "User no longer exists."))
        except sqlite3.IntegrityError:
            return self.redirect(start_response, "/", flash=("error", "Cannot update user to that username."))
        return self.redirect(start_response, "/", flash=("success", "User updated."))

    def handle_create_employer(self, start_response, session_user, form):
        if session_user["role"] == "employer":
            return self.redirect(start_response, "/", flash=("error", "Employer accounts are read-only."))

        required = ["legal_name", "contact_name", "work_email", "phone", "company_size", "industry", "website", "state"]
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
        html_body = self.flash_html(flash_message) + """
            <section class="card auth-card">
              <p class="eyebrow">Monolith Workspace</p>
              <h1>Log in to continue</h1>
              <p class="subtitle">Choose your account and keep the deployment checklist moving.</p>
              <form method="post" action="/login" class="form-grid">
                <label>Username <input type="text" name="username" placeholder="alex" required /></label>
                <label>Password <input type="password" name="password" placeholder="password" required /></label>
                <button type="submit">Log In to Continue</button>
              </form>
              <div class="hint"><strong>Demo accounts:</strong>
                <ul>
                  <li><code>alex</code> / <code>password123</code></li>
                  <li><code>sam</code> / <code>password123</code></li>
                  <li><code>admin</code> / <code>admin123</code> (super admin)</li>
                </ul>
              </div>
            </section>
            """
        html_doc = self.html_page("Monolith Task Tracker", html_body)
        headers = [("Content-Type", "text/html; charset=utf-8"), ("Set-Cookie", self.expire_cookie_header("flash"))]
        start_response("200 OK", headers)
        return [html_doc.encode("utf-8")]

    def render_dashboard(self, start_response, user, flash_message):
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

        admin_section = ""
        if user["role"] == "super_admin":
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
                        <option value='super_admin' {'selected' if row['role'] == 'super_admin' else ''}>super_admin</option>
                      </select>
                      <input name='password' type='password' placeholder='new password (optional)' />
                      <button type='submit' class='secondary'>Save</button>
                    </form>
                  </td>
                </tr>
                """
                for row in rows
            )
            admin_section = f"""
              <section class='section-block'>
                <h3>Super Admin · User Management</h3>
                <form method='post' action='/admin/users/create' class='inline-form'>
                  <input name='username' placeholder='new username' required minlength='3' />
                  <input name='password' type='password' placeholder='new password' required minlength='6' />
                  <select name='role'>
                    <option value='user'>user</option>
                    <option value='super_admin'>super_admin</option>
                  </select>
                  <button type='submit'>Create User</button>
                </form>
                <table class='user-table'>
                  <thead><tr><th>Username</th><th>Role</th><th>Modify</th></tr></thead>
                  <tbody>{user_rows}</tbody>
                </table>
              </section>
            """

        employer_form_section = ""
        settings_section = ""
        task_section = ""
        if user["role"] != "employer":
            task_section = """
              <article class='task-card'>
                <h2>Deployment Readiness Task</h2>
                <p>Confirm the app works in Codespaces and on Linode.</p>
                <form method='post' action='/task/complete'><button type='submit'>Mark My Task Complete</button></form>
              </article>
            """
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
            employer_form_section = """
              <section class='section-block'>
                <h3>Employer Onboarding</h3>
                <p class='subtitle'>New Employers are added once this form is complete.</p>
                <form method='post' action='/employers/create' class='onboarding-grid'>
                  <label>Legal business name
                    <input name='legal_name' required />
                  </label>
                  <label>Primary contact
                    <input name='contact_name' required />
                  </label>
                  <label>Work email
                    <input name='work_email' type='email' required />
                  </label>
                  <label>Phone
                    <input name='phone' required />
                  </label>
                  <label>Company size
                    <select name='company_size' required>
                      <option value=''>Select...</option>
                      <option>1-24</option><option>25-49</option><option>50-99</option><option>100+</option>
                    </select>
                  </label>
                  <label>Industry
                    <input name='industry' required />
                  </label>
                  <label>Website
                    <input name='website' placeholder='https://example.com' required />
                  </label>
                  <label>Headquarters state
                    <input name='state' required />
                  </label>
                  <button type='submit'>Complete form & create Employer</button>
                </form>
              </section>
            """

        employer_note = (
            "Employer accounts are read-only and can only see employers created by your manager."
            if user["role"] == "employer"
            else "All non-employer users can create new Employers from this form."
        )

        html_body = self.flash_html(flash_message) + f"""
            <section class='card dashboard theme-{user['theme']} density-{user['density']}'>
              <div class='welcome-banner'>🎉 Great to see you! Let's make today productive.</div>
              <header class='dashboard-header'>
                <div>
                  <h1>Welcome, {html.escape(user['display_name'])}</h1>
                  <p class='subtitle'>Track shared progress for deployment validation.</p>
                </div>
                <form method='post' action='/logout'><button class='secondary' type='submit'>Log Out</button></form>
              </header>
              {task_section}

              <section class='section-block'>
                <h3>Team Completion Status</h3>
                <ul class='status-list'>{status_rows}</ul>
              </section>
              {settings_section}
              {admin_section}

              {employer_form_section}
              <section class='section-block'>
                <h3>Employers</h3>
                <p class='subtitle'>{html.escape(employer_note)}</p>
                <table class='user-table'>
                  <thead><tr><th>Employer</th><th>Contact</th><th>Email</th><th>Portal Username</th><th>Assigned Task</th></tr></thead>
                  <tbody>{employer_rows}</tbody>
                </table>
              </section>
            </section>
            """
        html_doc = self.html_page("Dashboard", html_body)
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
