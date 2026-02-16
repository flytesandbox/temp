from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
from http import cookies
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "app.db"


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


class TaskTrackerApp:
    def __init__(self, db_path: str | None = None, secret_key: str | None = None):
        self.db_path = db_path or str(DEFAULT_DB)
        self.secret_key = (secret_key or os.environ.get("SECRET_KEY") or "dev-secret-change-me").encode("utf-8")
        self.init_db()

    def init_db(self) -> None:
        db = sqlite3.connect(self.db_path)
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL
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
            """
        )

        db.executemany(
            """
            INSERT OR IGNORE INTO users (username, display_name, password_hash)
            VALUES (?, ?, ?)
            """,
            [
                ("alex", "Alex", hash_password("password123")),
                ("sam", "Sam", hash_password("password123")),
            ],
        )
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
        cookie = cookies.SimpleCookie(environ.get("HTTP_COOKIE", ""))
        session_user = self.read_session_user(cookie)
        form_data = self.parse_form(environ)

        if path.startswith("/static/"):
            return self.serve_static(path, start_response)

        if path == "/":
            if not session_user:
                return self.redirect(start_response, "/login")
            return self.render_dashboard(start_response, session_user, self.consume_flash(cookie))

        if path == "/login" and method == "GET":
            return self.render_login(start_response, self.consume_flash(cookie))

        if path == "/login" and method == "POST":
            return self.handle_login(start_response, form_data)

        if path == "/logout" and method == "POST":
            return self.handle_logout(start_response)

        if path == "/task/complete" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            self.complete_for_user(session_user["id"], 1)
            return self.redirect(start_response, "/", flash=("success", "Task marked complete. Everyone can now see your status."))

        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Not found"]

    def parse_form(self, environ):
        try:
            size = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            size = 0
        body = environ["wsgi.input"].read(size) if size > 0 else b""
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
            SELECT u.id, u.display_name,
                   CASE WHEN tc.id IS NULL THEN 0 ELSE 1 END AS completed
            FROM users u
            LEFT JOIN task_completions tc
                ON tc.user_id = u.id AND tc.task_id = 1
            ORDER BY u.id
            """
        ).fetchall()
        db.close()
        return rows

    def complete_for_user(self, user_id: int, task_id: int):
        db = self.db()
        db.execute(
            "INSERT OR IGNORE INTO task_completions (task_id, user_id) VALUES (?, ?)",
            (task_id, user_id),
        )
        db.commit()
        db.close()

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

    def handle_logout(self, start_response):
        headers = [
            ("Location", "/login"),
            ("Set-Cookie", "session=; Path=/; HttpOnly; Max-Age=0"),
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
        return f"{name}={value}; Path=/; HttpOnly; SameSite=Lax"

    def render_login(self, start_response, flash_message):
        html = self.html_page(
            "Monolith Task Tracker",
            self.flash_html(flash_message)
            + """
            <section class=\"card auth-card\">
              <h1>Monolith Task Tracker</h1>
              <p class=\"subtitle\">Log in as one of the two demo users to validate shared task completion.</p>
              <form method=\"post\" action=\"/login\" class=\"form-grid\">
                <label>Username<input type=\"text\" name=\"username\" placeholder=\"alex or sam\" required /></label>
                <label>Password<input type=\"password\" name=\"password\" placeholder=\"password123\" required /></label>
                <button type=\"submit\">Log In</button>
              </form>
              <div class=\"hint\"><strong>Demo accounts:</strong>
                <ul><li><code>alex</code> / <code>password123</code></li><li><code>sam</code> / <code>password123</code></li></ul>
              </div>
            </section>
            """,
        )
        headers = [("Content-Type", "text/html; charset=utf-8"), ("Set-Cookie", "flash=; Path=/; HttpOnly; Max-Age=0")]
        start_response("200 OK", headers)
        return [html.encode("utf-8")]

    def render_dashboard(self, start_response, user, flash_message):
        rows = self.get_users_with_completion()
        status_rows = "".join(
            f"<li><span>{row['display_name']}</span><span class='pill {'complete' if row['completed'] else 'pending'}'>{'Completed' if row['completed'] else 'Pending'}</span></li>"
            for row in rows
        )
        html = self.html_page(
            "Dashboard",
            self.flash_html(flash_message)
            + f"""
            <section class=\"card\">
              <header class=\"dashboard-header\">
                <div>
                  <h1>Welcome, {user['display_name']}</h1>
                  <p class=\"subtitle\">Track shared progress for deployment validation.</p>
                </div>
                <form method=\"post\" action=\"/logout\"><button class=\"secondary\" type=\"submit\">Log Out</button></form>
              </header>
              <article class=\"task-card\">
                <h2>Deployment Readiness Task</h2>
                <p>Confirm the app works in Codespaces and on Linode.</p>
                <form method=\"post\" action=\"/task/complete\"><button type=\"submit\">Mark My Task Complete</button></form>
              </article>
              <section><h3>Team Completion Status</h3><ul class=\"status-list\">{status_rows}</ul></section>
            </section>
            """,
        )
        headers = [("Content-Type", "text/html; charset=utf-8"), ("Set-Cookie", "flash=; Path=/; HttpOnly; Max-Age=0")]
        start_response("200 OK", headers)
        return [html.encode("utf-8")]

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
        return f"<div class='flash-stack'><div class='flash {category}'>{message}</div></div>"

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
