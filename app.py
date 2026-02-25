from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import sqlite3
from http import cookies
from pathlib import Path
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "app.db"
PROCESS_SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
ALLOWED_THEMES = {"default", "sunset", "midnight", "dawn", "mint", "lavender"}
ALLOWED_DENSITIES = {"comfortable", "compact"}
ALLOWED_UI_MODES = {"LEGACY", "NEW"}
ROLE_LEVELS = {"employer": 0, "broker": 1, "admin": 2, "super_admin": 3}
CAPABILITY_KEYS = {
    "platform.audit_view_all",
    "team.audit_view",
    "team.user_admin",
    "team.staff_provision",
    "employer.user_admin",
}


def application_status_label(ichra_started: int, application_complete: int) -> str:
    if application_complete:
        return "Submitted"
    if ichra_started:
        return "In progress"
    return "Not started"


def db_connect(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

DEV_LOG_ENTRIES = [
    {"pr": 1, "merged_at": "2024-01-05 16:00 UTC", "change": "Built the first monolith task tracker shell.", "result": "Shipped an initial login + task completion flow as a runnable baseline.", "why": "Establish a deployable product foundation before layering in infrastructure and roles."},
    {"pr": 2, "merged_at": "2024-01-06 17:00 UTC", "change": "Added guidance for connecting the repository to Linode.", "result": "Deployment setup became documented and repeatable.", "why": "Reduce onboarding friction and avoid one-off deploy knowledge."},
    {"pr": 3, "merged_at": "2024-01-07 18:00 UTC", "change": "Fixed missing requirements.txt path issues.", "result": "Build/install steps stopped failing during environment setup.", "why": "Unblock runtime provisioning and prevent startup errors."},
    {"pr": 4, "merged_at": "2024-01-08 19:00 UTC", "change": "Repaired nginx service startup configuration.", "result": "Web service boot reliability improved.", "why": "Address infra-level blocker causing the app to stay unavailable."},
    {"pr": 5, "merged_at": "2024-01-09 15:00 UTC", "change": "Fixed another 502 failure on the webpage.", "result": "Traffic routed correctly again.", "why": "Stabilize user access after proxy/runtime mismatch."},
    {"pr": 6, "merged_at": "2024-01-10 16:00 UTC", "change": "Added additional 502 remediation for the monolith app.", "result": "Production routing became more resilient.", "why": "Harden service uptime across deploy attempts."},
    {"pr": 7, "merged_at": "2024-01-11 17:00 UTC", "change": "Completed a final 502-focused fix pass.", "result": "Resolved recurring gateway errors in the live stack.", "why": "Close repeated incident pattern before feature expansion."},
    {"pr": 8, "merged_at": "2024-01-12 18:00 UTC", "change": "Introduced manual trigger support for code push workflows.", "result": "Operators could run CI/CD on demand.", "why": "Improve release control for urgent fixes and validation."},
    {"pr": 9, "merged_at": "2024-01-13 19:00 UTC", "change": "Extended/refined manual trigger behavior in the pipeline.", "result": "Workflow controls became easier to execute consistently.", "why": "Make deployment operations safer and more predictable."},
    {"pr": 10, "merged_at": "2024-01-14 15:00 UTC", "change": "Created CI/CD workflow for Linode deployment.", "result": "Automated deploy path replaced manual-only steps.", "why": "Speed delivery and reduce drift between environments."},
    {"pr": 11, "merged_at": "2024-01-15 16:00 UTC", "change": "Updated the login screen experience.", "result": "Authentication entry point became clearer for users.", "why": "Improve first-touch usability in the app."},
    {"pr": 12, "merged_at": "2024-01-16 17:00 UTC", "change": "Added a GitHub Actions CI/CD pipeline.", "result": "Build and deployment checks became standardized in repo automation.", "why": "Increase confidence in merges and deployment repeatability."},
    {"pr": 13, "merged_at": "2024-01-17 18:00 UTC", "change": "Debugged production login issues.", "result": "Authentication reliability improved in deployed environments.", "why": "Solve real-user login blockers before scaling usage."},
    {"pr": 14, "merged_at": "2024-01-18 19:00 UTC", "change": "Fixed login flows and password management behavior.", "result": "Session/auth handling became more dependable.", "why": "Eliminate user lockout and inconsistent credential behavior."},
    {"pr": 15, "merged_at": "2024-01-19 15:00 UTC", "change": "Changed seeded user passwords to password123.", "result": "Demo/test account expectations were aligned.", "why": "Provide a consistent default during stabilization."},
    {"pr": 16, "merged_at": "2024-01-20 16:00 UTC", "change": "Resolved login loop caused by session key issues.", "result": "Successful login persisted correctly across redirects.", "why": "Fix a critical auth/session regression."},
    {"pr": 17, "merged_at": "2024-01-21 17:00 UTC", "change": "Fixed multi-cookie parsing for session validation.", "result": "Session detection became accurate with richer cookie headers.", "why": "Handle real browser cookie behavior safely."},
    {"pr": 18, "merged_at": "2024-01-22 18:00 UTC", "change": "Cleaned code and fixed task completion form parsing scope.", "result": "Task completion no longer stalled unexpectedly.", "why": "Address correctness and maintainability together."},
    {"pr": 19, "merged_at": "2024-01-23 19:00 UTC", "change": "Added user settings and a super admin role with stronger dashboard styling.", "result": "System gained administrative user lifecycle controls.", "why": "Support role-based administration as product complexity increased."},
    {"pr": 20, "merged_at": "2024-01-24 15:00 UTC", "change": "Introduced employer onboarding workflow with role-scoped visibility.", "result": "Employer account creation and scoped views were available.", "why": "Expand from internal task tracking to onboarding operations."},
    {"pr": 21, "merged_at": "2024-01-25 16:00 UTC", "change": "Reverted PR #20.", "result": "Prior behavior was restored.", "why": "Rollback risk while iterating toward a safer onboarding implementation."},
    {"pr": 22, "merged_at": "2024-01-26 17:00 UTC", "change": "Reintroduced employer onboarding while preserving existing dashboard features.", "result": "Onboarding returned without regressing prior functionality.", "why": "Deliver onboarding needs with lower disruption."},
    {"pr": 23, "merged_at": "2024-01-27 18:00 UTC", "change": "Added navigation-driven dashboard and rebuilt a full ICHRA application form.", "result": "UI became tabbed and workflow-oriented.", "why": "Improve information architecture as feature surface grew."},
    {"pr": 24, "merged_at": "2024-01-28 19:00 UTC", "change": "Added broker and employer role-specific experiences.", "result": "Role-tailored dashboards and permissions became first class.", "why": "Match product behavior to real participant responsibilities."},
    {"pr": 25, "merged_at": "2024-01-29 15:00 UTC", "change": "Added employer settings editing, DB-backed login hints, and admin activity logs.", "result": "Operational visibility and account support tooling improved.", "why": "Increase admin traceability and self-service controls."},
    {"pr": 26, "merged_at": "2024-01-30 16:00 UTC", "change": "Improved employer settings flow, log filter UX, and password policy.", "result": "Settings and audit workflows became easier and safer.", "why": "Polish day-to-day admin workflows after initial rollout."},
    {"pr": 27, "merged_at": "2024-01-31 17:00 UTC", "change": "Split employer setup from ICHRA app and added notifications.", "result": "Workflow boundaries became clearer and users gained update visibility.", "why": "Reduce confusion and proactively surface important events."},
    {"pr": 28, "merged_at": "2024-02-01 18:00 UTC", "change": "Adjusted setup toggle flow and redesigned employer settings dashboard.", "result": "Settings UI changed significantly.", "why": "Improve responsiveness and clarity in employer configuration."},
    {"pr": 29, "merged_at": "2024-02-02 19:00 UTC", "change": "Reverted PR #28.", "result": "Dashboard/settings behavior returned to known-stable implementation.", "why": "Rollback after issues with the redesign/toggle behavior."},
    {"pr": 30, "merged_at": "2024-02-03 15:00 UTC", "change": "Fixed employer app toggles and delivered an updated settings dashboard layout.", "result": "Redesign landed with corrected behavior.", "why": "Reapply UX improvements without the regressions that triggered the prior revert."},
    {"pr": 31, "merged_at": "2024-02-04 16:00 UTC", "change": "Made dashboard headers sticky with a scroll-condensed state and added a PR checklist reminder for Dev Log updates.", "result": "Long pages now keep context visible while scrolling and the merge process has an explicit Dev Log checkpoint.", "why": "Improve usability across long forms/lists and prevent Development Log drift from missed entries."},
    {"pr": 32, "merged_at": "2024-02-05 17:00 UTC", "change": "Extended Forms and Applications into every role workspace with permission-aware tooling.", "result": "All users can access the ecosystem workspace while role-specific actions are clearly surfaced in the UI.", "why": "Ensure functional completeness of forms/application flows without exposing unsafe actions to restricted user types."},
    {"pr": 33, "merged_at": "2026-02-23 16:33 UTC", "change": "Backfilled Development Log timestamps for all PR entries and enforced complete PR coverage in tests.", "result": "Dev Log now shows a date/time stamp for every PR and includes this latest merge entry.", "why": "Create an auditable, consistently updated release history visible directly in the application."},
    {"pr": 34, "merged_at": "2026-02-19 16:53 UTC", "change": "Fixed UI text wrapping and resizing behavior across dashboards.", "result": "Responsive layouts now preserve readability instead of clipping long text.", "why": "Prevent usability regressions on narrow viewports and dense data screens."},
    {"pr": 35, "merged_at": "2026-02-19 17:09 UTC", "change": "Resolved server errors when updating usernames in account management.", "result": "User profile edits save reliably without triggering runtime failures.", "why": "Stabilize core admin maintenance workflows."},
    {"pr": 36, "merged_at": "2026-02-19 18:44 UTC", "change": "Fixed ICHRA application loading issues in the forms workspace.", "result": "Application records open consistently for authorized users.", "why": "Remove a blocker in the primary onboarding funnel."},
    {"pr": 37, "merged_at": "2026-02-19 19:09 UTC", "change": "Updated admin operations dashboard features and controls.", "result": "Administrative workflows gained expanded operational tooling.", "why": "Improve throughput for high-volume account and task management."},
    {"pr": 38, "merged_at": "2026-02-19 19:12 UTC", "change": "Reverted PR #37 admin operations dashboard updates.", "result": "System behavior returned to the previously stable admin dashboard baseline.", "why": "Rollback introduced risk while preparing a safer follow-up implementation."},
    {"pr": 39, "merged_at": "2026-02-19 19:32 UTC", "change": "Delivered an urgent fix for a production outage path.", "result": "Service availability and critical runtime flows were restored.", "why": "Minimize downtime impact and stabilize user access."},
    {"pr": 40, "merged_at": "2026-02-19 19:39 UTC", "change": "Added sub-navigation menus for major dashboard sections.", "result": "Users can navigate dense feature areas with clearer in-page structure.", "why": "Reduce navigation friction as product complexity increased."},
    {"pr": 41, "merged_at": "2026-02-19 19:55 UTC", "change": "Removed deactivated users from selection menus and action lists.", "result": "Operational pickers now emphasize active accounts only.", "why": "Prevent accidental assignment and reduce visual noise in routine workflows."},
    {"pr": 42, "merged_at": "2026-02-19 20:08 UTC", "change": "Restored deactivated-user visibility in account management views.", "result": "Administrators regained access to audit and reactivation controls.", "why": "Preserve lifecycle governance while keeping day-to-day menus clean."},
    {"pr": 43, "merged_at": "2026-02-19 20:20 UTC", "change": "Made the primary header section sticky and collapsible.", "result": "Users keep key context visible while reclaiming vertical space on scroll.", "why": "Improve task focus on long forms and data-heavy pages."},
    {"pr": 44, "merged_at": "2026-02-19 20:34 UTC", "change": "Revised user-to-entity mapping and delivered supporting UI updates.", "result": "Ownership and relationship displays became more accurate across views.", "why": "Align interface behavior with underlying data responsibility rules."},
    {"pr": 45, "merged_at": "2026-02-19 20:43 UTC", "change": "Reviewed and upgraded the applications feature system.", "result": "Application workflows became more coherent and maintainable.", "why": "Prepare the module for broader cross-role usage."},
    {"pr": 46, "merged_at": "2026-02-19 21:03 UTC", "change": "Revised the ICHRA setup application process.", "result": "Setup steps and field handling are clearer for operators and employers.", "why": "Lower completion friction in a critical onboarding sequence."},
    {"pr": 47, "merged_at": "2026-02-19 21:51 UTC", "change": "Reverted to the prior applications UI implementation.", "result": "Users returned to a familiar and stable interface pattern.", "why": "Rollback after identifying issues in the revised experience."},
    {"pr": 48, "merged_at": "2026-02-19 22:07 UTC", "change": "Relabeled Setup Applications to Forms and Applications.", "result": "Navigation and page copy now match the broader workspace scope.", "why": "Improve terminology clarity for mixed-role users."},
    {"pr": 49, "merged_at": "2026-02-19 22:21 UTC", "change": "Integrated the Forms and Applications ecosystem across workflows.", "result": "Cross-feature handoffs are unified through a single workspace model.", "why": "Reduce duplication and keep form/application operations consistent."},
    {"pr": 50, "merged_at": "2026-02-19 22:42 UTC", "change": "Removed a separate Applications tab and revamped ICHRA setup surfaces.", "result": "Workspace navigation is simplified and setup actions are easier to find.", "why": "Streamline wayfinding and reduce overlapping entry points."},
    {"pr": 51, "merged_at": "2026-02-19 22:55 UTC", "change": "Transformed the team completion status screen experience.", "result": "Team progress visibility improved with clearer status presentation.", "why": "Help managers identify blockers and completion trends faster."},
    {"pr": 52, "merged_at": "2026-02-19 23:25 UTC", "change": "Implemented broader team visibility and administration controls.", "result": "Role-scoped team management capabilities expanded across the app.", "why": "Support multi-team operations with stronger governance controls."},
    {"pr": 53, "merged_at": "2026-02-23 09:23 UTC", "change": "Completed a full UI/UX redesign based on the approved wireframe.", "result": "Application experience now follows a cohesive app-shell and card-first design system.", "why": "Modernize usability and visual consistency across all workflows."},
    {"pr": 54, "merged_at": "2026-02-23 10:29 UTC", "change": "Reverted navigation menu UI changes from the redesign pass.", "result": "Navigation returned to the prior stable behavior while preserving other improvements.", "why": "Address regressions introduced by the menu implementation."},
    {"pr": 55, "merged_at": "2026-02-23 10:47 UTC", "change": "Updated Development Log process expectations for every PR.", "result": "Release history policy became explicit in merge-time workflow.", "why": "Prevent missing PR entries and maintain audit completeness."},
    {"pr": 56, "merged_at": "2026-02-23 11:02 UTC", "change": "Restricted broker user creation and added team broker admin controls.", "result": "Broker provisioning now follows role-safe rules with team-level governance.", "why": "Tighten permissions and prevent unauthorized account escalation."},
    {"pr": 57, "merged_at": "2026-02-23 11:04 UTC", "change": "Reverted PR #54 navigation rollback changes.", "result": "Navigation behavior returned to the redesigned implementation after revert validation.", "why": "Reprocess the navigation decision path to restore intended UX direction."},
    {"pr": 58, "merged_at": "2026-02-24 17:20 UTC", "change": "Introduced capability-scoped access payloads, tightened broker provisioning, and added team-scoped audit visibility.", "result": "Permission checks are clearer, UI can pre-render authorized actions, and operational auditing is delegated safely.", "why": "Scale the permission model with explicit capabilities and stronger tenant-safe guardrails."},
    {"pr": 69, "merged_at": "2026-02-25 02:52 UTC", "change": "Merged PR #69: Auto-record in-app Development Log entries for merged PRs", "result": "Development Log entry added automatically by CI.", "why": "Guarantee every merged PR is recorded in the in-app Dev Log."},
    {"pr": 70, "merged_at": "2026-02-25 02:58 UTC", "change": "Merged PR #70: fix: stabilize CI dev-log test for non-sequential PR numbers", "result": "Development Log entry added automatically by CI.", "why": "Guarantee every merged PR is recorded in the in-app Dev Log."},
    {"pr": 71, "merged_at": "2026-02-25 03:06 UTC", "change": "Merged PR #71: Revamp login conversion UX and Team Command Center; always-show Settings", "result": "Development Log entry added automatically by CI.", "why": "Guarantee every merged PR is recorded in the in-app Dev Log."},
    {"pr": 73, "merged_at": "2026-02-25 03:16 UTC", "change": "Merged PR #73: Add NEW_UI mode with Super Admin toggle, persisted , and initial NEW_UI dashboard shell", "result": "Development Log entry added automatically by CI.", "why": "Guarantee every merged PR is recorded in the in-app Dev Log."},
    {"pr": 74, "merged_at": "2026-02-25 13:23 UTC", "change": "Merged PR #74: Refine login and team panels for a more compact visual hierarchy", "result": "Development Log entry added automatically by CI.", "why": "Guarantee every merged PR is recorded in the in-app Dev Log."},
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
                is_team_admin INTEGER NOT NULL DEFAULT 0,
                is_team_super_admin INTEGER NOT NULL DEFAULT 0,
                theme TEXT NOT NULL DEFAULT 'default',
                density TEXT NOT NULL DEFAULT 'comfortable',
                ui_mode TEXT NOT NULL DEFAULT 'LEGACY',
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

            CREATE TABLE IF NOT EXISTS ichra_applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employer_id INTEGER NOT NULL UNIQUE,
                desired_start_date TEXT NOT NULL DEFAULT '',
                service_type TEXT NOT NULL DEFAULT '',
                primary_first_name TEXT NOT NULL DEFAULT '',
                primary_last_name TEXT NOT NULL DEFAULT '',
                primary_email TEXT NOT NULL DEFAULT '',
                primary_phone TEXT NOT NULL DEFAULT '',
                legal_name TEXT NOT NULL DEFAULT '',
                nature_of_business TEXT NOT NULL DEFAULT '',
                total_employee_count TEXT NOT NULL DEFAULT '',
                physical_state TEXT NOT NULL DEFAULT '',
                reimbursement_option TEXT NOT NULL DEFAULT '',
                employee_class_assistance TEXT NOT NULL DEFAULT '',
                planned_contribution TEXT NOT NULL DEFAULT '',
                claim_option TEXT NOT NULL DEFAULT '',
                agent_support TEXT NOT NULL DEFAULT '',
                artifact_status TEXT NOT NULL DEFAULT 'draft',
                access_token_status TEXT NOT NULL DEFAULT 'active',
                last_saved_by_user_id INTEGER,
                token_renewed_by_user_id INTEGER,
                token_renewed_at TEXT,
                submitted_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (employer_id) REFERENCES employers(id)
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

            CREATE TABLE IF NOT EXISTS team_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                assigned_to_user_id INTEGER NOT NULL,
                assigned_by_user_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT
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
        if "ui_mode" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN ui_mode TEXT NOT NULL DEFAULT 'LEGACY'")
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
        if "user_seed" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN user_seed TEXT")
        if "theme_variant" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN theme_variant TEXT")
        if "home_layout" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN home_layout TEXT")
        if "vibe_pack" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN vibe_pack TEXT")
        if "avatar_symbol" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN avatar_symbol TEXT")
        if "onboarding_complete" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN onboarding_complete INTEGER NOT NULL DEFAULT 0")
        if "shuffle_enabled" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN shuffle_enabled INTEGER NOT NULL DEFAULT 0")
        if "is_team_admin" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN is_team_admin INTEGER NOT NULL DEFAULT 0")
        if "is_team_super_admin" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN is_team_super_admin INTEGER NOT NULL DEFAULT 0")
        db.execute("UPDATE users SET is_team_admin = 0 WHERE role != 'broker'")
        db.execute("UPDATE users SET is_team_super_admin = 0 WHERE role NOT IN ('admin', 'broker')")
        db.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_team_admin_per_team
            ON users(team_id)
            WHERE role = 'broker' AND is_team_admin = 1 AND team_id IS NOT NULL AND is_active = 1
            """
        )
        db.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_team_super_admin_per_team
            ON users(team_id)
            WHERE is_team_super_admin = 1 AND team_id IS NOT NULL AND is_active = 1 AND role IN ('admin', 'broker')
            """
        )

        team_task_columns = {row[1] for row in db.execute("PRAGMA table_info(team_tasks)").fetchall()}
        if team_task_columns and "status" not in team_task_columns:
            db.execute("ALTER TABLE team_tasks ADD COLUMN status TEXT NOT NULL DEFAULT 'open'")
        if team_task_columns and "completed_at" not in team_task_columns:
            db.execute("ALTER TABLE team_tasks ADD COLUMN completed_at TEXT")

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
        db.execute("UPDATE users SET onboarding_complete = 1 WHERE username IN ('alex','sam','admin')")
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
        team_ids = [row[0] for row in db.execute("SELECT id FROM teams").fetchall()]
        for team_id in team_ids:
            team_super_admin = db.execute(
                """
                SELECT id
                FROM users
                WHERE team_id = ? AND role IN ('admin', 'broker') AND is_active = 1
                ORDER BY CASE role WHEN 'admin' THEN 0 ELSE 1 END, id
                LIMIT 1
                """,
                (team_id,),
            ).fetchone()
            if team_super_admin:
                db.execute(
                    "UPDATE users SET is_team_super_admin = CASE WHEN id = ? THEN 1 ELSE 0 END WHERE team_id = ? AND role IN ('admin', 'broker')",
                    (team_super_admin["id"], team_id),
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

        ichra_columns = {row[1] for row in db.execute("PRAGMA table_info(ichra_applications)").fetchall()}
        if not ichra_columns:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS ichra_applications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employer_id INTEGER NOT NULL UNIQUE,
                    desired_start_date TEXT NOT NULL DEFAULT '',
                    service_type TEXT NOT NULL DEFAULT '',
                    primary_first_name TEXT NOT NULL DEFAULT '',
                    primary_last_name TEXT NOT NULL DEFAULT '',
                    primary_email TEXT NOT NULL DEFAULT '',
                    primary_phone TEXT NOT NULL DEFAULT '',
                    legal_name TEXT NOT NULL DEFAULT '',
                    nature_of_business TEXT NOT NULL DEFAULT '',
                    total_employee_count TEXT NOT NULL DEFAULT '',
                    physical_state TEXT NOT NULL DEFAULT '',
                    reimbursement_option TEXT NOT NULL DEFAULT '',
                    employee_class_assistance TEXT NOT NULL DEFAULT '',
                    planned_contribution TEXT NOT NULL DEFAULT '',
                    claim_option TEXT NOT NULL DEFAULT '',
                    agent_support TEXT NOT NULL DEFAULT '',
                    artifact_status TEXT NOT NULL DEFAULT 'draft',
                    access_token_status TEXT NOT NULL DEFAULT 'active',
                    last_saved_by_user_id INTEGER,
                    token_renewed_by_user_id INTEGER,
                    token_renewed_at TEXT,
                    submitted_at TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (employer_id) REFERENCES employers(id)
                )
                """
            )
        if "access_token_status" not in ichra_columns:
            db.execute("ALTER TABLE ichra_applications ADD COLUMN access_token_status TEXT NOT NULL DEFAULT 'active'")
        if "token_renewed_by_user_id" not in ichra_columns:
            db.execute("ALTER TABLE ichra_applications ADD COLUMN token_renewed_by_user_id INTEGER")
        if "token_renewed_at" not in ichra_columns:
            db.execute("ALTER TABLE ichra_applications ADD COLUMN token_renewed_at TEXT")
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
            active_view = query.get("view", ["dashboard"])[0]
            flash_message = self.consume_flash(cookie)
            return self.render_ui_mode_router(start_response, session_user, flash_message, active_view, query)

        if path == "/me/access" and method == "GET":
            if not session_user:
                start_response("401 Unauthorized", [("Content-Type", "application/json")])
                return [json.dumps({"error": "Authentication required."}).encode("utf-8")]
            payload = self.build_effective_access_payload(session_user)
            start_response("200 OK", [("Content-Type", "application/json")])
            return [json.dumps(payload).encode("utf-8")]

        if path == "/login" and method == "GET":
            return self.render_login(start_response, self.consume_flash(cookie))

        if path == "/login" and method == "POST":
            return self.handle_login(start_response, self.parse_form(environ))

        if path == "/signup" and method == "POST":
            return self.handle_public_employer_signup(start_response, self.parse_form(environ))

        if path == "/signup/broker" and method == "POST":
            return self.handle_public_broker_signup(start_response, self.parse_form(environ))

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
            return self.handle_profile_settings(start_response, session_user, self.parse_form(environ))

        if path == "/settings/style" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            return self.handle_style_settings(start_response, session_user, self.parse_form(environ))

        if path == "/onboarding/complete" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            return self.handle_onboarding_complete(start_response, session_user, self.parse_form(environ))

        if path == "/settings/preferences" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            return self.handle_preferences_settings(start_response, session_user, self.parse_form(environ))

        if path == "/settings/ui-mode" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            return self.handle_ui_mode_settings(start_response, session_user, self.parse_form(environ))

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
            self.start_employer_ichra(session_user["id"])
            self.log_action(session_user["id"], "ichra_started", "employer", session_user["id"], session_user["username"], "Employer started ICHRA setup")
            return self.redirect(start_response, "/?view=application", flash=("success", "ICHRA setup application opened. Complete and submit the application when ready."))

        if path == "/applications/ichra/save" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            return self.handle_save_ichra_application(start_response, session_user, self.parse_form(environ))

        if path == "/applications/ichra/renew" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            return self.handle_renew_ichra_token(start_response, session_user, self.parse_form(environ))

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

        if path == "/teams/assign-broker-admin" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] != "super_admin":
                return self.redirect(start_response, "/?view=team", flash=("error", "Only super admins can assign team broker admins."))
            return self.handle_assign_broker_admin(start_response, session_user, self.parse_form(environ))

        if path == "/teams/assign-team-super-admin" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] != "super_admin":
                return self.redirect(start_response, "/?view=team", flash=("error", "Only super admins can assign team super admins."))
            return self.handle_assign_team_super_admin(start_response, session_user, self.parse_form(environ))

        if path == "/team-tasks/create" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] == "employer":
                return self.redirect(start_response, "/?view=dashboard", flash=("error", "Employer accounts are read-only."))
            return self.handle_create_team_task(start_response, session_user, self.parse_form(environ))

        if path == "/team-tasks/complete" and method == "POST":
            if not session_user:
                return self.redirect(start_response, "/login")
            if session_user["role"] == "employer":
                return self.redirect(start_response, "/?view=dashboard", flash=("error", "Employer accounts are read-only."))
            return self.handle_complete_team_task(start_response, session_user, self.parse_form(environ))

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

    def capability_flags_for_user(self, user):
        flags = {key: False for key in CAPABILITY_KEYS}
        if not user or not user["is_active"]:
            return flags
        role = user["role"]
        if role == "super_admin":
            for key in flags:
                flags[key] = True
            return flags
        if role in {"admin", "broker"} and user["is_team_super_admin"] == 1:
            flags["team.user_admin"] = True
            flags["team.staff_provision"] = True
            flags["team.audit_view"] = True
            flags["employer.user_admin"] = True
            return flags
        if role == "admin":
            flags["team.user_admin"] = True
            flags["team.staff_provision"] = True
            flags["team.audit_view"] = True
            flags["employer.user_admin"] = True
        elif role == "broker":
            flags["team.audit_view"] = True
            flags["employer.user_admin"] = True
        elif role == "employer":
            flags["employer.user_admin"] = True
        return flags

    def build_effective_access_payload(self, user):
        employers = self.list_visible_employers(user)
        team_memberships = []
        if user["team_id"] is not None:
            team_memberships.append({
                "team_id": user["team_id"],
                "role": user["role"],
                "is_team_super_admin": bool(user["is_team_super_admin"]),
            })
        assigned_employer_ids = [row["id"] for row in employers if user["role"] == "broker"]
        employer_membership_ids = [row["id"] for row in employers if user["role"] == "employer"]
        return {
            "user_id": user["id"],
            "role": user["role"],
            "capabilities": self.capability_flags_for_user(user),
            "team_memberships": team_memberships,
            "employer_memberships": employer_membership_ids,
            "assigned_employer_ids": assigned_employer_ids,
        }

    def get_users_with_completion(self, session_user=None, include_employers: bool = False):
        db = self.db()
        rows = db.execute(
            """
            SELECT u.id, u.username, u.display_name, u.role, u.created_by_user_id, u.team_id,
                   u.is_active,
                   e.legal_name AS employer_legal_name,
                   CASE WHEN tc.id IS NULL THEN 0 ELSE 1 END AS completed
            FROM users u
            LEFT JOIN employers e ON e.linked_user_id = u.id
            LEFT JOIN task_completions tc
                ON tc.user_id = u.id AND tc.task_id = 1
            WHERE u.is_active = 1
            ORDER BY u.id
            """
        ).fetchall()
        db.close()
        if not include_employers:
            rows = [row for row in rows if row["role"] != "employer"]
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
            SELECT id, username, role, is_active, team_id, is_team_admin, is_team_super_admin
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

        team_id = filters.get("team_id", [""])[0]
        if team_id:
            where.append("(actor.team_id = ? OR l.entity_type = 'team' AND l.entity_id = ?)")
            params.extend([team_id, team_id])

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

    def list_active_users_for_team(self, team_id: int):
        db = self.db()
        rows = db.execute(
            """
            SELECT id, username, display_name, role
            FROM users
            WHERE team_id = ? AND is_active = 1
            ORDER BY CASE role WHEN 'super_admin' THEN 0 WHEN 'admin' THEN 1 WHEN 'broker' THEN 2 ELSE 3 END, username
            """,
            (team_id,),
        ).fetchall()
        db.close()
        return rows

    def list_assignable_admins(self):
        db = self.db()
        rows = db.execute("SELECT id, username, team_id FROM users WHERE role = 'admin' AND is_active = 1 ORDER BY username").fetchall()
        db.close()
        return rows

    def list_brokers_for_team(self, team_id: int):
        db = self.db()
        rows = db.execute(
            "SELECT id, username, is_team_admin FROM users WHERE role = 'broker' AND team_id = ? AND is_active = 1 ORDER BY username",
            (team_id,),
        ).fetchall()
        db.close()
        return rows

    def assign_team_admin_broker(self, broker_user_id: int, team_id: int):
        db = self.db()
        broker = db.execute(
            "SELECT id FROM users WHERE id = ? AND role = 'broker' AND team_id = ? AND is_active = 1",
            (broker_user_id, team_id),
        ).fetchone()
        if not broker:
            db.close()
            raise ValueError("Invalid broker or team.")
        db.execute("UPDATE users SET is_team_admin = 0 WHERE role = 'broker' AND team_id = ?", (team_id,))
        db.execute("UPDATE users SET is_team_admin = 1 WHERE id = ?", (broker_user_id,))
        db.commit()
        db.close()

    def list_assignable_users(self):
        db = self.db()
        rows = db.execute(
            "SELECT id, username, role, team_id, is_team_super_admin FROM users WHERE role != 'super_admin' AND is_active = 1 ORDER BY role, username"
        ).fetchall()
        db.close()
        return rows

    def ensure_team_super_admin_for_team(self, team_id: int | None):
        if team_id is None:
            return
        db = self.db()
        current = db.execute(
            "SELECT id FROM users WHERE team_id = ? AND is_team_super_admin = 1 AND is_active = 1 AND role IN ('admin', 'broker')",
            (team_id,),
        ).fetchone()
        if current:
            db.close()
            return
        fallback = db.execute(
            """
            SELECT id FROM users
            WHERE team_id = ? AND is_active = 1 AND role IN ('admin', 'broker')
            ORDER BY CASE role WHEN 'admin' THEN 0 ELSE 1 END, id
            LIMIT 1
            """,
            (team_id,),
        ).fetchone()
        if fallback:
            db.execute("UPDATE users SET is_team_super_admin = CASE WHEN id = ? THEN 1 ELSE 0 END WHERE team_id = ? AND role IN ('admin', 'broker')", (fallback["id"], team_id))
            db.commit()
        db.close()

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
        old_team = db.execute("SELECT team_id FROM users WHERE id = ?", (admin_user_id,)).fetchone()
        old_team_id = old_team["team_id"] if old_team else None
        db.execute("UPDATE users SET team_id = ?, is_team_super_admin = 0 WHERE id = ?", (team_id, admin_user_id))
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
        self.ensure_team_super_admin_for_team(old_team_id)
        self.ensure_team_super_admin_for_team(team_id)

    def assign_user_to_team(self, user_id: int, team_id: int):
        db = self.db()
        target = db.execute("SELECT id, role FROM users WHERE id = ? AND role != 'super_admin' AND is_active = 1", (user_id,)).fetchone()
        team = db.execute("SELECT id FROM teams WHERE id = ?", (team_id,)).fetchone()
        if not target or not team:
            db.close()
            raise ValueError("Invalid user or team.")

        old_team = db.execute("SELECT team_id FROM users WHERE id = ?", (user_id,)).fetchone()
        old_team_id = old_team["team_id"] if old_team else None
        db.execute("UPDATE users SET team_id = ?, is_team_super_admin = CASE WHEN role IN ('admin', 'broker') THEN 0 ELSE is_team_super_admin END WHERE id = ?", (team_id, user_id))
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
        self.ensure_team_super_admin_for_team(old_team_id)
        self.ensure_team_super_admin_for_team(team_id)

    def list_visible_employers(self, session_user):
        db = self.db()
        if session_user["role"] == "super_admin":
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username,
                       COALESCE(u.is_active, 0) AS portal_user_is_active,
                       broker.username AS broker_username
                FROM employers e
                LEFT JOIN users u ON u.id = e.linked_user_id
                LEFT JOIN users broker ON broker.id = e.broker_user_id AND broker.is_active = 1
                ORDER BY e.created_at DESC
                """
            ).fetchall()
        elif session_user["role"] == "admin":
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username,
                       COALESCE(u.is_active, 0) AS portal_user_is_active,
                       broker.username AS broker_username
                FROM employers e
                LEFT JOIN users u ON u.id = e.linked_user_id
                LEFT JOIN users broker ON broker.id = e.broker_user_id
                LEFT JOIN users owner_admin ON owner_admin.id = e.primary_user_id
                LEFT JOIN users employer_user ON employer_user.id = e.linked_user_id
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
        elif session_user["role"] == "broker":
            if session_user["is_team_super_admin"] == 1:
                rows = db.execute(
                    """
                    SELECT e.*, u.username AS portal_username,
                           COALESCE(u.is_active, 0) AS portal_user_is_active,
                           broker.username AS broker_username
                    FROM employers e
                    LEFT JOIN users u ON u.id = e.linked_user_id
                    LEFT JOIN users broker ON broker.id = e.broker_user_id
                    LEFT JOIN users owner_admin ON owner_admin.id = e.primary_user_id
                    LEFT JOIN users employer_user ON employer_user.id = e.linked_user_id
                    WHERE (
                        e.broker_user_id = ?
                        OR (owner_admin.team_id IS NOT NULL AND owner_admin.team_id = ?)
                        OR (broker.team_id IS NOT NULL AND broker.team_id = ?)
                        OR (employer_user.team_id IS NOT NULL AND employer_user.team_id = ?)
                    )
                    ORDER BY e.created_at DESC
                    """,
                    (session_user["id"], session_user["team_id"], session_user["team_id"], session_user["team_id"]),
                ).fetchall()
            else:
                rows = db.execute(
                    """
                    SELECT e.*, u.username AS portal_username,
                           COALESCE(u.is_active, 0) AS portal_user_is_active,
                           broker.username AS broker_username
                    FROM employers e
                    LEFT JOIN users u ON u.id = e.linked_user_id
                    LEFT JOIN users broker ON broker.id = e.broker_user_id AND broker.is_active = 1
                    WHERE e.broker_user_id = ?
                    ORDER BY e.created_at DESC
                    """,
                    (session_user["id"],),
                ).fetchall()
        elif session_user["role"] == "employer":
            rows = db.execute(
                """
                SELECT e.*, u.username AS portal_username,
                       COALESCE(u.is_active, 0) AS portal_user_is_active,
                       broker.username AS broker_username
                FROM employers e
                LEFT JOIN users u ON u.id = e.linked_user_id
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
        capabilities = self.capability_flags_for_user(session_user)
        if session_user["role"] == "super_admin":
            return target_user["role"] != "super_admin"
        if capabilities["team.user_admin"]:
            return target_user["team_id"] == session_user["team_id"] and target_user["role"] in {"admin", "broker", "employer"}
        if session_user["role"] == "broker":
            return target_user["team_id"] == session_user["team_id"] and target_user["role"] == "employer"
        if session_user["role"] == "admin":
            return target_user["team_id"] == session_user["team_id"] and target_user["role"] in {"admin", "broker", "employer"}
        return target_user["id"] == session_user["id"]

    def is_team_super_admin_user(self, user):
        return bool(user) and user["role"] in {"admin", "broker"} and user["is_team_super_admin"] == 1 and user["is_active"] == 1

    def assign_team_super_admin(self, user_id: int, team_id: int):
        db = self.db()
        target = db.execute(
            "SELECT id FROM users WHERE id = ? AND role IN ('admin', 'broker') AND team_id = ? AND is_active = 1",
            (user_id, team_id),
        ).fetchone()
        if not target:
            db.close()
            raise ValueError("Invalid team super admin assignment.")
        db.execute(
            "UPDATE users SET is_team_super_admin = 0 WHERE role IN ('admin', 'broker') AND team_id = ?",
            (team_id,),
        )
        db.execute("UPDATE users SET is_team_super_admin = 1 WHERE id = ?", (user_id,))
        db.commit()
        db.close()


    def list_team_members(self, team_id: int):
        if not team_id:
            return []
        db = self.db()
        rows = db.execute(
            """
            SELECT id, username, display_name, role
            FROM users
            WHERE team_id = ? AND is_active = 1 AND role != 'employer'
            ORDER BY CASE role WHEN 'super_admin' THEN 0 WHEN 'admin' THEN 1 WHEN 'broker' THEN 2 ELSE 3 END, username
            """,
            (team_id,),
        ).fetchall()
        db.close()
        return rows

    def list_team_tasks(self, team_id: int):
        if not team_id:
            return []
        db = self.db()
        rows = db.execute(
            """
            SELECT tt.id, tt.title, tt.details, tt.status, tt.created_at, tt.completed_at,
                   assignee.username AS assigned_to_username,
                   assignee.display_name AS assigned_to_display_name,
                   assignee.role AS assigned_to_role,
                   assigner.username AS assigned_by_username,
                   assigner.display_name AS assigned_by_display_name
            FROM team_tasks tt
            JOIN users assignee ON assignee.id = tt.assigned_to_user_id
            JOIN users assigner ON assigner.id = tt.assigned_by_user_id
            WHERE tt.team_id = ?
            ORDER BY
                CASE tt.status WHEN 'open' THEN 0 ELSE 1 END,
                tt.created_at DESC,
                tt.id DESC
            """,
            (team_id,),
        ).fetchall()
        db.close()
        return rows

    def list_visible_team_tasks(self, session_user):
        if session_user["role"] == "super_admin":
            db = self.db()
            rows = db.execute(
                """
                SELECT tt.id, tt.title, tt.details, tt.status, tt.created_at, tt.completed_at,
                       assignee.username AS assigned_to_username,
                       assignee.display_name AS assigned_to_display_name,
                       assignee.role AS assigned_to_role,
                       assigner.username AS assigned_by_username,
                       assigner.display_name AS assigned_by_display_name
                FROM team_tasks tt
                JOIN users assignee ON assignee.id = tt.assigned_to_user_id
                JOIN users assigner ON assigner.id = tt.assigned_by_user_id
                ORDER BY
                    CASE tt.status WHEN 'open' THEN 0 ELSE 1 END,
                    tt.created_at DESC,
                    tt.id DESC
                """
            ).fetchall()
            db.close()
            return rows
        if session_user["team_id"] is None:
            return []
        return self.list_team_tasks(session_user["team_id"])

    def create_team_task(self, team_id: int, title: str, details: str, assigned_to_user_id: int, assigned_by_user_id: int):
        db = self.db()
        db.execute(
            """
            INSERT INTO team_tasks (team_id, title, details, assigned_to_user_id, assigned_by_user_id, status)
            VALUES (?, ?, ?, ?, ?, 'open')
            """,
            (team_id, title, details, assigned_to_user_id, assigned_by_user_id),
        )
        db.commit()
        db.close()

    def complete_team_task(self, task_id: int, user_id: int):
        db = self.db()
        row = db.execute(
            """
            SELECT tt.id, tt.team_id, tt.status, tt.assigned_to_user_id, u.team_id AS user_team_id
            FROM team_tasks tt
            JOIN users u ON u.id = ?
            WHERE tt.id = ?
            """,
            (user_id, task_id),
        ).fetchone()
        if not row:
            db.close()
            return None, "Task not found."
        if row["team_id"] != row["user_team_id"]:
            db.close()
            return None, "You can only update tasks in your team."
        if row["assigned_to_user_id"] != user_id:
            db.close()
            return None, "Only the assigned user can complete this task."
        if row["status"] == "completed":
            db.close()
            return row, "Task already completed."
        db.execute(
            "UPDATE team_tasks SET status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = ?",
            (task_id,),
        )
        db.commit()
        db.close()
        return row, None

    def can_assign_task_to_user(self, session_user, target_user):
        if not target_user or not target_user["is_active"]:
            return False
        if session_user["team_id"] is None or target_user["team_id"] is None:
            return False
        return session_user["team_id"] == target_user["team_id"] and target_user["role"] in {"super_admin", "admin", "broker"}

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

    def upsert_ichra_application(self, employer_id: int, payload: dict[str, str], actor_user_id: int, submit: bool = False):
        db = self.db()
        status_value = "submitted" if submit else "draft"
        token_status = "locked" if submit else "active"
        db.execute(
            """
            INSERT INTO ichra_applications (
                employer_id, desired_start_date, service_type, primary_first_name, primary_last_name,
                primary_email, primary_phone, legal_name, nature_of_business, total_employee_count,
                physical_state, reimbursement_option, employee_class_assistance, planned_contribution,
                claim_option, agent_support, artifact_status, access_token_status, last_saved_by_user_id, submitted_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE NULL END, CURRENT_TIMESTAMP)
            ON CONFLICT(employer_id) DO UPDATE SET
                desired_start_date = excluded.desired_start_date,
                service_type = excluded.service_type,
                primary_first_name = excluded.primary_first_name,
                primary_last_name = excluded.primary_last_name,
                primary_email = excluded.primary_email,
                primary_phone = excluded.primary_phone,
                legal_name = excluded.legal_name,
                nature_of_business = excluded.nature_of_business,
                total_employee_count = excluded.total_employee_count,
                physical_state = excluded.physical_state,
                reimbursement_option = excluded.reimbursement_option,
                employee_class_assistance = excluded.employee_class_assistance,
                planned_contribution = excluded.planned_contribution,
                claim_option = excluded.claim_option,
                agent_support = excluded.agent_support,
                artifact_status = excluded.artifact_status,
                access_token_status = excluded.access_token_status,
                last_saved_by_user_id = excluded.last_saved_by_user_id,
                submitted_at = CASE WHEN excluded.artifact_status = 'submitted' THEN CURRENT_TIMESTAMP ELSE ichra_applications.submitted_at END,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                employer_id,
                payload.get("desired_start_date", ""),
                payload.get("service_type", ""),
                payload.get("primary_first_name", ""),
                payload.get("primary_last_name", ""),
                payload.get("primary_email", ""),
                payload.get("primary_phone", ""),
                payload.get("legal_name", ""),
                payload.get("nature_of_business", ""),
                payload.get("total_employee_count", ""),
                payload.get("physical_state", ""),
                payload.get("reimbursement_option", ""),
                payload.get("employee_class_assistance", ""),
                payload.get("planned_contribution", ""),
                payload.get("claim_option", ""),
                payload.get("agent_support", ""),
                status_value,
                token_status,
                actor_user_id,
                1 if submit else 0,
            ),
        )
        db.execute(
            "UPDATE employers SET ichra_started = 1, application_complete = ? WHERE id = ?",
            (1 if submit else 0, employer_id),
        )
        db.commit()
        db.close()

    def get_ichra_application(self, employer_id: int):
        db = self.db()
        row = db.execute("SELECT * FROM ichra_applications WHERE employer_id = ?", (employer_id,)).fetchone()
        db.close()
        return row

    def renew_ichra_access_token(self, employer_id: int, actor_user_id: int):
        db = self.db()
        db.execute(
            """
            UPDATE ichra_applications
            SET access_token_status = 'active',
                artifact_status = 'draft',
                token_renewed_by_user_id = ?,
                token_renewed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE employer_id = ?
            """,
            (actor_user_id, employer_id),
        )
        db.execute("UPDATE employers SET ichra_started = 1, application_complete = 0 WHERE id = ?", (employer_id,))
        db.commit()
        db.close()

    def start_employer_ichra(self, employer_user_id: int):
        db = self.db()
        employer = db.execute("SELECT id FROM employers WHERE linked_user_id = ?", (employer_user_id,)).fetchone()
        if not employer:
            db.close()
            return None
        db.execute("UPDATE employers SET ichra_started = 1, application_complete = 0 WHERE linked_user_id = ?", (employer_user_id,))
        db.execute(
            "INSERT OR IGNORE INTO ichra_applications (employer_id, artifact_status, last_saved_by_user_id) VALUES (?, 'draft', ?)",
            (employer["id"], employer_user_id),
        )
        db.commit()
        db.close()
        return employer["id"]

    def refer_client_ichra(self, employer_id: int):
        db = self.db()
        employer = db.execute("SELECT id, legal_name, linked_user_id FROM employers WHERE id = ?", (employer_id,)).fetchone()
        if not employer:
            db.close()
            return None
        db.execute("UPDATE employers SET ichra_started = 1, application_complete = 0 WHERE id = ?", (employer_id,))
        db.execute(
            "INSERT OR IGNORE INTO ichra_applications (employer_id, artifact_status, last_saved_by_user_id) VALUES (?, 'draft', ?)",
            (employer_id, employer["linked_user_id"]),
        )
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


    def update_user_ui_mode(self, user_id: int, ui_mode: str):
        if ui_mode not in ALLOWED_UI_MODES:
            ui_mode = "LEGACY"
        db = self.db()
        db.execute("UPDATE users SET ui_mode = ? WHERE id = ?", (ui_mode, user_id))
        db.commit()
        db.close()

    def effective_ui_mode(self, user):
        preferred_mode = user["ui_mode"] if "ui_mode" in user.keys() and user["ui_mode"] in ALLOWED_UI_MODES else "LEGACY"
        if preferred_mode == "NEW" and user["role"] != "super_admin":
            self.update_user_ui_mode(user["id"], "LEGACY")
            return "LEGACY"
        return preferred_mode

    def render_ui_mode_toggle(self, user, active_view: str):
        if user["role"] != "super_admin" or active_view not in {"dashboard", "home"}:
            return ""
        checked = "checked" if self.effective_ui_mode(user) == "NEW" else ""
        return f"""
        <form method='post' action='/settings/ui-mode' class='ui-mode-toggle' aria-label='UI mode toggle form'>
          <input type='hidden' name='view' value='{html.escape(active_view)}' />
          <input type='hidden' name='ui_mode' value="{'LEGACY' if checked else 'NEW'}" />
          <label class='toggle-switch' aria-label='New UI'>
            <input type='checkbox' role='switch' aria-label='New UI' {checked} onchange="this.form.ui_mode.value=this.checked?'NEW':'LEGACY'; this.form.submit();" />
            <span>New UI</span>
          </label>
        </form>
        """

    def render_ui_mode_router(self, start_response, user, flash_message, active_view, query):
        ui_mode = self.effective_ui_mode(user)
        if ui_mode == "NEW":
            try:
                return self.render_new_ui_app(start_response, user, flash_message, active_view, query)
            except Exception:
                self.update_user_ui_mode(user["id"], "LEGACY")
                self.log_action(user["id"], "ui_mode_fallback", "user", user["id"], user["username"], f"route={active_view};from=NEW;to=LEGACY")
                fallback_flash = ("error", "New UI is temporarily unavailable. Switched back to Legacy UI.")
                return self.render_dashboard(start_response, user, fallback_flash, active_view, query)
        return self.render_dashboard(start_response, user, flash_message, active_view, query)

    def render_new_ui_app(self, start_response, user, flash_message, active_view, query):
        if user["role"] == "super_admin" and active_view in {"dashboard", "home"}:
            return self.render_super_admin_new_ui_dashboard(start_response, user, flash_message)
        return self.render_dashboard(start_response, user, flash_message, active_view, query)

    def render_super_admin_new_ui_dashboard(self, start_response, user, flash_message):
        notifications = self.list_notifications(user["id"])
        unseen_count = sum(1 for item in notifications if not item["seen"])
        employers = self.list_visible_employers(user)
        active_employer_count = sum(1 for row in employers if row["portal_user_is_active"])
        onboarding_count = sum(1 for row in employers if not row["application_complete"])
        tasks = self.list_visible_team_tasks(user)
        open_tasks = sum(1 for row in tasks if row["status"] != "completed")
        toggle = self.render_ui_mode_toggle(user, "dashboard")
        body = self.flash_html(flash_message) + f"""
          <section class='new-ui-shell app-shell'>
            <header class='new-ui-header'>
              <div>
                <h1>Super Admin Dashboard</h1>
                <p class='subtitle'>New UI preview mode with legacy-safe route fallback.</p>
              </div>
              <div class='header-actions'>
                {toggle}
                <a class='header-action-btn' href='/?view=settings'>Settings</a>
                <form method='post' action='/logout'><button class='header-action-btn logout-btn' type='submit'>Log Out</button></form>
              </div>
            </header>
            <nav class='new-ui-breadcrumbs' aria-label='Breadcrumb'><span>Home</span><span>/</span><span>Dashboard</span></nav>
            <div class='new-ui-grid'>
              <article class='new-ui-card'><h3>Scoped Employers</h3><p class='new-ui-metric'>{len(employers)}</p><p class='subtitle'>{active_employer_count} active portals</p></article>
              <article class='new-ui-card'><h3>Open Setup Workflows</h3><p class='new-ui-metric'>{onboarding_count}</p><p class='subtitle'>Submitted + in-progress tracking</p></article>
              <article class='new-ui-card'><h3>Team Tasks</h3><p class='new-ui-metric'>{open_tasks}</p><p class='subtitle'>Open operational tasks</p></article>
              <article class='new-ui-card'><h3>Notifications</h3><p class='new-ui-metric'>{unseen_count}</p><p class='subtitle'>Unread alerts</p></article>
            </div>
            <section class='new-ui-card'>
              <h3>Workspace Navigation</h3>
              <div class='new-ui-row-list'>
                <a class='new-ui-row' href='/?view=application'><strong>ICHRA Setup Workspace</strong><span>Open forms and submission workflow</span></a>
                <a class='new-ui-row' href='/?view=employers'><strong>Employers</strong><span>Manage employer roster and ownership</span></a>
                <a class='new-ui-row' href='/?view=users'><strong>Users</strong><span>Provision admins, brokers, and employers</span></a>
                <a class='new-ui-row' href='/?view=system'><strong>System</strong><span>Review teams, logs, and control panels</span></a>
              </div>
            </section>
          </section>
        """
        html_doc = self.html_page("Dashboard", body)
        headers = [("Content-Type", "text/html; charset=utf-8"), ("Set-Cookie", self.expire_cookie_header("flash"))]
        start_response("200 OK", headers)
        return [html_doc.encode("utf-8")]

    def create_user(self, username: str, password: str, role: str, created_by_user_id: int | None = None, team_id: int | None = None):
        db = self.db()
        is_team_admin = 1 if role == "broker" and team_id is not None and db.execute(
            "SELECT 1 FROM users WHERE role = 'broker' AND team_id = ? AND is_team_admin = 1 AND is_active = 1",
            (team_id,),
        ).fetchone() is None else 0
        is_team_super_admin = 1 if role in {"admin", "broker"} and team_id is not None and db.execute(
            "SELECT 1 FROM users WHERE role IN ('admin', 'broker') AND team_id = ? AND is_team_super_admin = 1 AND is_active = 1",
            (team_id,),
        ).fetchone() is None else 0
        db.execute(
            "INSERT INTO users (username, display_name, password_hash, password_hint, role, created_by_user_id, must_change_password, team_id, is_team_admin, is_team_super_admin) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
            (username, username.capitalize(), hash_password(password), password, role, created_by_user_id, team_id, is_team_admin, is_team_super_admin),
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
            "UPDATE users SET username = ?, display_name = ?, role = ?, password_hash = ?, password_hint = ?, must_change_password = ?, is_active = ?, is_team_admin = CASE WHEN ? = 'broker' AND is_team_admin = 1 THEN 1 ELSE 0 END, is_team_super_admin = CASE WHEN ? IN ('admin', 'broker') AND is_team_super_admin = 1 THEN 1 ELSE 0 END WHERE id = ?",
            (username, username.capitalize(), role, password_hash, password or user["password_hint"], 0 if password else user["must_change_password"], is_active, role, role, user_id),
        )
        db.commit()
        db.close()
        self.ensure_team_super_admin_for_team(user["team_id"])

    def build_employer_username(self, db, legal_name: str) -> str:
        seed = "".join(ch for ch in legal_name.lower() if ch.isalnum())[:12] or "employer"
        count = db.execute("SELECT COUNT(*) AS n FROM users WHERE username LIKE ?", (f"{seed}%",)).fetchone()["n"]
        return f"{seed}{count + 1}"

    def build_broker_username(self, db, brokerage_name: str) -> str:
        seed = "".join(ch for ch in brokerage_name.lower() if ch.isalnum())[:12] or "broker"
        count = db.execute("SELECT COUNT(*) AS n FROM users WHERE username LIKE ?", (f"{seed}%",)).fetchone()["n"]
        return f"{seed}{count + 1}"

    def create_public_broker(self, form: dict[str, str]) -> str:
        db = self.db()
        username = self.build_broker_username(db, form["brokerage_name"])
        display_name = form["contact_name"].strip() or form["brokerage_name"].strip()
        db.execute(
            """
            INSERT INTO users (username, display_name, password_hash, password_hint, role, created_by_user_id, must_change_password, team_id, is_team_admin, is_team_super_admin)
            VALUES (?, ?, ?, ?, 'broker', 1, 1, NULL, 0, 0)
            """,
            (username, display_name, hash_password("user"), "user"),
        )
        db.commit()
        db.close()
        return username

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

    def ensure_user_personalization(self, user):
        base = f"{user['id']}:{user['username']}"
        seed = hashlib.sha256(base.encode("utf-8")).hexdigest()
        themes = ["sunset", "dawn", "mint", "lavender", "midnight"]
        vibes = ["orbit", "spark", "kite", "burst", "pixel"]
        orders = [
            "recent,favorites,recommended",
            "favorites,recommended,recent",
            "recommended,recent,favorites",
            "recent,recommended,favorites",
        ]
        avatar_symbols = ["◉", "✦", "▲", "✶", "◆"]
        theme = user["theme_variant"] or themes[int(seed[:2], 16) % len(themes)]
        order = user["home_layout"] or orders[int(seed[2:4], 16) % len(orders)]
        vibe = user["vibe_pack"] or vibes[int(seed[4:6], 16) % len(vibes)]
        avatar = user["avatar_symbol"] or avatar_symbols[int(seed[6:8], 16) % len(avatar_symbols)]
        onboarding_complete = user["onboarding_complete"]
        if user["user_seed"] and user["theme_variant"] and user["home_layout"] and user["vibe_pack"] and user["avatar_symbol"]:
            return {"seed": user["user_seed"], "theme": theme, "order": order, "vibe": vibe, "avatar": avatar, "onboarding_complete": onboarding_complete}
        db = self.db()
        db.execute(
            """
            UPDATE users
            SET user_seed = COALESCE(user_seed, ?),
                theme_variant = COALESCE(theme_variant, ?),
                home_layout = COALESCE(home_layout, ?),
                vibe_pack = COALESCE(vibe_pack, ?),
                avatar_symbol = COALESCE(avatar_symbol, ?)
            WHERE id = ?
            """,
            (seed, theme, order, vibe, avatar, user["id"]),
        )
        db.commit()
        db.close()
        return {"seed": seed, "theme": theme, "order": order, "vibe": vibe, "avatar": avatar, "onboarding_complete": onboarding_complete}

    def handle_onboarding_complete(self, start_response, session_user, form):
        avatar_symbol = (form.get("avatar_symbol") or "").strip()[:2] or None
        shuffle_enabled = 1 if form.get("shuffle_enabled") == "1" else 0
        db = self.db()
        db.execute(
            "UPDATE users SET onboarding_complete = 1, avatar_symbol = COALESCE(?, avatar_symbol), shuffle_enabled = ? WHERE id = ?",
            (avatar_symbol, shuffle_enabled, session_user["id"]),
        )
        db.commit()
        db.close()
        self.log_action(session_user["id"], "onboarding_completed", "user", session_user["id"], session_user["username"], "Completed first-run profile setup")
        return self.redirect(start_response, "/", flash=("success", "Personal workspace ready."))

    def handle_preferences_settings(self, start_response, session_user, form):
        shuffle_enabled = 1 if form.get("shuffle_enabled") == "1" else 0
        db = self.db()
        db.execute("UPDATE users SET shuffle_enabled = ? WHERE id = ?", (shuffle_enabled, session_user["id"]))
        db.commit()
        db.close()
        return self.redirect(start_response, "/?view=settings", flash=("success", "Preferences updated."))


    def handle_ui_mode_settings(self, start_response, session_user, form):
        active_view = form.get("view", "dashboard")
        if session_user["role"] != "super_admin" or active_view not in {"dashboard", "home"}:
            return self.redirect(start_response, "/?view=dashboard", flash=("error", "Only Super Admins can switch UI mode from the dashboard header."))
        requested = (form.get("ui_mode") or "LEGACY").upper()
        if requested not in ALLOWED_UI_MODES:
            return self.redirect(start_response, "/?view=dashboard", flash=("error", "Invalid UI mode selected."))
        previous = self.effective_ui_mode(session_user)
        self.update_user_ui_mode(session_user["id"], requested)
        self.log_action(session_user["id"], "ui_mode_toggled", "user", session_user["id"], session_user["username"], f"route={active_view};previous_mode={previous};new_mode={requested}")
        mode_label = "New UI" if requested == "NEW" else "Legacy UI"
        return self.redirect(start_response, f"/?view={active_view}", flash=("success", f"Switched to {mode_label}."))

    def handle_admin_create_user(self, start_response, session_user, form):
        username = form.get("username", "").strip().lower()
        role = form.get("role", "admin")
        capabilities = self.capability_flags_for_user(session_user)
        if session_user["role"] == "broker" and not capabilities["team.staff_provision"] and role != "employer":
            return self.redirect(start_response, "/", flash=("error", "Brokers can only create employer users assigned to their team scope."))
        if role in {"admin", "broker"} and not capabilities["team.staff_provision"]:
            return self.redirect(start_response, "/", flash=("error", "You do not have permission to provision team staff users."))
        if role == "employer" and not capabilities["employer.user_admin"]:
            return self.redirect(start_response, "/", flash=("error", "You do not have permission to provision employer users."))
        is_team_super_admin = self.is_team_super_admin_user(session_user)
        creator_level = ROLE_LEVELS.get("admin", -1) if is_team_super_admin else ROLE_LEVELS.get(session_user["role"], -1)
        role_level = ROLE_LEVELS.get(role, -1)
        if role_level < 0:
            return self.redirect(start_response, "/", flash=("error", "Invalid role selected."))
        if (session_user["role"] != "broker" or not is_team_super_admin) and role_level >= creator_level:
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
        capabilities = self.capability_flags_for_user(session_user)
        is_team_super_admin = self.is_team_super_admin_user(session_user)
        actor_level = ROLE_LEVELS.get("admin", -1) if is_team_super_admin else ROLE_LEVELS.get(session_user["role"], -1)
        target_level = ROLE_LEVELS.get(role, -1)
        if session_user["role"] == "broker" and not capabilities["team.staff_provision"] and role != "employer":
            return self.redirect(start_response, "/", flash=("error", "Brokers can only manage employer users."))
        if role in {"admin", "broker"} and not capabilities["team.staff_provision"]:
            return self.redirect(start_response, "/", flash=("error", "You do not have permission to manage team staff users."))
        if target_level < 0:
            return self.redirect(start_response, "/", flash=("error", "Invalid role selected."))
        if (session_user["role"] != "broker" or not is_team_super_admin) and target_level >= actor_level:
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
            self.upsert_ichra_application(existing_employer_id, {
                "desired_start_date": form.get("ichra_start_date", "").strip(),
                "service_type": form.get("service_type", "").strip(),
                "primary_first_name": form.get("primary_first_name", "").strip(),
                "primary_last_name": form.get("primary_last_name", "").strip(),
                "primary_email": form.get("primary_email", "").strip(),
                "primary_phone": form.get("primary_phone", "").strip(),
                "legal_name": form.get("legal_name", "").strip(),
                "nature_of_business": form.get("nature_of_business", "").strip(),
                "total_employee_count": form.get("total_employee_count", "").strip(),
                "physical_state": form.get("physical_state", "").strip(),
                "reimbursement_option": form.get("reimbursement_option", "").strip(),
                "employee_class_assistance": form.get("employee_class_assistance", "").strip(),
                "planned_contribution": form.get("planned_contribution", "").strip(),
                "claim_option": form.get("claim_option", "").strip(),
                "agent_support": form.get("agent_support", "").strip(),
            }, actor_user_id=session_user["id"], submit=False)
            self.log_action(session_user["id"], "employer_updated", "employer", employer["id"], employer["legal_name"], "ICHRA setup application initialized")
            self.create_notification(session_user["id"], f"{employer['legal_name']} ICHRA setup application initialized.")
            return self.redirect(
                start_response,
                f"/?view=application&employer_id={existing_employer_id}",
                flash=("success", f"ICHRA setup application started for {employer['legal_name']}. Continue editing before submission.")
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

    def handle_save_ichra_application(self, start_response, session_user, form):
        try:
            employer_id = int(form.get("employer_id", ""))
        except ValueError:
            return self.redirect(start_response, "/?view=application", flash=("error", "Select an employer before saving the ICHRA application."))

        employer = self.get_visible_employer_by_id(session_user, employer_id)
        if not employer:
            return self.redirect(start_response, "/?view=application", flash=("error", "Employer not found in your access scope."))

        if session_user["role"] == "employer" and employer["linked_user_id"] != session_user["id"]:
            return self.redirect(start_response, "/?view=application", flash=("error", "You can only edit your own employer application."))

        artifact = self.get_ichra_application(employer_id)
        if artifact and artifact["access_token_status"] == "locked":
            return self.redirect(
                start_response,
                f"/?view=application&employer_id={employer_id}",
                flash=("error", "This ICHRA setup workspace is locked after submission. Ask an admin or broker to renew access."),
            )

        required_fields = [
            "desired_start_date", "service_type", "primary_first_name", "primary_last_name", "primary_email",
            "primary_phone", "legal_name", "nature_of_business", "total_employee_count", "physical_state",
            "reimbursement_option", "employee_class_assistance", "planned_contribution", "claim_option", "agent_support",
        ]
        payload = {key: form.get(key, "").strip() for key in required_fields}
        action = form.get("artifact_action", "save")
        submit = action == "submit"

        if submit and any(not payload[field] for field in required_fields):
            return self.redirect(start_response, f"/?view=application&employer_id={employer_id}", flash=("error", "Complete all required ICHRA application fields before submitting."))

        self.upsert_ichra_application(employer_id, payload, actor_user_id=session_user["id"], submit=submit)
        if submit:
            self.log_action(session_user["id"], "application_status_changed", "employer", employer_id, employer["legal_name"], "status=complete;application=ichra")
            if employer["primary_user_id"]:
                self.create_notification(employer["primary_user_id"], f"ICHRA setup application submitted for {employer['legal_name']}.")
            self.create_notification(session_user["id"], f"ICHRA setup application submitted for {employer['legal_name']}.")
            flash = ("success", f"ICHRA setup application submitted for {employer['legal_name']}.")
        else:
            self.log_action(session_user["id"], "employer_updated", "employer", employer_id, employer["legal_name"], "Saved ICHRA setup application draft")
            flash = ("success", f"Draft saved for {employer['legal_name']}.")

        return self.redirect(start_response, f"/?view=application&employer_id={employer_id}", flash=flash)

    def handle_renew_ichra_token(self, start_response, session_user, form):
        if session_user["role"] not in {"super_admin", "admin", "broker"}:
            return self.redirect(start_response, "/?view=application", flash=("error", "Only admins and brokers can renew workspace access tokens."))
        try:
            employer_id = int(form.get("employer_id", ""))
        except ValueError:
            return self.redirect(start_response, "/?view=application", flash=("error", "Select an employer to renew."))
        employer = self.get_visible_employer_by_id(session_user, employer_id)
        if not employer:
            return self.redirect(start_response, "/?view=application", flash=("error", "Employer not found in your access scope."))

        artifact = self.get_ichra_application(employer_id)
        if not artifact or artifact["access_token_status"] != "locked":
            return self.redirect(start_response, f"/?view=application&employer_id={employer_id}", flash=("error", "This workspace is already active."))

        self.renew_ichra_access_token(employer_id, session_user["id"])
        self.log_action(session_user["id"], "application_status_changed", "employer", employer_id, employer["legal_name"], "status=open;application=ichra;token=renewed")
        self.create_notification(employer["linked_user_id"], f"ICHRA setup workspace reopened for {employer['legal_name']}. You can now continue editing.")
        return self.redirect(start_response, f"/?view=application&employer_id={employer_id}", flash=("success", f"ICHRA setup workspace reopened for {employer['legal_name']}."))

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

    def handle_public_broker_signup(self, start_response, form):
        form["brokerage_name"] = form.get("brokerage_name", "")
        form["contact_name"] = form.get("contact_name", "")
        form["work_email"] = form.get("work_email", "")
        form["phone"] = form.get("phone", "") or "Not provided"

        required = ["brokerage_name", "contact_name", "work_email"]
        if any(not form.get(name, "").strip() for name in required):
            return self.redirect(start_response, "/login", flash=("error", "Please complete brokerage name, contact, and email."))

        username = self.create_public_broker(form)
        self.log_action(None, "broker_signup_requested", "user", None, form["brokerage_name"].strip(), f"username={username};email={form['work_email'].strip().lower()};phone={form['phone'].strip()}")
        return self.redirect(
            start_response,
            "/login",
            flash=("success", f"Broker setup submitted. Portal username: {username}, temporary password: user. Admin assigns teams after review."),
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

    def handle_assign_broker_admin(self, start_response, session_user, form):
        try:
            broker_user_id = int(form.get("broker_user_id", ""))
            team_id = int(form.get("team_id", ""))
        except ValueError:
            return self.redirect(start_response, "/?view=team", flash=("error", "Select a broker and a team."))
        try:
            self.assign_team_admin_broker(broker_user_id, team_id)
        except ValueError:
            return self.redirect(start_response, "/?view=team", flash=("error", "Invalid broker team admin assignment."))
        target = self.get_user_by_id(broker_user_id)
        self.log_action(session_user["id"], "team_broker_admin_assigned", "user", broker_user_id, target["username"] if target else "broker", f"team_id={team_id}")
        return self.redirect(start_response, "/?view=team", flash=("success", "Team broker admin updated."))

    def handle_assign_team_super_admin(self, start_response, session_user, form):
        try:
            user_id = int(form.get("user_id", ""))
            team_id = int(form.get("team_id", ""))
        except ValueError:
            return self.redirect(start_response, "/?view=team", flash=("error", "Select a team and assignee."))
        try:
            self.assign_team_super_admin(user_id, team_id)
        except ValueError:
            return self.redirect(start_response, "/?view=team", flash=("error", "Invalid team super admin assignment."))
        target = self.get_user_by_id(user_id)
        self.log_action(session_user["id"], "team_super_admin_assigned", "user", user_id, target["username"] if target else "team-user", f"team_id={team_id}")
        return self.redirect(start_response, "/?view=team", flash=("success", "Team super admin updated."))


    def handle_create_team_task(self, start_response, session_user, form):
        title = form.get("title", "").strip()
        details = form.get("details", "").strip()
        if len(title) < 3:
            return self.redirect(start_response, "/?view=dashboard", flash=("error", "Task title must be at least 3 characters."))
        try:
            assigned_to_user_id = int(form.get("assigned_to_user_id", ""))
        except ValueError:
            return self.redirect(start_response, "/?view=dashboard", flash=("error", "Select a valid teammate."))

        target = self.get_user_by_id(assigned_to_user_id)
        if not self.can_assign_task_to_user(session_user, target):
            return self.redirect(start_response, "/?view=dashboard", flash=("error", "You can only assign tasks within your team."))

        self.create_team_task(
            team_id=session_user["team_id"],
            title=title,
            details=details,
            assigned_to_user_id=assigned_to_user_id,
            assigned_by_user_id=session_user["id"],
        )
        self.log_action(
            session_user["id"],
            "team_task_created",
            "team_task",
            assigned_to_user_id,
            target["username"],
            f"title={title}",
        )
        return self.redirect(start_response, "/?view=dashboard", flash=("success", "Team task assigned."))

    def handle_complete_team_task(self, start_response, session_user, form):
        try:
            task_id = int(form.get("task_id", ""))
        except ValueError:
            return self.redirect(start_response, "/?view=dashboard", flash=("error", "Invalid task."))

        task_row, error = self.complete_team_task(task_id, session_user["id"])
        if error:
            flash_type = "success" if error == "Task already completed." else "error"
            return self.redirect(start_response, "/?view=dashboard", flash=(flash_type, error))

        self.log_action(
            session_user["id"],
            "team_task_completed",
            "team_task",
            task_id,
            session_user["username"],
            "Task completed",
        )
        return self.redirect(start_response, "/?view=dashboard", flash=("success", "Task completed."))

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
        html_body = self.flash_html(flash_message) + f"""
            <section class="card auth-card vibe-orbit">
              <header class='app-header'>
                <div>
                  <p class="eyebrow">Monolith Flow</p>
                  <h1>Launch your ICHRA workspace in minutes</h1>
                  <p class="subtitle">Get a faster go-live with guided setup, transparent tracking, and team-ready onboarding.</p>
                </div>
                <div class='avatar-chip'>◉</div>
              </header>

              <section class="section-block panel-card signup-highlight">
                <h3>Need to create a new account?</h3>
                <p class="subtitle">Start a secure setup for a new Employer or Broker account. We&apos;ll guide you to the right form next.</p>
                <div class='signup-benefits'>
                  <span class='pill pending'>Employer setup form</span>
                  <span class='pill pending'>Broker setup form</span>
                  <span class='pill pending'>Guided onboarding</span>
                </div>
                <button type="button" class="secondary centered-setup-button" data-modal-open="public-setup-modal">Start New Setup</button>
              </section>

              <section class='section-block panel-card'>
                <h3>Member Login</h3>
                <form method="post" action="/login" class="form-grid">
                  <label>Username <input type="text" name="username" placeholder="alex" required /></label>
                  <label>Password <input type="password" name="password" placeholder="user" required /></label>
                  <button type="submit" class='primary-action'>Start workspace</button>
                </form>
              </section>
            </section>
            <div class="modal" id="public-setup-modal" aria-hidden="true">
              <div class="modal-backdrop" data-modal-close="public-setup-modal"></div>
              <section class="modal-card card">
                <button type="button" class="modal-close" aria-label="Close" data-modal-close="public-setup-modal">×</button>
                <p class="eyebrow">Quick intake</p>
                <h2>New Setup Forms</h2>
                <div class='setup-toggle-row'>
                  <button type='button' class='secondary setup-toggle active' data-setup-mode='employer'>New Employer Setup Form</button>
                  <button type='button' class='secondary setup-toggle' data-setup-mode='broker'>New Broker Setup Form</button>
                </div>
                <div class='setup-panel' data-panel-mode='employer'>
                  {self.render_new_employer_setup_form()}
                </div>
                <div class='setup-panel' data-panel-mode='broker' hidden>
                  {self.render_new_broker_setup_form()}
                </div>
              </section>
            </div>
            """
        html_doc = self.html_page("Monolith Task Tracker", html_body)
        headers = [("Content-Type", "text/html; charset=utf-8"), ("Set-Cookie", self.expire_cookie_header("flash"))]
        start_response("200 OK", headers)
        return [html_doc.encode("utf-8")]

    def render_permissions_panel(self):
        matrix_rows = [
            (
                "Account lifecycle management",
                "Can create/update admin, broker, and employer users across teams (except other super admins).",
                "Can create/update admin, broker, and employer users inside their assigned team.",
                "Can create/update employer users only inside their assigned team; cannot provision broker peers.",
                "Can only update their own profile and password.",
            ),
            (
                "Employer portfolio visibility",
                "Sees all employers plus active/inactive account scopes.",
                "Sees employers in the same team scope.",
                "Sees only employers assigned to that broker.",
                "Sees only the employer record linked to their own user account.",
            ),
            (
                "ICHRA Setup Workspace",
                "Full access to save drafts, submit applications, and renew locked tokens.",
                "Full access to save drafts, submit applications, and renew locked tokens.",
                "Full access for assigned employers with lock-state aware actions.",
                "Can view/edit only their own application and submit when eligible.",
            ),
            (
                "Team administration",
                "Can create teams, assign Team Super Admin, and set broker team admin singleton per team.",
                "Can administer users in their team; Team Super Admin flag grants admin-equivalent scope within the team.",
                "Can view team workspace; Team Super Admin flag grants admin-equivalent scope within the team.",
                "Read-only team awareness; no team administration actions.",
            ),
            (
                "Audit visibility",
                "Platform-wide Activity Log visibility.",
                "Team-scoped Activity Log visibility.",
                "Team-scoped Activity Log visibility.",
                "No Activity Log tab.",
            ),
        ]

        table_rows = "".join(
            """
            <tr>
              <td><strong>{area}</strong></td>
              <td>{super_admin}</td>
              <td>{admin}</td>
              <td>{broker}</td>
              <td>{employer}</td>
            </tr>
            """.format(
                area=html.escape(area),
                super_admin=html.escape(super_admin),
                admin=html.escape(admin),
                broker=html.escape(broker),
                employer=html.escape(employer),
            )
            for area, super_admin, admin, broker, employer in matrix_rows
        )

        return f"""
          <section class='section-block panel-card'>
            <h3>Permissions and Access Control Baseline</h3>
            <p class='subtitle'>Authorization is enforced through capability + scope checks (platform, team, employer) with role defaults layered on top. Use this panel as the runtime source of truth.</p>
            <div class='table-wrap'>
              <table>
                <thead>
                  <tr>
                    <th>Capability Area</th>
                    <th>Super Admin</th>
                    <th>Admin</th>
                    <th>Broker</th>
                    <th>Employer</th>
                  </tr>
                </thead>
                <tbody>{table_rows}</tbody>
              </table>
            </div>
          </section>
          <section class='section-block panel-card'>
            <h3>Operational Rules in Effect (DevOps Notes)</h3>
            <ul class='status-list'>
              <li><strong>Capability model:</strong> Permission decisions resolve through explicit capabilities (for example <code>team.user_admin</code>, <code>team.audit_view</code>, and <code>employer.user_admin</code>) and scoped resource checks.</li>
              <li><strong>Team boundary:</strong> Management and audit actions are team-scoped for non-super users to preserve tenant isolation.</li>
              <li><strong>Broker staff provisioning guardrail:</strong> Brokers cannot create or edit broker/admin staff users, preventing peer-account sprawl.</li>
              <li><strong>Single broker admin per team:</strong> The broker-team-admin designation is singleton per team and can only be reassigned by a super admin.</li>
              <li><strong>Application lock model:</strong> Submitted ICHRA applications become token-locked until an operations role renews access, enabling controlled post-submit edits.</li>
              <li><strong>Effective access endpoint:</strong> <code>GET /me/access</code> returns capability flags plus scoped memberships so UI can render access-aware actions without trial-and-error 403 flows.</li>
            </ul>
          </section>
        """

    def render_dashboard(self, start_response, user, flash_message, active_view="dashboard", query=None):
        query = query or {}
        role = user["role"]
        personalization = self.ensure_user_personalization(user)
        theme_variant = user["theme"] if user["theme"] != "default" else personalization["theme"]
        vibe_pack = personalization["vibe"]
        module_order = personalization["order"].split(",")
        team = self.get_team_for_user(user["id"])
        team_tasks = self.list_visible_team_tasks(user)
        team_members = self.list_team_members(user["team_id"]) if user["team_id"] is not None else []

        employers = self.list_visible_employers(user)
        employers_scope = query.get("employers_scope", ["active"])[0] if query else "active"
        if employers_scope not in {"active", "all", "inactive"}:
            employers_scope = "active"
        if role == "employer":
            visible_employer_rows = employers
        elif employers_scope == "all":
            visible_employer_rows = employers
        elif employers_scope == "inactive":
            visible_employer_rows = [row for row in employers if not row["portal_user_is_active"]]
        else:
            visible_employer_rows = [row for row in employers if row["portal_user_is_active"]]

        active_employer_count = sum(1 for row in employers if row["portal_user_is_active"])
        inactive_employer_count = len(employers) - active_employer_count
        employer_rows = "".join(
            f"""
            <tr>
              <td>{html.escape(row['legal_name'])}</td>
              <td>{html.escape(row['contact_name'])}</td>
              <td>{html.escape(row['work_email'])}</td>
              <td>{html.escape(row['portal_username'] or 'N/A')}</td>
              <td>{html.escape(row['broker_username'] or 'Unassigned')}</td>
              <td>{'Active' if row['portal_user_is_active'] else 'Inactive'}</td>
              <td>{application_status_label(row['ichra_started'], row['application_complete'])}</td>
              <td>{html.escape(row['onboarding_task'])}</td>
              <td>{self.render_employer_settings_link(row, role)}</td>
            </tr>
            """
            for row in visible_employer_rows
        )
        if not employer_rows:
            employer_rows = "<tr><td colspan='9'>No employers available for this account yet.</td></tr>"
        role_title = {
            "super_admin": "Admin Operations Dashboard",
            "broker": "Broker Portfolio Dashboard",
            "employer": "Employer Workspace",
            "admin": "Admin Team Dashboard",
        }.get(role, "Dashboard")

        role_banner = {
            "super_admin": "Manage broker accounts and system-wide visibility.",
            "broker": "Create employers and monitor all ICHRA setup workspaces assigned to your book.",
            "employer": "Review your application and complete outstanding onboarding tasks.",
            "admin": "Create and oversee brokers and employers assigned to your organization.",
        }.get(role, "")

        show_application = role in {"super_admin", "admin", "broker", "employer"}
        show_settings = role in {"super_admin", "admin", "broker", "employer"}
        capabilities = self.capability_flags_for_user(user)
        show_logs = capabilities["platform.audit_view_all"] or capabilities["team.audit_view"]

        notifications = self.list_notifications(user["id"])
        unseen_count = sum(1 for item in notifications if not item["seen"])
        employer_profile = employers[0] if role == "employer" and employers else None

        nav_links = [("dashboard", "Dashboard")]
        if show_application:
            nav_links.append(("application", "ICHRA Setup Workspace"))
        if role in {"super_admin", "admin", "broker"}:
            nav_links.append(("employers", "Employers"))
        nav_links.append(("team", "Team"))
        nav_links.append(("notifications", f"Notifications {'⚠️' if unseen_count else ''}"))
        nav_links.append(("permissions", "Permissions"))
        nav_links.append(("system", "System"))

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
            if role == "broker":
                editable_role_options = ["broker", "employer"]
            else:
                editable_role_options = ["admin", "broker", "employer"]
            user_rows = "".join(
                f"""
                <tr>
                  <td>{html.escape(row['username'])}</td>
                      <td>{html.escape(row['role'])}{" · Team Admin" if row['role'] == 'broker' and row['is_team_admin'] else ''}{" · Team Super Admin" if row['is_team_super_admin'] else ''}</td>
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
                          {''.join(f"<option value='{option}' {'selected' if row['role'] == option else ''}>{option}</option>" for option in editable_role_options)}
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
            create_role_options = "<option value='admin'>admin</option><option value='broker'>broker</option><option value='employer'>employer</option>" if role != "broker" else "<option value='broker'>broker</option><option value='employer'>employer</option>"
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
                        <option value='dawn' {'selected' if user['theme'] == 'dawn' else ''}>Dawn</option>
                        <option value='mint' {'selected' if user['theme'] == 'mint' else ''}>Mint</option>
                        <option value='lavender' {'selected' if user['theme'] == 'lavender' else ''}>Lavender</option>
                      </select>
                    </label>
                    <label>Density
                      <select name='density'>
                        <option value='comfortable' {'selected' if user['density'] == 'comfortable' else ''}>Comfortable</option>
                        <option value='compact' {'selected' if user['density'] == 'compact' else ''}>Compact</option>
                      </select>
                    </label>
                    <button type='submit'>Save Style</button>
                  </form>
                </div>
                <div>
                  <h3>Workspace Preferences</h3>
                  <form method='post' action='/settings/preferences' class='form-grid'>
                    <label class='check-row'><input type='checkbox' name='shuffle_enabled' value='1' {'checked' if user['shuffle_enabled'] else ''} /> Enable shuffle mode</label>
                    <button type='submit'>Save Preferences</button>
                  </form>
                </div>
              </section>
            """

        teams = self.list_teams()
        assignable_admins = self.list_assignable_admins()
        assignable_users = self.list_assignable_users()

        selected_team_id = None
        if role == "super_admin":
            requested_team_id = (query.get("team_id", [""])[0] or "").strip()
            if requested_team_id.isdigit():
                selected_team_id = int(requested_team_id)
        else:
            selected_team_id = user["team_id"]
        if selected_team_id is None and teams:
            selected_team_id = teams[0]["id"]
        selected_team = next((row for row in teams if row["id"] == selected_team_id), None)

        selected_team_name = html.escape(selected_team["name"]) if selected_team else "No team selected"
        scoped_team_options = "".join(
            f"<option value='{row['id']}' {'selected' if selected_team and row['id'] == selected_team['id'] else ''}>{html.escape(row['name'])}</option>"
            for row in teams
        )
        scoped_admin_options = "".join(
            f"<option value='{row['id']}'>{html.escape(row['username'])}</option>"
            for row in assignable_admins
            if selected_team is None or row["team_id"] in {None, selected_team["id"]}
        )
        scoped_assignable_user_options = "".join(
            f"<option value='{row['id']}'>{html.escape(row['username'])} ({html.escape(row['role'])})</option>"
            for row in assignable_users
        )
        scoped_broker_options = "".join(
            f"<option value='{broker['id']}'>{html.escape(broker['username'])}{' (team admin)' if broker['is_team_admin'] else ''}</option>"
            for broker in (self.list_brokers_for_team(selected_team["id"]) if selected_team else [])
        )
        scoped_team_super_admin_options = "".join(
            f"<option value='{row['id']}'>{html.escape(row['username'])} ({html.escape(row['role'])}){' · current team super admin' if row['is_team_super_admin'] else ''}</option>"
            for row in assignable_users
            if row["role"] in {"admin", "broker"}
        )

        assign_task_user_options = "".join(
            f"<option value='{row['id']}'>{html.escape(row['display_name'])} ({html.escape(row['username'])} · {html.escape(row['role'])})</option>"
            for row in team_members
        )
        team_task_rows = "".join(
            f"""
            <li>
              <div class='team-task-item'>
                <div>
                  <strong>{html.escape(row['title'])}</strong>
                  <small>Assigned to {html.escape(row['assigned_to_display_name'])} by {html.escape(row['assigned_by_display_name'])}</small>
                  <small>{html.escape(row['details'] or 'No details provided.')}</small>
                </div>
                <div class='team-task-actions'>
                  <span class='pill {'complete' if row['status'] == 'completed' else 'pending'}'>{'Completed' if row['status'] == 'completed' else 'Open'}</span>
                  {"<form method='post' action='/team-tasks/complete'><input type='hidden' name='task_id' value='" + str(row['id']) + "' /><button type='submit' class='secondary'>Mark Complete</button></form>" if row['status'] == 'open' and row['assigned_to_username'] == user['username'] and role != 'employer' else ''}
                </div>
              </div>
            </li>
            """
            for row in team_tasks
        )
        if not team_task_rows:
            team_task_rows = "<li class='subtitle'>No team tasks yet.</li>"

        team_focus_summary = "<p class='subtitle'>No team is currently in focus.</p>"
        team_member_rows = "<tr><td colspan='4'>No users in this team yet.</td></tr>"
        if selected_team:
            members = self.list_active_users_for_team(selected_team['id'])
            team_focus_summary = f"""
            <section class='team-focus-summary'>
              <h4>Team Snapshot</h4>
              <div class='team-focus-metrics'>
                <article><span>Team in Focus</span><strong>{selected_team_name}</strong></article>
                <article><span>Admins</span><strong>{selected_team['admin_count']}</strong></article>
                <article><span>Brokers</span><strong>{selected_team['broker_count']}</strong></article>
                <article><span>Employers</span><strong>{selected_team['employer_count']}</strong></article>
              </div>
            </section>
            """
            team_member_rows = "".join(
                f"<tr><td>{html.escape(member['display_name'])}</td><td>{html.escape(member['username'])}</td><td>{html.escape(member['role'])}</td><td>{'Yes' if ('is_team_super_admin' in member.keys() and member['is_team_super_admin']) else 'No'}</td></tr>"
                for member in members
            ) or "<tr><td colspan='4'>No users in this team yet.</td></tr>"

        team_focus_picker = ""
        team_create_form = ""
        team_assign_admin_form = ""
        team_assign_user_form = ""
        team_assign_broker_admin_form = ""
        team_assign_super_admin_form = ""
        if role == "super_admin":
            team_focus_picker = (
                "<form method='get' action='/' class='inline-form'><input type='hidden' name='view' value='team' />"
                f"<select name='team_id'><option value=''>Select team</option>{scoped_team_options}</select>"
                "<button type='submit' class='secondary'>Focus Team</button></form>"
            )
            team_create_form = "<form method='post' action='/teams/create' class='inline-form'><input name='name' placeholder='new team name' required minlength='3' /><button type='submit'>Create Team</button></form>"
            team_assign_admin_form = (
                "<form method='post' action='/teams/assign-admin' class='inline-form'>"
                f"<select name='admin_user_id' required><option value=''>Select admin</option>{scoped_admin_options}</select>"
                f"<select name='team_id' required><option value=''>Select team</option>{scoped_team_options}</select>"
                "<button type='submit'>Assign Admin to Team</button></form>"
            )
            team_assign_user_form = (
                "<form method='post' action='/teams/assign-user' class='inline-form'>"
                f"<select name='user_id' required><option value=''>Select user</option>{scoped_assignable_user_options}</select>"
                f"<select name='team_id' required><option value=''>Select team</option>{scoped_team_options}</select>"
                "<button type='submit'>Assign User to Team</button></form>"
            )
            team_assign_broker_admin_form = (
                "<form method='post' action='/teams/assign-broker-admin' class='inline-form'>"
                f"<select name='team_id' required><option value=''>Select team</option>{scoped_team_options}</select>"
                f"<select name='broker_user_id' required><option value=''>Select broker</option>{scoped_broker_options}</select>"
                "<button type='submit'>Set Team Broker Admin</button></form>"
            )
            team_assign_super_admin_form = (
                "<form method='post' action='/teams/assign-team-super-admin' class='inline-form'>"
                f"<select name='team_id' required><option value=''>Select team</option>{scoped_team_options}</select>"
                f"<select name='user_id' required><option value=''>Select admin or broker</option>{scoped_team_super_admin_options}</select>"
                "<button type='submit'>Set Team Super Admin</button></form>"
            )

        team_workspace_panel = f"""
          <section class='section-block panel-card'>
            <h3>Team Workspace</h3>
            <p class='subtitle'>Manage one team at a time. Choose a team, review members, then apply targeted assignment updates.</p>
            {team_focus_picker}
            {team_focus_summary}
            {team_create_form}
            {team_assign_admin_form}
            {team_assign_user_form}
            {team_assign_broker_admin_form}
            {team_assign_super_admin_form}
            <div class='table-wrap'><table class='user-table'>
              <thead><tr><th>Name</th><th>Username</th><th>Role</th><th>Team Super Admin</th></tr></thead>
              <tbody>{team_member_rows}</tbody>
            </table></div>
          </section>
        """

        team_panel = f"""
            <nav class='dashboard-nav sub-nav'>
              <a class='nav-link {'active' if query.get('team_section', [''])[0] != 'account-management' else ''}' href='/?view=team{f"&team_id={selected_team['id']}" if selected_team else ""}'>Team Workspace</a>
              <a class='nav-link {'active' if query.get('team_section', [''])[0] == 'account-management' else ''}' href='/?view=team&team_section=account-management'>Account Management</a>
            </nav>
            {broker_admin_section if query.get('team_section', [''])[0] == 'account-management' else team_workspace_panel}
        """

        notification_targets = self.get_users_with_completion(user, include_employers=True)
        notification_target_options = "".join(
            f"<option value='{row['id']}'>{html.escape(row['username'])} ({html.escape(row['role'])}{' · ' + html.escape(row['employer_legal_name']) if row['employer_legal_name'] else ''})</option>"
            for row in notification_targets
        )
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
        ) or "<li class='subtitle'>No notifications yet.</li>"

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
              {"" if role == "employer" else f"<p class='subtitle'>Showing <strong>{len(visible_employer_rows)}</strong> of <strong>{len(employers)}</strong> scoped employers. Active portal accounts: <strong>{active_employer_count}</strong> · Inactive portal accounts: <strong>{inactive_employer_count}</strong>.</p><nav class='sub-nav dashboard-nav'><a class='nav-link {'active' if employers_scope == 'active' else ''}' href='/?view=employers&employers_scope=active'>Active</a><a class='nav-link {'active' if employers_scope == 'inactive' else ''}' href='/?view=employers&employers_scope=inactive'>Inactive</a><a class='nav-link {'active' if employers_scope == 'all' else ''}' href='/?view=employers&employers_scope=all'>All</a></nav>"}
              <div class='table-wrap'><table class='user-table'>
                <thead><tr><th>Employer</th><th>Contact</th><th>Email</th><th>Portal Username</th><th>Broker Owner</th><th>Portal Status</th><th>Application</th><th>Assigned Task</th><th>Settings</th></tr></thead>
                <tbody>{employer_rows}</tbody>
              </table></div>
            </section>
        """

        employer_applications_panel = ""
        header_primary_cta = ""
        employer_application_modal = ""
        if role == "employer" and employer_profile:
            ichra_status = application_status_label(employer_profile["ichra_started"], employer_profile["application_complete"])
            employer_applications_panel = f"""
                <section class='section-block'>
                  <h3>Applications</h3>
                  <div class='table-wrap'><table class='user-table'>
                    <thead><tr><th>Application</th><th>Status</th><th>Open</th><th>Authority</th></tr></thead>
                    <tbody>
                      <tr><td>Initial Employer Setup</td><td>Submitted</td><td><a class='table-link' href='/?view=employers'>Open</a></td><td><span class='badge'>/db/employers</span></td></tr>
                      <tr><td>ICHRA Setup Application</td><td>{ichra_status}</td><td>{"<a class='table-link' href='/?view=application&employer_id=" + str(employer_profile['id']) + "'>Open Application</a>" if employer_profile['ichra_started'] else "<a class='table-link' href='/?view=application&employer_id=" + str(employer_profile['id']) + "'>Start Application</a>"}</td><td><span class='badge'>/db/ichra_applications</span></td></tr>
                    </tbody>
                  </table></div>
                </section>
            """

            if not employer_profile["ichra_started"]:
                header_primary_cta = """
                    <a class='nav-link active' href='/?view=application'>Start ICHRA Workspace</a>
                """
            elif not employer_profile["application_complete"]:
                header_primary_cta = """
                    <a class='nav-link active' href='/?view=application'>Continue ICHRA Workspace</a>
                """
            else:
                header_primary_cta = "<span class='nav-link active'>Application Submitted</span>"
        if role == "broker":
            header_primary_cta = "<a class='nav-link active' href='/?view=dashboard'>Refer a Client</a>"

        if capabilities["platform.audit_view_all"]:
            logs = self.list_activity_logs(query)
        elif capabilities["team.audit_view"]:
            scoped_query = dict(query)
            scoped_query["team_id"] = [str(user["team_id"])] if user["team_id"] is not None else ["-1"]
            logs = self.list_activity_logs(scoped_query)
        else:
            logs = []
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
            f"<tr><td>PR #{entry['pr']}</td><td>{html.escape(entry['merged_at'])}</td><td>{html.escape(entry['change'])}</td><td>{html.escape(entry['result'])}</td><td>{html.escape(entry['why'])}</td></tr>"
            for entry in sorted(DEV_LOG_ENTRIES, key=lambda item: item["pr"])
        )
        devlog_panel = f"""
            <section class='section-block'>
              <h3>Development Log</h3>
              <p class='subtitle'>A running history of merged PRs, merge timestamps, what changed, outcomes, and rationale. Entries are auto-recorded for every merged PR going forward.</p>
              <div class='table-wrap'><table class='user-table'>
                <thead><tr><th>PR</th><th>Merged At (UTC)</th><th>What Changed</th><th>Result</th><th>Why</th></tr></thead>
                <tbody>{devlog_rows}</tbody>
              </table></div>
            </section>
        """

        forms_workspace_hint = {
            "super_admin": "Govern all ICHRA setup workspace pipelines across teams.",
            "admin": "Tool employer setup and ICHRA artifacts for your assigned organization.",
            "broker": "Guide client onboarding, then launch and monitor ICHRA application progress.",
            "employer": "Use your workspace to complete and submit your ICHRA application artifact.",
        }.get(role, "Access your ICHRA setup workspace tools.")

        forms_workspace_cta = (
            "<a class='nav-link active' href='/?view=application'>Open ICHRA Setup Workspace</a>"
            if role != "employer"
            else "<a class='nav-link active' href='/?view=application'>Open My Application Workspace</a>"
        )

        team_task_engine_panel = f"""
            <section class='section-block panel-card'>
              <h3>Team Task Engine · {html.escape(team['name']) if team else 'Unassigned Team'}</h3>
              <p class='subtitle'>Assign tasks to anyone in your team, including Super Admin accounts, to build confidence through visible execution.</p>
              {"<form method='post' action='/team-tasks/create' class='form-grid'><label>Task Title<input name='title' required minlength='3' /></label><label>Task Details<textarea name='details' placeholder='Optional context'></textarea></label><label>Assign To<select name='assigned_to_user_id' required><option value=''>Select team member</option>" + assign_task_user_options + "</select></label><button type='submit'>Assign Team Task</button></form>" if role != 'employer' and assign_task_user_options else "<p class='subtitle'>No assignable team members are currently available.</p>"}
              <ul class='status-list'>{team_task_rows}</ul>
            </section>
        """

        dashboard_panel = f"""
            {task_section}
            {team_task_engine_panel}
            {broker_refer_cta}
            <section class='section-block panel-card ecosystem-callout'>
              <h3>ICHRA Setup Workspace Ecosystem</h3>
              <p class='subtitle'>{forms_workspace_hint}</p>
              {forms_workspace_cta}
            </section>
            <section class='section-block'>
              <h3>Workflow Snapshot</h3>
              <div class='stats-grid'>
                <article><h4>Employers</h4><p>{len(employers)}</p></article>
                <article><h4>Applications Complete</h4><p>{sum(1 for row in employers if row['application_complete'])}</p></article>
                <article><h4>Open Team Tasks</h4><p>{sum(1 for row in team_tasks if row['status'] == 'open')}</p></article>
                <article><h4>Unread Notifications</h4><p>{unseen_count}</p></article>
              </div>
            </section>
            {employer_workspace}
        """

        selected_employer_id = None
        artifact_view = (query.get("artifact_view", ["application"])[0] or "application").strip().lower()
        if artifact_view not in {"application", "form"}:
            artifact_view = "application"
        try:
            selected_employer_id = int(query.get("employer_id", [""])[0]) if query.get("employer_id") else None
        except ValueError:
            selected_employer_id = None

        home_sections = {
            "recent": f"<section class='section-block panel-card'><h3>Recently used</h3><p class='subtitle'>Quickly jump back into active workspaces and tasks.</p>{team_task_engine_panel}</section>",
            "favorites": f"<section class='section-block panel-card'><h3>Favorites</h3><p class='subtitle'>Pinned items based on your role and ICHRA responsibilities.</p>{broker_refer_cta or forms_workspace_cta}</section>",
            "recommended": f"<section class='section-block panel-card'><h3>Recommended next actions</h3><h4>Workflow Snapshot</h4><p class='subtitle'>{forms_workspace_hint}</p>{task_section}<div class='stats-grid'><article><h4>Employers</h4><p>{len(employers)}</p></article><article><h4>Open tasks</h4><p>{sum(1 for row in team_tasks if row['status'] == 'open')}</p></article><article><h4>Unread</h4><p>{unseen_count}</p></article></div></section>",
        }
        dashboard_panel = "".join(home_sections.get(k, "") for k in module_order) + employer_workspace

        profile_panel = f"""
            <section class='section-block panel-card'>
              <h3>Profile</h3>
              <p class='subtitle'>Identity and contribution summary.</p>
              <div><strong>{html.escape(user['display_name'])}</strong> · {html.escape(role)}</div>
              <div class='stats-grid'>
                <article><h4>Completed applications</h4><p>{sum(1 for row in employers if row['application_complete'])}</p></article>
                <article><h4>Team tasks done</h4><p>{sum(1 for row in team_tasks if row['status'] == 'completed')}</p></article>
                <article><h4>Notifications</h4><p>{len(notifications)}</p></article>
              </div>
            </section>
        """

        system_sections = [("permissions", "Permissions")]
        if show_logs:
            system_sections.append(("logs", "Activity Log"))
        system_sections.append(("devlog", "Dev Log"))
        requested_system_view = (query.get("system_view", [""])[0] or "").strip().lower()
        valid_system_keys = {key for key, _ in system_sections}
        active_system_view = requested_system_view if requested_system_view in valid_system_keys else system_sections[0][0]
        system_nav = "".join(
            f"<a class='nav-link {'active' if active_system_view == key else ''}' href='/?view=system&system_view={key}'>{label}</a>"
            for key, label in system_sections
        )
        system_panels = {
            "permissions": self.render_permissions_panel(),
            "logs": logs_panel if show_logs else "<section class='section-block'><p class='subtitle'>No activity log access for this account.</p></section>",
            "devlog": devlog_panel,
        }
        system_panel = f"<nav class='dashboard-nav sub-nav'>{system_nav}</nav>{system_panels.get(active_system_view, self.render_permissions_panel())}"

        panel_lookup = {
            "dashboard": dashboard_panel,
            "home": dashboard_panel,
            "library": employer_applications_panel if role == "employer" else employers_panel,
            "team": team_panel,
            "action": self.render_ichra_application_form(user, selected_employer_id=selected_employer_id, artifact_view=artifact_view) if show_application else "",
            "application": self.render_ichra_application_form(user, selected_employer_id=selected_employer_id, artifact_view=artifact_view) if show_application else "",
            "employers": employers_panel,
            "applications": employer_applications_panel if role == "employer" else employers_panel,
            "history": notifications_panel,
            "notifications": notifications_panel,
            "profile": profile_panel,
            "permissions": self.render_permissions_panel(),
            "devlog": devlog_panel,
            "settings": settings_section,
            "logs": logs_panel if show_logs else "",
            "system": system_panel,
        }

        if not personalization["onboarding_complete"] and active_view in {"dashboard", "home"}:
            active_view = "onboarding"
            active_panel = f"""
              <section class='section-block panel-card'>
                <h3>First Run Personalization</h3>
                <p class='subtitle'>30-second setup for your ICHRA Setup Workspace: turn shuffle mode on/off.</p>
                <form method='post' action='/onboarding/complete' class='form-grid'>
                  <label class='check-row'><input type='checkbox' name='shuffle_enabled' value='1' {'checked' if user['shuffle_enabled'] else ''} /> Enable shuffle-style module rotation</label>
                  <button type='submit' class='primary-action'>Finish setup</button>
                </form>
              </section>
            """
        else:
            active_panel = panel_lookup.get(active_view, "")
            if not active_panel:
                active_view = "dashboard"
                active_panel = dashboard_panel

        password_banner = ""
        if user["must_change_password"]:
            password_banner = "<div class='flash-stack'><div class='flash error persistent-banner'>Security notice: your temporary password is still active. Please update your password in Settings.</div></div>"

        html_body = password_banner + self.flash_html(flash_message) + f"""
            <section class='card dashboard app-shell role-{role} theme-{theme_variant} density-{user['density']} vibe-{vibe_pack}'>
              <header class='dashboard-header app-header'>
                <div>
                  <h1>{html.escape(role_title)}</h1>
                  <p class='subtitle'>Welcome, {html.escape(user['display_name'])}</p>
                </div>
                <div class='header-controls'>
                  <div class='header-actions'>
                    {header_primary_cta}
                    {self.render_ui_mode_toggle(user, active_view)}
                    {"<a class='header-action-btn' href='/?view=settings'>Settings</a>" if show_settings else ''}
                    <form method='post' action='/logout'><button class='header-action-btn logout-btn' type='submit'>Log Out</button></form>
                  </div>
                  <div class='welcome-banner compact-banner'>Theme: {theme_variant.title()} · Vibe pack: {vibe_pack.title()} · Layout seed: {html.escape(personalization['seed'][:8])}</div>
                </div>
              </header>
              <div class='dashboard-layout'>
                <nav class='dashboard-nav floating-nav'>{nav_html}</nav>
                <div class='dashboard-content'>
                  {active_panel}
                </div>
              </div>
            </section>
            {employer_application_modal}
            """
        html_doc = self.html_page("Dashboard", html_body)
        headers = [("Content-Type", "text/html; charset=utf-8"), ("Set-Cookie", self.expire_cookie_header("flash"))]
        start_response("200 OK", headers)
        return [html_doc.encode("utf-8")]

    def render_ichra_application_form(self, user, selected_employer_id: int | None = None, artifact_view: str = "application"):
        role = user["role"]
        can_open_setup_form = role in {"super_admin", "admin", "broker"}
        artifact_sub_nav = f"""
          <nav class='dashboard-nav sub-nav'>
            <a class='nav-link {'active' if artifact_view == 'application' else ''}' href='/?view=application&artifact_view=application'>ICHRA Setup Workspace</a>
            {"<a class='nav-link " + ("active" if artifact_view == "form" else "") + "' href='/?view=application&artifact_view=form'>New Employer Setup Form</a>" if can_open_setup_form else ""}
          </nav>
        """

        if artifact_view == "form":
            if not can_open_setup_form:
                return artifact_sub_nav + """
                <section class='section-block panel-card'>
                  <h3>Permission Scoped</h3>
                  <p class='subtitle'>Employer users can complete their own ICHRA artifact, but cannot create new employer setup records.</p>
                </section>
                """
            return artifact_sub_nav + self.render_new_employer_setup_form()

        visible_employers = self.list_visible_employers(user)
        if not visible_employers:
            return artifact_sub_nav + """
            <section class='section-block panel-card'>
              <h3>ICHRA Setup Application Center</h3>
              <p class='subtitle'>Create an employer first, then initialize and manage their employer-containerized ICHRA setup workspace from here.</p>
            </section>
            """

        if selected_employer_id is None:
            selected_employer_id = visible_employers[0]["id"]
        selected_employer = next((row for row in visible_employers if row["id"] == selected_employer_id), visible_employers[0])
        selected_employer_id = selected_employer["id"]

        artifact = self.get_ichra_application(selected_employer_id)
        if role == "employer" and (not artifact or not selected_employer["ichra_started"]):
            self.start_employer_ichra(user["id"])
            selected_employer = self.get_visible_employer_by_id(user, selected_employer_id) or selected_employer
            artifact = self.get_ichra_application(selected_employer_id)
        artifact_defaults = {
            "desired_start_date": "",
            "service_type": "",
            "primary_first_name": "",
            "primary_last_name": "",
            "primary_email": selected_employer["work_email"],
            "primary_phone": selected_employer["phone"],
            "legal_name": selected_employer["legal_name"],
            "nature_of_business": selected_employer["industry"],
            "total_employee_count": selected_employer["company_size"],
            "physical_state": selected_employer["state"],
            "reimbursement_option": "",
            "employee_class_assistance": "",
            "planned_contribution": "",
            "claim_option": "",
            "agent_support": "",
        }
        if artifact:
            for key in artifact_defaults:
                artifact_defaults[key] = artifact[key] if artifact[key] else artifact_defaults[key]

        status_label = "Open"
        if selected_employer["application_complete"]:
            status_label = "Submitted"

        token_status = (artifact["access_token_status"] if artifact and artifact["access_token_status"] else "active")
        is_locked = token_status == "locked"
        renew_block = ""
        if is_locked and role in {"super_admin", "admin", "broker"}:
            renew_block = f"""
            <form method='post' action='/applications/ichra/renew' class='inline-form'>
              <input type='hidden' name='employer_id' value='{selected_employer_id}' />
              <button type='submit'>Renew Workspace Token</button>
            </form>
            """
        elif is_locked:
            renew_block = "<p class='subtitle'>Workspace token is locked after submission. Ask an admin or broker to reopen it.</p>"

        employer_options = "".join(
            f"<option value='{row['id']}' {'selected' if row['id'] == selected_employer_id else ''}>{html.escape(row['legal_name'])} ({html.escape(row['portal_username'])})</option>"
            for row in visible_employers
        )

        return artifact_sub_nav + f"""
        <section class='section-block panel-card artifact-center'>
          <h3>ICHRA Setup Workspace</h3>
          <p class='subtitle'>Every ICHRA setup workspace is employer-owned. Start it once, save drafts anytime, and submit only when complete.</p>
          <div class='artifact-meta-grid'>
            <article><h4>Employer</h4><p>{html.escape(selected_employer['legal_name'])}</p></article>
            <article><h4>Application Status</h4><p>{status_label}</p></article>
            <article><h4>Access Token</h4><p>{'Locked' if is_locked else 'Active'}</p></article>
            <article><h4>Portal User</h4><p>{html.escape(selected_employer['portal_username'])}</p></article>
          </div>
          {renew_block}

          <form method='get' action='/' class='inline-form artifact-picker'>
            <input type='hidden' name='view' value='application' />
            <label>Switch employer application
              <select name='employer_id'>{employer_options}</select>
            </label>
            <button type='submit' class='secondary'>Load Application</button>
          </form>

          <form method='post' action='/applications/ichra/save' class='form-grid artifact-form'>
            <input type='hidden' name='employer_id' value='{selected_employer_id}' />
            <fieldset {'disabled' if is_locked else ''}>
            <h4>Plan & Contact</h4>
            <label>Desired ICHRA Start Date *<input type='date' name='desired_start_date' value='{html.escape(artifact_defaults['desired_start_date'])}' required /></label>
            <label>Service Type *
              <select name='service_type' required>
                <option value=''>Select service type</option>
                <option value='ICHRA Documents + Monthly Administration' {'selected' if artifact_defaults['service_type'] == 'ICHRA Documents + Monthly Administration' else ''}>ICHRA Documents + Monthly Administration</option>
                <option value='ICHRA Documents Only' {'selected' if artifact_defaults['service_type'] == 'ICHRA Documents Only' else ''}>ICHRA Documents Only</option>
              </select>
            </label>
            <label>Primary Contact First Name *<input name='primary_first_name' value='{html.escape(artifact_defaults['primary_first_name'])}' required /></label>
            <label>Primary Contact Last Name *<input name='primary_last_name' value='{html.escape(artifact_defaults['primary_last_name'])}' required /></label>
            <label>Primary Contact Email *<input type='email' name='primary_email' value='{html.escape(artifact_defaults['primary_email'])}' required /></label>
            <label>Primary Contact Phone *<input name='primary_phone' value='{html.escape(artifact_defaults['primary_phone'])}' required /></label>

            <h4>Employer Profile Inputs</h4>
            <label>Legal Business Name *<input name='legal_name' value='{html.escape(artifact_defaults['legal_name'])}' required /></label>
            <label>Nature of Business *<input name='nature_of_business' value='{html.escape(artifact_defaults['nature_of_business'])}' required /></label>
            <label>Total Employee Count *<input name='total_employee_count' value='{html.escape(artifact_defaults['total_employee_count'])}' required /></label>
            <label>Physical State *<input name='physical_state' value='{html.escape(artifact_defaults['physical_state'])}' required /></label>
            <label>Reimbursement Option *<input name='reimbursement_option' value='{html.escape(artifact_defaults['reimbursement_option'])}' required /></label>
            <label>Employee Class Assistance *<input name='employee_class_assistance' value='{html.escape(artifact_defaults['employee_class_assistance'])}' required /></label>
            <label>Planned Contribution *<input name='planned_contribution' value='{html.escape(artifact_defaults['planned_contribution'])}' required /></label>
            <label>Claim Option *<input name='claim_option' value='{html.escape(artifact_defaults['claim_option'])}' required /></label>
            <label>Agent Support *<input name='agent_support' value='{html.escape(artifact_defaults['agent_support'])}' required /></label>
            <div class='artifact-actions'>
              <button type='submit' name='artifact_action' value='save' class='secondary'>Save Draft</button>
              <button type='submit' name='artifact_action' value='submit'>Submit Application</button>
            </div>
            </fieldset>
          </form>
        </section>
        """

    def render_new_employer_setup_form(self):
        return """
        <section class='section-block panel-card public-setup-card'>
          <h3>New Employer Setup Form</h3>
          <p class='subtitle'>This is the same intake form available on the login page as the public entry point for new employers.</p>
          <form method='post' action='/signup' class='form-grid'>
            <label>Employer Legal Name <input type='text' name='legal_name' required /></label>
            <label>Contact Name <input type='text' name='prospect_name' required /></label>
            <label>Work Email <input type='email' name='prospect_email' required /></label>
            <label>Phone <input type='text' name='prospect_phone' /></label>
            <button type='submit'>Submit Employer Request</button>
          </form>
        </section>
        """

    def render_new_broker_setup_form(self):
        return """
        <section class='section-block panel-card public-setup-card'>
          <h3>New Broker Setup Form</h3>
          <p class='subtitle'>Public entry point for prospective brokers. Brokers can create employers after login, and admins assign teams afterward.</p>
          <form method='post' action='/signup/broker' class='form-grid'>
            <label>Brokerage Name <input type='text' name='brokerage_name' required /></label>
            <label>Contact Name <input type='text' name='contact_name' required /></label>
            <label>Work Email <input type='email' name='work_email' required /></label>
            <label>Phone <input type='text' name='phone' /></label>
            <button type='submit'>Submit Broker Request</button>
          </form>
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
