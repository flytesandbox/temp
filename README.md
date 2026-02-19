# Monolith Task Tracker

A simple monolith Python app with shared task tracking, user settings, super-admin user management, and an added Employer onboarding workflow.

## Features

- Session-based login/logout.
- Seeded users (`alex`, `sam`) and super admin (`admin`).
- Shared deployment-readiness task and team completion status.
- User profile updates and dashboard style preferences.
- Super admin user creation and update controls.
- Added Employer onboarding form that creates Employer accounts after form completion.
- Employer-role accounts are read-only and only see employers created by their manager/creator user.
- SQLite persistence with stdlib only.

## Run locally

```bash
python app.py
```

Open `http://localhost:8000`.

## Test

```bash
python -m unittest tests/test_app.py
```
