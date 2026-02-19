# Employer Onboarding Monolith

A simple Python WSGI app that reenvisions a multi-step marketing style form as an internal **Employer onboarding app**.

## Features

- Session login/logout with seeded users: `alex`, `sam`, `admin`.
- New onboarding form that creates a new **Employer** account after form completion.
- Every created Employer gets an assigned starter onboarding task.
- Role restrictions:
  - `user` and `super_admin` can submit the onboarding form.
  - `employer` is read-only and cannot create or modify anything.
  - `employer` users only see employers created by their creator user.
- SQLite persistence with stdlib only.

## Run

```bash
python app.py
```

Open http://localhost:8000.

## Test

```bash
python -m unittest tests/test_app.py
```
