# Monolith Task Tracker

A simple monolith Python app with two login users. Each user can mark a shared task complete and immediately see the other user's status.

## Features

- Session-based login/logout.
- Two seeded users (`alex`, `sam`) with password `password123`.
- One shared deployment-readiness task.
- Shared completion status persisted in SQLite.
- Clean, styled UI for demo/test flow.
- No external runtime dependencies (stdlib only).

## Run locally (or in GitHub Codespaces)

1. Start app:
   ```bash
   python app.py
   ```
2. Open `http://localhost:8000`.

## Test

```bash
python -m unittest tests/test_app.py
```

## Deploy to Linode (quick path)

1. Provision a Linode with Ubuntu.
2. Install Python + git, clone this repo.
3. Set `SECRET_KEY` env var.
4. Run `python app.py` (or run behind a process manager + nginx).
5. Visit live URL and run the two-user validation.

A detailed step-by-step handoff log template is in [`DEPLOYMENT_LOG.md`](DEPLOYMENT_LOG.md).

## 502 Bad Gateway troubleshooting

If nginx is up but you still get `502`, check the app service first:

```bash
systemctl status monolith-task-tracker --no-pager
journalctl -u monolith-task-tracker -n 100 --no-pager
```

If you see `can't open file '/opt/monolith-task-tracker/app.py'`, your systemd `WorkingDirectory` / `ExecStart` path does not match the folder where this repo was cloned (for example, some setups clone into `/opt/monolith-task-tracker/temp`). Update the unit file path, then reload and restart the service. Detailed commands are documented in [`DEPLOYMENT_LOG.md`](DEPLOYMENT_LOG.md).
