# Deployment Log (Codespaces ➜ Linode)

Use this file as a running log you can paste into ChatGPT between PRs.

## Metadata

- Date:
- Branch/PR:
- Commit SHA:
- Tester:

## Phase 1: Codespaces Validation

- [ ] Environment booted.
- [ ] `python -m unittest tests/test_app.py`
- [ ] `python app.py`
- [ ] Logged in as `alex` and marked task complete.
- [ ] Logged in as `sam` and verified Alex completion.
- [ ] Marked task complete as `sam`.
- [ ] Verified both users show **Completed**.

### Notes

- Issues:
- Fixes:
- Remaining risks:

## Phase 2: Linode Deployment

### Server setup

- [ ] Linode created + SSH working.
- [ ] System packages installed.
- [ ] Repo cloned/pulled.
- [ ] Python env configured.
- [ ] Environment variables set (`SECRET_KEY`, etc.).

### App setup

- [ ] (Optional) dependencies installed.
- [ ] App launched under process manager.
- [ ] Reverse proxy configured.
- [ ] HTTPS enabled.

### Live validation

- [ ] Opened live site.
- [ ] `alex` login + complete.
- [ ] `sam` sees alex completion.
- [ ] `sam` complete + both visible.

### Notes

- Live URL:
- Performance observations:
- Errors/log snippets:
- Next PR scope:
