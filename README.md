# Monolith Task Tracker

Full-stack Python monolith for team operations and ICHRA onboarding, now redesigned with a card-first mobile-inspired UX and deterministic per-user personalization.

## Run locally

```bash
python app.py
```

Open `http://localhost:8000`.

## Test

```bash
python -m pytest -q
```

## UI/UX Redesign Highlights
- Full IA refresh with bottom navigation and app-shell layout.
- First-run onboarding (avatar + preference toggle).
- Home, Library, Action, History, Profile, and Settings experiences.
- Deterministic personalization per user:
  - theme variant
  - module order
  - vibe pack

## Verify "different user experience"
1. Login as `alex` (`user`) and complete first-run onboarding.
2. Logout, login as `sam` (`user`).
3. Compare:
   - header banner values (theme/vibe/seed)
   - home section ordering
   - accent/theme treatment
4. Log out/in again to confirm consistency persists.
