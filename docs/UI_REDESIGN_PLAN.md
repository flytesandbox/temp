# UI Redesign Plan

## Phase 0 Discovery (Current State)
- Framework/runtime: Python WSGI monolith (`wsgiref`), single entry app in `app.py`.
- Data layer: SQLite with direct SQL access and migrations in `TaskTrackerApp.init_db`.
- Routing: path-based request router in `TaskTrackerApp.__call__`; screen switching uses `?view=` query param.
- Auth/session: signed cookie session (`session`) + flash cookie.
- UI composition: server-rendered HTML strings in `render_login`, `render_dashboard`, and view helper methods.
- Styling: one global CSS file (`static/styles.css`).
- Tests: Python unittest/pytest coverage in `tests/test_app.py`.

## Target Information Architecture
- First Run (`onboarding` state): quick avatar + shuffle preference.
- Home (`view=home`/`dashboard`): card-first modules for recently used, favorites, recommended.
- Library (`view=library`): employer/applications collection.
- Primary Action (`view=action`): ICHRA setup workspace form flow.
- Confirmation/Recap (`view=history` + success flash on submit): post-action confirmation and recent notifications.
- Profile (`view=profile`): avatar, role summary, contribution stats.
- Settings (`view=settings`): account, theme, preferences toggles.

## User Workflow
1. Login.
2. First run onboarding appears until completed.
3. User lands in Home with personalized module order.
4. User enters Primary Action to create/update ICHRA application.
5. Save/submit shows confirmation feedback and can move to History.
6. Library exposes favorites/history-like collections.
7. Profile/Settings allow persistent personalization adjustments.

## Design System Plan
- Tokens: color palette variants, spacing, radii, shadows, motion, typography.
- Components:
  - `AppShell` (card container + sticky bottom nav)
  - `Header` (title, avatar, actions)
  - `BottomNav` (5 items)
  - `Card/Tile`, `SectionHeader`, `ListRow`, `Toggle/check-row`
  - `PrimaryActionButton`
  - Modal/Sheet styles
  - Empty/loading support through panel-card + subtitle conventions

## Migration Approach
- Keep existing backend routes/actions intact.
- Replace render shell and navigation structure in `render_login` and `render_dashboard`.
- Add user personalization persistence columns and deterministic seed initialization.
- Keep existing functional panels (employers/application/team/logs) but remap them into new IA views.
- Update tests to validate new IA/personalization contract while preserving critical workflows.
