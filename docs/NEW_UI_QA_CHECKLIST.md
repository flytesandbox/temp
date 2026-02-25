# NEW_UI QA Checklist Notes

## Breakpoint checks
- Mobile (`<=640`): NEW super-admin dashboard cards stack into one column; header actions wrap.
- Tablet (`641-1024`): KPI cards auto-fit two-ish columns based on available width.
- Desktop (`>=1025`): card grid uses multi-column layout and preserves generous whitespace.

## Accessibility checks
- UI mode toggle includes `role="switch"` and `aria-label="New UI"`.
- Breadcrumb in NEW_UI header includes `aria-label="Breadcrumb"`.
- Focus styles are visible for the toggle and NEW_UI nav rows.
- Toggle interaction remains keyboard reachable because it is a native checkbox in a form.

## Fallback checks
- If NEW_UI render path throws, server auto-resets to `LEGACY`, logs `ui_mode_fallback`, and shows banner flash.
- Non-super-admin users are forced to LEGACY even if `ui_mode` is set to `NEW`.
- Non-converted routes under NEW mode fall back to LEGACY render path without route breakage.

## Persistence checks
- Preferred mode persisted on user row (`users.ui_mode`) and survives page refresh/re-login.

## Scope checks
- Toggle appears only for super admins and only on dashboard/home header.
- Other roles do not see or control UI mode switch.
