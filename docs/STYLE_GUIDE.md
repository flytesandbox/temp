# Style Guide

## Brand Direction
Soft retro-tactile product UI: rounded geometry, warm/pastel palette, card-first composition, airy spacing, subtle motion.

## Tokens
- Typography: `--font-body`
- Spacing: `--space-1..--space-6`
- Radii: `--radius-sm`, `--radius-md`, `--radius-lg`, `--radius-pill`
- Elevation: `--shadow-1`, `--shadow-2`
- Motion: `--motion-fast`, `--motion-base`, `--ease-playful`
- Core colors: `--bg`, `--surface`, `--text`, `--muted`, `--accent`, `--accent-2`
- Theme variants: `sunset`, `dawn`, `mint`, `lavender`, `midnight`

## Components
- AppShell: `.app-shell.card`
- Header: `.app-header`
- BottomNav: `.bottom-nav`, `.bottom-item`
- Cards/Tiles: `.panel-card`, `.task-card`
- Section headers: `<h3>` + `.subtitle`
- Toggle row: `.check-row`
- List row: `.status-list li`
- Primary action: `.primary-action` / default button
- Modal/sheet: `.modal`, `.modal-card`, `.modal-backdrop`

## Usage Rules
1. Use panels as primary layout blocks instead of long continuous tables.
2. Keep all key actions reachable from bottom nav or header action.
3. Always surface role, personalization state, and current context in header/banner.
4. Preserve semantic form labels and keyboard accessibility.
5. Use theme variables only (avoid hard-coded random colors in markup).
