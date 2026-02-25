# NEW_UI Route Mapping Inventory (Phase 0)

| Route | Current Template | Pattern(s) | Primary Components Observed | NEW_UI Plan |
|---|---|---|---|---|
| `/login` | AuthLayout | CreateEditForm | labeled inputs, primary submit, secondary links | keep legacy now (bridge fallback) |
| `/` `view=dashboard/home` | DashboardLayout | ListPage + ReportsOrAnalytics | cards, nav links, status blocks, notifications | converted for **Super Admin dashboard** to NEW_UI shell |
| `/` `view=application` | FormLayout | CreateEditForm | forms, field groups, state badges, submit buttons | keep legacy now (bridge fallback) |
| `/` `view=users` | SettingsLayout | RoleUserManagement | table rows, role badges, create/update forms | keep legacy now (bridge fallback) |
| `/` `view=employers` | MasterDetailLayout (table + settings links) | ListPage + RoleUserManagement | data table, filters/scope tabs, action links | keep legacy now (bridge fallback) |
| `/` `view=settings` | SettingsLayout | CreateEditForm | profile form, style form, preference toggles | keep legacy now (bridge fallback) |
| `/` `view=system` (+ `system_view`) | SettingsLayout | ListPage | sub-nav, permissions matrix, logs/devlog table | keep legacy now (bridge fallback) |
| `/employers/settings` | FormLayout | DetailPage + CreateEditForm | edit form card, ownership selects, action footer | keep legacy now (bridge fallback) |

## Notes
- The app uses a query-driven dashboard router (`/?view=...`) rather than many path routers.
- NEW_UI entry point is now enabled via `uiMode` (`LEGACY`/`NEW`) with one shell mounted at a time.
- Non-converted views intentionally bridge to LEGACY_UI until each page is migrated.
