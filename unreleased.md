### Added
- Architecture: Extracted Redirect Service (`/redir/<slug>`, `/redirects`, `/api/redirects*`) into its own Flask Blueprint module (`redirects.py`) with shared payload validation.

### Changed
- Security: Scoped `X-API-Key` CSRF exemption in `check_csrf_protection()` strictly to `/api/*` routes (no longer applies to `/redir/*` or `/auth/*` form routes) and respected `WTF_CSRF_ENABLED`.
- Stats: Added `redirects` count to `db.get_db_stats()` (`/api/system` & System Info).

### Fixed
- Redirects: Cleared per-link rate-limit counter upon successful PIN/password unlock so legitimate repeat unlocks are not throttled.
- Redirects: Validated `expires_at` as ISO-8601 on create/update (failing closed on unparseable dates) and rejected embedded credentials (`user:pass@host`) in external redirect URLs.
