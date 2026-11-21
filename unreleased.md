### Added
- Tests: Added `test_orchestration.py` covering UniFi port string/int comparison, Cloudflare failure rollback, multi-service VPS teardown preservation, MQTT command dispatch, VPS host key invalidation via API, and bogus `X-API-Key` 2FA bypass prevention.

### Changed
- Performance: Added a 10-second thread-safe TTL cache for database settings in `database.py` (auto-invalidated on writes) and proactive background warming of UniFi/public IP caches in `health_check_loop()`.
- Logging: Migrated all remaining `print()` statements in `main.py` and `mqtt_handler.py` to structured `logger.*` calls so operational events appear in both stdout and `/app/data/app.log` (in-app Logs viewer).
- CI: Removed duplicate `.github/workflows/docker-dev.yml` workflow (already handled by `docker-image.yml`).
- Cleanup: Deduplicated `showToast()` and `getCsrfToken()` out of `templates/login.html` into `static/js/main.js`.

### Fixed
- Security (High): Validated `X-API-Key` against the database in `check_2fa_enforcement()` so arbitrary/bogus `X-API-Key` headers cannot bypass global 2FA enforcement on `@login_required` `/api/*` routes.
- Security (High): Eliminated stored XSS sink in API key delete button in `templates/settings.html` by switching from inline JS string interpolation to `data-*` attributes.
- Security (Medium): Added `MAX_CONTENT_LENGTH` (2 MB) upload cap and synced `VPS_SSH_HOST_KEY` invalidation + MQTT reload across `/api/settings` and `/api/settings/restore`.
- Bug (High): Fixed Settings "Test Connection" buttons (UniFi, Cloudflare, VPS SSH) being blocked client-side when secret inputs were left blank to use stored encrypted credentials.
- Bug (Medium): Fixed `edit_service()` cleaning up old Traefik/Cloudflare routes before updating routing identifiers on an active service, and guarded missing `active_services` in `templates/index.html`.
