### Added
- Security: Symmetric Fernet encryption at rest (`crypto_utils.py`) for sensitive settings (`CF_API_TOKEN`, `UNIFI_PASS`, `REDIS_PASS`, `VPS_SSH_KEY`, `WG_PRIVATE_KEY`, `MQTT_PASS`, `DISCORD_WEBHOOK_URL`) and TOTP secrets, with automatic migration of existing plaintext values.
- Tests: Added `test_audit_fixes.py` covering registration lockdown, password-change verification, reset-password IDOR protection, secret encryption/redaction, SSRF validation, 2FA API enforcement, and Redis empty-clear handling.

### Changed
- Dependencies: Bumped python dependencies (`python-dotenv` 1.2.4, `gunicorn` 27.0.1, `webauthn` 3.0.1, `paramiko` 5.1.0, `paho-mqtt` 2.2.0).
- Security: Settings page no longer echoes stored plaintext secrets into HTML inputs; `/api/settings/backup` omits sensitive secrets by default.
- Performance: Replaced per-connection `PRAGMA journal_mode=WAL` with one-time init, switched `get_status()` to Redis `mget`, replaced blocking Redis `KEYS` with `scan_iter`, tailed `/api/logs` to last 200KB, and moved network probes/notifications outside `_cache_lock`.
- Docker: Pinned base image to `python:3.13-alpine` and wired `ARG PUID`/`PGID` into user creation.
- Cleanup: Removed orphaned templates (`api_keys.html`, `system.html`), deduplicated `showToast()` into `static/js/main.js`, and replaced deprecated `datetime.utcnow()` and `paho-mqtt` 1.x `Client()` calls.

### Fixed
- Security (Critical): Closed open WebAuthn registration in `/auth/register/begin` and `/auth/register/complete` once any user exists (with atomic lock guard).
- Security (Critical): Restricted `/api/users/<username>/reset-password` to session-authenticated owners only (removed API key access and cross-user IDOR).
- Security (High): Required `current_password` verification in `/auth/password/change` when a password is already set, and enforced global `ENFORCE_2FA` on session-authenticated `/api/*` endpoints.
- Security (High): Added `ProxyFix` for accurate client IP rate limiting behind reverse proxies, synchronized `LOGIN_ATTEMPTS` with `_cache_lock`, added unique ZSET members in Redis rate limiting, validated all resolved IPs in `validate_target_url()`, disabled redirects in backend diagnostics, and restricted `/api/notifications/test` to Discord webhook URLs.
- Reliability: Removed duplicate `Tee` + `RotatingFileHandler` log writer so `logging_config.py` rotates `app.log` cleanly without double-logging.
- Reliability: Fixed UniFi `toggle_unifi()` port `str` vs `int` comparison, added UniFi firewall rollback if Cloudflare DNS creation fails, preserved shared VPS port 443/WireGuard when other VPS services remain active, guarded `WG_CLIENT_ADDRESS`/`count_active_routers()`/`cf_request()`/`api_clear_redis_routes()` against crashes, fixed MQTT test thread leak, and respected `UNIFI_VERIFY_SSL` across all UniFi sessions.
