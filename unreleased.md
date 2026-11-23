### Added
- Redirect Service (`/redir/<slug>`): Added built-in short-link & dynamic service redirect manager (`/redirects` UI + `/api/redirects` CRUD API) supporting static external URLs with custom or auto-generated slugs, dynamic RouteGhost service redirects that automatically follow rotating URLs, optional PIN/password protection with rate-limited unlock gate, optional expiration timestamps, hit counters, and `Cache-Control: no-store`.

### Changed
- Dependencies: Bumped Docker base image (`python:3.13-alpine` → `python:3.15-alpine`) and `pyotp` (`2.10.0` → `2.12.1`).

### Fixed
