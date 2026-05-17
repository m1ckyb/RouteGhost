### Added
- MQTT: Added support for rotating service URLs from Home Assistant via a new "Rotate URL" button entity. (Note: Subdomain rotation now preserves the current firewall port).
- MQTT: Added global MQTT buttons for Home Assistant: "Rotate Firewall Port", "Turn All Services ON", and "Turn All Services OFF".
- Settings UI: Added a "Test Connection" button for UniFi integration to validate credentials.

### Changed
- Settings UI: Reorganized Firewall Controller section to group action buttons at the bottom for better clarity.
- Dependencies: Updated `redis`, `requests`, `gunicorn`, `Flask-WTF`, and `paramiko` to newer versions in `requirements.txt`.

### Fixed
- UniFi: Improved API resilience by implementing robust retry logic for rate limits (429 errors) and optimized URL rotation to eliminate redundant controller requests.
- MQTT: Fixed a bug where global MQTT commands (Rotate Port, All On/Off) were ignored due to a topic length check.
- MQTT: Refactored URL rotation to feel more atomic and suppressed redundant "Shutdown/Enabling" banners during the rotation process.
