### Added
- Routing: Support for service-level Routing Mode (Cloudflare or VPS/WireGuard).
- MQTT: Expanded service sensor with additional attributes (Router, Service, Target, Prefix, Current URL, Health, and Routing Mode).
- MQTT: Added automatic discovery cleanup when a service is deleted.
- MQTT: Added immediate discovery/state updates when a service is created or edited.

### Changed
- Updated `redis` to 7.3.0 and `python-dotenv` to 1.2.2 in `requirements.txt`.
- Added a note to `README.md` clarifying that the project was created with AI assistance.
