# Changelog

All notable changes to ProbeDeck are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-09-23

### Fixed
- **Maintenance windows now respect a configurable timezone** (`PROBEDECK_TZ`).
  Browser wall-clock input was silently treated as UTC, firing windows at the
  wrong hour for non-UTC operators. One-off windows convert to UTC on input and
  display back in local time; daily windows compare local time-of-day.
- **SQLite runs in WAL mode with a busy timeout**, so the background sampler,
  web handlers, and the websocket tail no longer race to "database is locked".
- In-flight probe subprocesses are killed on shutdown instead of being orphaned.

### Added
- Sample retention is now age- and count-based (`PROBEDECK_RETENTION_DAYS`,
  `PROBEDECK_MAX_SAMPLES`) instead of a fixed 200 rows, so uptime and the detail
  chart look back days rather than ~3h for a 60s monitor.
- `/healthz` endpoint plus a Docker Compose healthcheck.
- Per-IP login throttling with lockout after repeated failures.
- `PROBEDECK_SECURE_COOKIE` to flag the session cookie `Secure` behind TLS.
- `nmap` "extra" args restricted to a scanning allowlist (blocks file-writing,
  host-list and NSE/script flags).
- `ruff` lint config + CI lint job, FastAPI `TestClient` route tests, and
  pinned `tzdata` so `PROBEDECK_TZ` works on slim base images.

## [0.1.0]

- Initial release.
