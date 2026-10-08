# Changelog

All notable changes to Eagle Talon. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). The release process is in
[docs/RUNBOOK.md](docs/RUNBOOK.md).

Every change merged to `staging` adds a line under **Unreleased**.

## [Unreleased]

### Added
- Staging environment beside prod on core (UI `:8098`, API `127.0.0.1:8100`,
  volume `eagle-talon-staging-data`). Driven by `deploy/env/staging.env`.
- `deploy/deploy.sh <prod|staging>`: one command to build and restart an
  environment, with guard rails. Staging cannot use prod's names, ports or
  volume. Prod deploys only from a clean `vX.Y.Z` tag, with an automatic DB
  backup first. `--dry-run` previews the config.
- `deploy/backup-db.sh`: online, read-only, integrity-checked SQLite backups
  with retention.
- `deploy/seed-staging-db.sh`: refreshes staging with a copy of prod data,
  backing up staging first.
- `VERSION` file and `GET /api/version` (version, git commit, environment,
  scheduler state).
- Version chip in the top bar. Non-prod environments show an amber
  `STAGING · vX.Y.Z` chip, a striped top edge, and a `[STAGING]` tab title.
- `EAGLE_TALON_SCHEDULER=off` switch. Staging uses it so it doesn't re-scan
  every client domain or spend the shared NVD quota.
- Docs: `docs/RUNBOOK.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`,
  decision records in `docs/adr/`, and `CLAUDE.md`.
- **SOC Phase 1, log collector** (`soc/`): Vector 0.58 receives FortiGate
  syslog (5516/udp) and Suricata `eve.json`, normalizes everything to one
  event format, and writes a 30-day hot store on Core plus a 400-day gzip
  archive on the NAS `logs` share. Includes `soc/preflight.sh` (read-only
  readiness check), `soc/deploy-collector.sh` (deploy plus self-test),
  `soc/retention.sh`, and Vector unit tests. See `docs/SOC-COLLECTOR.md` and
  ADR 0003. The collector runs as `eddy`; it joins the `eve.json` group only
  when the file isn't world-readable, and never joins `root`.
- **Events view** (top bar → Events, EN/JP): searches the SOC hot store with
  a time range, source, allowed/blocked and direction filters, and free text
  (IP, country, port, signature, app). It shows headline tiles (click to
  filter), a blocked-vs-total timeline, top remote countries and most-hit
  inbound ports (click to search), and a collector freshness indicator. Click
  a row to see the full original log. It auto-refreshes every 30 s, and the
  collector's self-test events are hidden.
- API: `GET /api/soc/status`, `/api/soc/events`, `/api/soc/summary`. These are
  read-only, validated inputs, queried in place with DuckDB
  (`backend/soc_logs.py`).
- Tests: `backend/tests/test_soc_logs.py` (20 tests, including
  injection-shaped input and API validation).

### Fixed
- `backup-db.sh` labels each backup with the version the environment is
  actually running (from `/api/version`, or `pre-0.2.0`), not the version in
  the checkout running the script.
- `seed-staging-db.sh` creates the staging volume with Compose's labels, so
  `deploy.sh staging` no longer warns that the volume "already exists".

### Changed
- `docker-compose.yml`, the nginx template and the API Dockerfile take names,
  ports and the volume from environment variables. Every default is the prod
  value, so prod's rendered config is unchanged apart from new informational
  env vars.
- Removed the obsolete `version:` key from `docker-compose.yml`.
- The API container mounts the SOC hot store **read-only** at `/soc-hot`, from
  `SOC_HOT_DIR` (set in `env/staging.env`). When it's unset, as in prod until
  v0.3.0, an empty placeholder folder is mounted, and the Events view says
  "not connected".
- Top bar: labels no longer wrap, and spacing tightens below 1640 px and
  1460 px, so nothing is clipped from 1280 px up.
- New dependency: `duckdb==1.5.6`.

## [0.1.0] - 2026-08-31
Baseline: the code prod ran before staging existed (commit `954da2d`).
Passive ASM scanning, Talon Scope radar, multi-client workspaces, CSV bulk
upload, NVD CVE correlation, scheduled domain monitoring with change alerts,
EN/JP UI.
