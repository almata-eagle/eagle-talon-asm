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

### Changed
- `docker-compose.yml`, the nginx template and the API Dockerfile take names,
  ports and the volume from environment variables. Every default is the prod
  value, so prod's rendered config is unchanged apart from new informational
  env vars.
- Removed the obsolete `version:` key from `docker-compose.yml`.

## [0.1.0] - 2026-08-31
Baseline: the code prod ran before staging existed (commit `954da2d`).
Passive ASM scanning, Talon Scope radar, multi-client workspaces, CSV bulk
upload, NVD CVE correlation, scheduled domain monitoring with change alerts,
EN/JP UI.
