# ADR 0001 — Staging beside prod on core, tagged releases

- **Status:** accepted
- **Date:** 2026-10-08

## Context
Talon's prod on core (`:8088`) was the only environment. The next phase, the
managed-SOC log platform (ADR 0002), is large and will touch the API, UI and
data. That work needs somewhere to run against realistic data without risking
prod or Eagle Eye, which shares prod's data volume.

## Decision
1. **One compose file, two identity files.** `deploy/env/prod.env` and
   `deploy/env/staging.env` set names, ports, volume and scheduler. Every
   default in the compose file is the prod value.
2. **Staging is fully separate on the same host:** its own checkout
   (`~/eagle-talon-staging`), compose project, containers, ports (8098, and
   8100 on loopback) and volume. It never mounts `eagle-talon-data`.
   `deploy.sh` refuses if it would.
3. **Staging data is a copy of prod**, refreshed on demand by
   `seed-staging-db.sh` through a read-only backup. Scheduled monitoring is off
   in staging so external scans and the shared NVD quota aren't doubled.
4. **Prod deploys only from a clean `vX.Y.Z` tag** matching `VERSION`, with an
   automatic DB backup first. Branches: `staging` for integration, `main` for releases.
5. **Docs live in the repo** and change in the same commit as the code:
   `CHANGELOG.md`, `docs/RUNBOOK.md`, `docs/ARCHITECTURE.md`, ADRs.

## Consequences
- Staging and prod share core's CPU, disk and Tailscale identity. A heavy
  staging job can slow prod. That's acceptable at PoC scale; revisit before the
  SOC pipeline ingests at volume.
- There is no staging Eagle Eye yet. Eye still syncs only with prod. Add an
  Eye staging instance on the staging volume when Eye changes need testing
  against Talon changes.
- The rollback to `v0.1.0` uses the old `docker compose up` path, because that
  tag predates `deploy.sh`.
