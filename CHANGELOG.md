# Changelog

All notable changes to Eagle Talon. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). The release process is in
[docs/RUNBOOK.md](docs/RUNBOOK.md).

Every change merged to `staging` adds a line under **Unreleased**.

## [Unreleased]

### Added
- **Talon OT, phase OT-1** (`backend/ot/`, `frontend/ot.html`, guide in
  [docs/OT.md](docs/OT.md)): FRCS assessments against UFC 4-010-06 / NIST SP
  800-82.
  - Engagements (with a marking banner), systems (type, design phase, C-I-A
    impact and who set it), and a checklist worked item by item: status,
    severity, finding, remediation, owner, due date.
  - Import any `.xlsx`/`.csv` checklist. Header row and columns are guessed
    (EN/JA), you confirm the mapping, answers are normalised, and the original
    cells are kept.
  - Export the same layout back with the answers filled in, plus Talon columns,
    a POA&M sheet and a summary; formula injection blocked. Printable report
    (EN/JA).
  - Evidence stored by SHA-256, re-verified on download.
  - Local accounts (admin/assessor/viewer) and an audit log of every change.
  - Its own SQLite file under `/app/data/ot`, never the Talon DB. Inside
    Talon behind `OT_ENABLED=on` (staging on, prod off); standalone for
    on-prem/DDIL with `backend/ot_app.py` and `deploy/ot/docker-compose.yml`.
  - The import wizard opens on the sheet that looks most like a checklist.
  - **Import checklist** on the engagement page: pick an existing system or
    name a new one, and Talon creates it as part of the import.
  - Talon's top bar shows an **OT** button when it's on.
  - New dependency `openpyxl==3.1.5`.
  - nginx allows 30 MB bodies on `/api/ot/`.
- **Known devices** (`backend/soc_assets.py`, new table `soc_assets`): name
  any of your own IPs, set its type and notes, and mark what's normal for it.
  You can choose contacting new countries, large uploads, or allowed inbound
  for a public server. Quieted kinds stop opening cases for that device, and
  its open ones can be closed in the same step (marked 👎, reopenable).
  Attacks from outside can't be quieted. Names show next to the IP in Events,
  summaries, the explainer and the device view. Claude gets them as
  operator-provided context. `GET/PUT/DELETE /api/soc/assets`.
- **"What's happening" summaries** (`backend/soc_insights.py`): the country
  drawer and a new **device view** spell out the pattern in plain words (EN/JA).
  Recognised patterns: one device pinging many servers (VPN or game latency
  checks), reachability pings, internet scanning the firewall blocked, inbound
  traffic that got through, ordinary web traffic, DNS, big uploads,
  threat-listed addresses, and one device behind most of the traffic.
  `GET /api/soc/insights?kind=country|device`.
  Every part of a slice's traffic is described: a mix bar (pings, DNS, web/QUIC,
  Tailscale, VPN, email, SSH, other) plus one sentence per part, so devices
  that do several things at once are fully explained. Load errors are shown
  instead of an empty box.
- **Device view:** click any of your own IPs (in Events, the explainer or a
  summary) to see what that device did: protocols, busiest remote networks,
  countries, firewall outcomes and data.
- **Ask Claude to explain this:** on a country or device, Claude explains the
  aggregated traffic (counts, never raw logs or content) with a verdict and next
  steps, in EN/JA. On demand only, fenced and validated, cached for 30 minutes,
  capped by `SOC_ASK_MAX_PER_HOUR` (default 10). New table `soc_explanations`.
  `POST /api/soc/ask`.
- **Threat intelligence** (see `docs/SOC-INTEL.md` and ADR 0006):
  - Public feeds are downloaded on Core and matched locally, so no address is
    sent out: abuse.ch Feodo Tracker, Spamhaus DROP (v4/v6), the Tor exit
    list, blocklist.de, and ThreatFox when `ABUSECH_AUTH_KEY` is set.
    `backend/soc_intel.py` adds the new tables `ti_indicators` and `ti_feeds`.
  - New detection rule **Known-bad address** (`intel_match`) for *allowed*
    traffic to or from a listed address. It's critical when our host reached a
    malicious address.
  - ⚑ badges on IPs in Events, Cases and the map drawer. On the dashboard,
    a "Known-bad IPs (24h)" KPI, a "Known-bad addresses" panel with feed
    status and a refresh button, red rings on map dots, and callouts when
    feeds stop updating.
  - Claude triage receives the hits as `threat_intel` evidence.
  - **Plain-language explainer:** click any ⚑ badge to see a verdict for that
    traffic, what the list means, which of your devices talked to the address
    and how (7 days), numbered steps, and a link to the source's listing.
    Badges are larger and readable. `GET /api/soc/intel/explain`.
  - API: `GET /api/soc/intel`, `POST /api/soc/intel/refresh`,
    `GET /api/soc/intel/lookup?ip=`, `GET /api/soc/intel/sightings`, `GET /api/soc/intel/explain`.
  - New env: `SOC_INTEL` (on in prod and staging), `SOC_INTEL_FEEDS`
    (staging leaves out Spamhaus), `ABUSECH_AUTH_KEY` (optional).
  - Tests: `backend/tests/test_soc_intel.py` (16), `test_soc_insights.py` (9), `test_soc_assets.py` (5). 105 in total.

- Docs: `docs/OT-DESIGN.md` and ADR 0007 (proposed). Talon OT is a portable,
  offline-first module for FRCS assessments against UFC 4-010-06 and NIST SP
  800-82. Design only, no code yet.

### Changed
- Rule "New country" ignores ping-only contact. VPN apps and games ping
  servers worldwide to measure latency, and that opened dozens of cases.

### Fixed
- Dashboard: when the API can't answer (for example an older API behind a newer
  page), the map, KPIs and callouts say so instead of loading forever.

## [0.5.1] - 2026-10-09
### Fixed
- `deploy.sh prod` stopped silently right after "Backing up the prod DB" when
  prod was still running a release without `/api/version` (v0.1.0):
  `backup-db.sh` exited on the failed version check under `set -e`. It now
  carries on and labels the backup `pre-0.2.0` or `unknown`.
- `deploy.sh` and `backup-db.sh` now print the line that failed instead of
  exiting without a message.

## [0.5.0] - 2026-10-09
First release since the v0.1.0 baseline. It ships roadmap phases 0–3 together:
the staging/release process, the SOC log collector and Events view, cases with
Claude triage (read-only), and the Dashboard. In prod, detection and triage are
switched on in `deploy/env/prod.env`. Staging keeps them on with a smaller
Claude budget (5 triages an hour), so both don't spend the same amount.

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
- **SOC Phase 2, cases and Claude triage (read-only)** — see `docs/SOC-TRIAGE.md` and ADR 0004:
  - Six detection rules (`backend/soc_rules.py`): port scan, repeated login
    attempts, IDS/IPS alert, inbound allowed, large upload, and new country
    (needs 24 h of history). They run every 5 minutes when `SOC_DETECT=on`.
  - Findings merge into **cases** (`backend/soc_cases.py`, new `soc_cases`
    table) by rule and entity while open. Evidence covers each case's whole lifetime.
  - **Claude triage** (`backend/soc_triage.py`): verdict, severity, confidence,
    what happened, why it matters, unknowns, and 2–4 response options (one
    recommended), in English and Japanese, with MITRE ATT&CK ids. It uses a
    forced tool call with a strict schema plus re-validation, and hardened
    prompts (fenced, escaped, truncated, allowlisted evidence; injection
    attempts flagged). There's an hourly budget, re-triage only on growth, and
    a cached system prompt. Nothing is ever executed.
  - **Cases view** (top bar → Cases, EN/JP): severity-sorted list, Claude's
    assessment, option cards, evidence facts and samples, 👍/👎 feedback,
    resolve/reopen, re-triage, engine status, and "Run detection now".
  - API: `/api/soc/engine`, `/api/soc/detect/run`, `/api/soc/cases`,
    `/api/soc/cases/{id}` (+ `/status`, `/feedback`, `/retriage`).
  - `backend/soc_context.md`: the operator-written network description sent to Claude.
  - Tests: `backend/tests/test_soc_cases.py` (23 tests: rules, merging,
    injection fencing, schema validation, budget, failures, API). 43 in total.
- **SOC Phase 3, dashboard (read-only)**: see `docs/SOC-DASHBOARD.md` and ADR 0005.
  - **Dashboard view** (top bar → Dashboard, EN/JP): KPI tiles (open cases by
    severity, new in 24 h, median time to detect, explain and resolve, events
    and blocked in 24 h, sensors reporting).
  - **Global traffic map**: inbound and outbound arcs per remote country, with
    animated flow. Dashed means fully blocked. Hover shows events, bytes, top
    ports and IPs, and a click opens the matching events. It has a range and
    direction filter.
  - **Needs attention** callouts: open cases with Claude's headline and
    recommended option (Open case / View events / Mark resolved), plus
    sensor and system problems such as a silent IDS or a missing log store,
    each with steps to fix.
  - **MITRE ATT&CK heatmap** by tactic from triaged cases, and a top remote
    countries table.
  - **Interactive map**: zoom (wheel, pinch, double-click, + / − / reset),
    drag to pan, country labels when zoomed in, and hover to highlight a
    country's arcs. Clicking a country, arc, dot or table row opens a
    **country details drawer** with totals per direction, an activity timeline,
    related cases, top remote IPs and ports, and the latest events (click one
    to see all its fields). Every item there links on to Events or Cases.
  - API: `GET /api/soc/map`, `GET /api/soc/map/country`, `GET /api/soc/dashboard` (`backend/soc_dashboard.py`).
  - Country lookup (`backend/soc_geo.py`) and map outlines are generated
    offline from Natural Earth by `tools/build-world-map.js` and committed,
    so nothing is fetched at runtime.
  - DB: new `soc_cases.resolved_at` column (additive migration), set when a
    case is resolved, for MTTR.
  - Tests: `backend/tests/test_soc_dashboard.py` (32 tests). 75 in total.

### Fixed
- Top bar: the domain search box could shrink to nothing and cover the
  theme button (at 1280–1366 px). It now keeps a minimum width, clips its
  contents, and the compact mode also re-checks after the client list loads.
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
- Top bar: switches to a compact form (logo plus icon buttons with tooltips)
  only when it would overflow. This handles Japanese labels at any width.
- New dependency: `anthropic==1.12.1`. New env (prod defaults off):
  `SOC_DETECT`, `SOC_DETECT_INTERVAL_S`, `SOC_TRIAGE`, `SOC_TRIAGE_MODEL`,
  `SOC_TRIAGE_MAX_PER_HOUR`, and `ANTHROPIC_API_KEY` (from `secrets.env`).

## [0.1.0] - 2026-08-31
Baseline: the code prod ran before staging existed (commit `954da2d`).
Passive ASM scanning, Talon Scope radar, multi-client workspaces, CSV bulk
upload, NVD CVE correlation, scheduled domain monitoring with change alerts,
EN/JP UI.
