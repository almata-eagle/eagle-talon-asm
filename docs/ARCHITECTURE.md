# Eagle Talon — Architecture (as of v0.2.0-dev, SOC Phases 1–3 in staging)

Eagle Talon is the operator console of the Eagle platform. Eagle Eye
(`almata-eagle/eagle-eye`) is the client-facing portal and shares Talon's data.

## Runtime on core

```
Browser ──Tailscale──► nginx (eagle-talon-web, :8088)
                         ├─ /        → frontend/index.html (static, no build step)
                         └─ /api/*   → FastAPI (eagle-talon-api, :8000)
                                         ├─ scanner.py    passive recon
                                         ├─ techstack.py  tech fingerprint → NVD CVEs
                                         ├─ monitoring scheduler thread (60s tick)
                                         └─ SQLite /app/data/eagle_talon.db
                                                 │  Docker volume eagle-talon-data
Eagle Eye API (:8001) ── mounts the same volume ─┘  (read-write, bidirectional sync)
```

Both containers use `network_mode: host`. Tailscale's netfilter rules on core
leave Docker's bridge without NAT egress, so nginx reaches the API on
`localhost`. Because everything shares the host's port space, each
environment needs its own ports. That's why staging uses 8098 and 8100. See
[adr/0001](adr/0001-staging-and-release-process.md).

## SOC log pipeline (Phase 1)

```
FortiGate ──udp/5516──┐
Suricata eve.json ────┴─► eagle-soc-collector (Vector) ─┬─► ~/eagle-soc/hot        (Core, 30 days)
                                                        └─► /mnt/nas/logs/eagle-soc/archive (NAS, 400 days)
```
Detection rules run over the same hot store every 5 minutes (Phase 2) and
turn findings into **cases**, which Claude explains (read-only). See
[SOC-TRIAGE.md](SOC-TRIAGE.md) and [adr/0004](adr/0004-cases-and-claude-triage.md).
The **Dashboard** (Phase 3) aggregates the same hot store and the cases
into a traffic map, callouts and KPIs. See [SOC-DASHBOARD.md](SOC-DASHBOARD.md)
and [adr/0005](adr/0005-dashboard-and-offline-geo.md).
Talon's **Events** view reads the hot store through `backend/soc_logs.py`. It's
mounted read-only and queried in place with DuckDB, with no database server.
One collector per host, shared by staging and prod. The event format, deploy
and FortiGate setup are in [SOC-COLLECTOR.md](SOC-COLLECTOR.md); the reasoning
is in [adr/0003](adr/0003-log-collector-and-storage.md).

## Components

| Part | File | Notes |
|---|---|---|
| API | `backend/main.py` | FastAPI. Workspaces (clients), scans, monitors, alerts, bulk CSV jobs, mock portfolio, `/api/version`. |
| Scanner | `backend/scanner.py` | Passive only: DNS, CT logs (crt.sh), TLS metadata, HTTP security headers, RDAP. No port sweeps or probing, so it is legal against third-party domains. |
| CVE correlation | `backend/techstack.py` | NVD API with `virtualMatchString` (not `cpeName`) for version ranges. `NVD_API_KEY` from secrets. |
| UI | `frontend/index.html` | Single file, vanilla JS. Talon Scope radar, log view, report drawer, EN/JP i18n, monitoring page. |
| Web | `deploy/nginx.conf.template` | Ports filled from `NGINX_PORT` and `API_PORT` at container start. |
| SOC search | `backend/soc_logs.py` | Read-only DuckDB queries over the hot store (mounted at `/soc-hot`). `/api/soc/status`, `/api/soc/events`, `/api/soc/summary`. |
| SOC cases | `backend/soc_rules.py`, `soc_cases.py`, `soc_triage.py`, `soc_context.md` | Detection rules → cases (SQLite `soc_cases`) → Claude triage. Read-only. See [SOC-TRIAGE.md](SOC-TRIAGE.md). |
| SOC dashboard | `backend/soc_dashboard.py`, `soc_geo.py`, `soc_geo_countries.json`, `frontend/world-110m.json` | Traffic map, callouts, MTTD/MTTR, ATT&CK tally. `/api/soc/map`, `/api/soc/dashboard`. Read-only. Geo data built by `tools/build-world-map.js`. |
| Log collector | `soc/` | `collector/vector.yaml` (pipeline + schema), `collector/tests.yaml`, `preflight.sh`, `deploy-collector.sh`, `retention.sh`. |
| Deploy | `deploy/` | `docker-compose.yml`, `env/<env>.env`, `deploy.sh`, `backup-db.sh`, `seed-staging-db.sh`. |

## Data

SQLite, single file. Tables: `clients`, `scans`, `monitors`, `alerts`, `soc_cases`
(`resolved_at` added in Phase 3).
Migrations run at startup and are additive only (`PRAGMA table_info` check,
then `ALTER TABLE ... ADD COLUMN`). Never drop or rename a column: older
releases must keep working on a newer DB so rollback stays safe.

## Configuration (environment variables)

| Variable | Prod | Staging | Purpose |
|---|---|---|---|
| `EAGLE_TALON_ENV` | prod | staging | Shown in UI; non-prod gets a banner |
| `STACK_NAME` | eagle-talon | eagle-talon-staging | Container name prefix |
| `DATA_VOLUME` | eagle-talon-data | eagle-talon-staging-data | Docker volume |
| `EAGLE_TALON_WEB_PORT` | 8088 | 8098 | nginx |
| `API_HOST` / `API_PORT` | 0.0.0.0 / 8000 | 127.0.0.1 / 8100 | uvicorn bind |
| `EAGLE_TALON_SCHEDULER` | on | off | Background monitoring |
| `EAGLE_TALON_VERSION`, `EAGLE_TALON_GIT_SHA` | set by deploy.sh | set by deploy.sh | `/api/version` |
| `NVD_API_KEY` | secrets.env | secrets.env | CVE lookups |
| `SOC_DETECT`, `SOC_DETECT_INTERVAL_S` | off, 300 | on, 300 | Background detection loop |
| `SOC_TRIAGE`, `SOC_TRIAGE_MODEL`, `SOC_TRIAGE_MAX_PER_HOUR` | off, claude-sonnet-5-5, 20 | on, claude-sonnet-5-5, 20 | Claude triage |
| `ANTHROPIC_API_KEY` | — | secrets.env (`eagle-soc` workspace) | Claude API |
| `SOC_HOT_DIR` | unset (→ empty `soc/no-hot-store`) | `/home/eddy/eagle-soc/hot` | Host folder mounted read-only at `/soc-hot` for the Events view |

## Ports on core used by Eagle

| Port | What | Bound to |
|---|---|---|
| 8088 / 8000 | Talon prod web / API | all / all |
| 8098 / 8100 | Talon staging web / API | all / loopback |
| 8089 / 8001 | Eagle Eye web / API | all / all |
| 5514/udp | existing rootless container (likely Wazuh syslog) — not Eagle | — |
| 5516/udp | SOC collector syslog in | all (UFW: FortiGate only) |
| 8686 | SOC collector health API | loopback |

## UI safety rule
Everything in a log line is attacker-controlled. In `frontend/index.html`, event
values only reach the page through `escH()` or `textContent`, never raw
`innerHTML`. The tests and a browser check use a signature containing
`<img onerror=…>` to prove it.

## Known limits
- CORS is `*` and there is no auth on the Talon API. It is reachable only over
  Tailscale, and this must be fixed before any client-facing exposure.
- SQLite is single-writer. The planned log/SOC pipeline will use its own store
  (see [ROADMAP.md](ROADMAP.md)) rather than this DB.
