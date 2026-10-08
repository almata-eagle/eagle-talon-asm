# Eagle Talon — Architecture (as of v0.2.0-dev)

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

## Components

| Part | File | Notes |
|---|---|---|
| API | `backend/main.py` | FastAPI. Workspaces (clients), scans, monitors, alerts, bulk CSV jobs, mock portfolio, `/api/version`. |
| Scanner | `backend/scanner.py` | Passive only: DNS, CT logs (crt.sh), TLS metadata, HTTP security headers, RDAP. No port sweeps or probing, so it is legal against third-party domains. |
| CVE correlation | `backend/techstack.py` | NVD API with `virtualMatchString` (not `cpeName`) for version ranges. `NVD_API_KEY` from secrets. |
| UI | `frontend/index.html` | Single file, vanilla JS. Talon Scope radar, log view, report drawer, EN/JP i18n, monitoring page. |
| Web | `deploy/nginx.conf.template` | Ports filled from `NGINX_PORT` and `API_PORT` at container start. |
| Deploy | `deploy/` | `docker-compose.yml`, `env/<env>.env`, `deploy.sh`, `backup-db.sh`, `seed-staging-db.sh`. |

## Data

SQLite, single file. Tables: `clients`, `scans`, `monitors`, `alerts`.
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

## Known limits
- CORS is `*` and there is no auth on the Talon API. It is reachable only over
  Tailscale, and this must be fixed before any client-facing exposure.
- SQLite is single-writer. The planned log/SOC pipeline will use its own store
  (see [ROADMAP.md](ROADMAP.md)) rather than this DB.
