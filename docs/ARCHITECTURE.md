# Eagle Talon — Architecture (as of v0.6.0-dev: SOC Phases 1–3 in prod, threat intel in staging)

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
| SOC dashboard | `backend/soc_dashboard.py`, `soc_geo.py`, `soc_geo_countries.json`, `frontend/world-110m.json` | Traffic map, callouts, MTTD/MTTR, ATT&CK tally. `/api/soc/map`, `/api/soc/map/country`, `/api/soc/dashboard`. Read-only. Geo data built by `tools/build-world-map.js`. |
| Threat intel | `backend/soc_intel.py` | Public feeds → SQLite `ti_indicators`/`ti_feeds` → in-memory matching (IPs and networks). Rule `intel_match`, badges, dashboard panel, triage evidence. `/api/soc/intel*`. No address leaves Core. See [SOC-INTEL.md](SOC-INTEL.md). |
| Insights + Ask Claude | `backend/soc_insights.py`, `soc_ask.py` | Traffic profile of a country or device → recognised patterns (plain-language in the UI) → optional on-demand Claude explanation (aggregates only, cached, capped). `/api/soc/insights`, `POST /api/soc/ask`. |
| Alerts | `backend/soc_alerts.py` | After each detection run: open cases at or above `SOC_ALERT_MIN_SEVERITY` → ntfy push + Slack, reminders until acknowledged, quiet hours, "no logs" alert. Notify only. `/api/soc/alerts*`, `/api/soc/cases/{id}/ack`. See [SOC-ALERTS.md](SOC-ALERTS.md), ADR 0008. |
| Response | `backend/soc_response.py` | The one action: a human-approved, time-limited block of a public IPv4 on the FortiGate (address object in `SOC_FGT_BLOCK_GROUP`, used by the operator's deny policies). Approval code, protected ranges, limits, expiry loop, undo, audit. `/api/soc/response*`, `/api/soc/cases/{id}/block`. See [SOC-RESPONSE.md](SOC-RESPONSE.md), ADR 0009. |
| Known devices | `backend/soc_assets.py` | Names, type, notes and quieted case kinds per local IP. Used by case merging, the UI and Claude's network context. `/api/soc/assets`. |
| Talon OT | `backend/ot/` (`db.py`, `auth.py`, `sheets.py`, `api.py`), `backend/ot_app.py`, `frontend/ot.html` | FRCS assessments (UFC 4-010-06). Own SQLite `ot.db` + `evidence/` under `OT_DATA_DIR`, own users/sessions/audit. Mounted at `/api/ot` when `OT_ENABLED=on`; `ot_app.py` runs it alone (DDIL). See [OT.md](OT.md), ADR 0007. |
| Log collector | `soc/` | `collector/vector.yaml` (pipeline + schema), `collector/tests.yaml`, `preflight.sh`, `deploy-collector.sh`, `retention.sh`. |
| Deploy | `deploy/` | `docker-compose.yml`, `env/<env>.env`, `deploy.sh`, `backup-db.sh`, `seed-staging-db.sh`. |

## Data

SQLite, single file. Tables: `clients`, `scans`, `monitors`, `alerts`, `soc_cases`
(`resolved_at` added in Phase 3), `ti_indicators`, `ti_feeds`, `soc_explanations`, `soc_assets`, `soc_alert_state`, `soc_alert_log`, `soc_actions`, `soc_action_log` (v0.6).
Migrations run at startup and are additive only (`PRAGMA table_info` check,
then `ALTER TABLE ... ADD COLUMN`). Never drop or rename a column: older
releases must keep working on a newer DB so rollback stays safe.

Talon OT keeps a separate SQLite file, `OT_DATA_DIR/ot.db` (default
`/app/data/ot/ot.db`): `ot_users`, `ot_sessions` (token SHA-256 only),
`ot_engagements`, `ot_systems`, `ot_items` (with the original `source_row`),
`ot_evidence` (files at `OT_DATA_DIR/evidence/<sha[:2]>/<sha>`), `ot_audit`.
The same additive-only rule applies.

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
| `SOC_DETECT`, `SOC_DETECT_INTERVAL_S` | on, 300 (compose default off) | on, 300 | Background detection loop |
| `SOC_TRIAGE`, `SOC_TRIAGE_MODEL`, `SOC_TRIAGE_MAX_PER_HOUR` | on, claude-sonnet-5-5, 20 (compose default off) | on, claude-sonnet-5-5, 5 | Claude triage |
| `ANTHROPIC_API_KEY` | secrets.env (`eagle-soc` workspace) | secrets.env (same key) | Claude API |
| `SOC_INTEL`, `SOC_INTEL_FEEDS` | on, all feeds (compose default off) | on, without Spamhaus | Threat-intel feeds, refreshed in the background |
| `SOC_ASK_MAX_PER_HOUR` | 10 | 10 | Cap on on-demand "Ask Claude" explanations |
| `ABUSECH_AUTH_KEY` | secrets.env (optional) | secrets.env (optional) | Enables the ThreatFox feed |
| `SOC_ALERTS` | off (compose default) | on | Alerts master switch |
| `SOC_NTFY_TOPIC`, `SOC_NTFY_TOKEN`, `SOC_SLACK_WEBHOOK`, `SOC_ALERT_SECRET` | secrets.env | secrets.env | Alert channels and the phone-acknowledge signing key |
| `SOC_ALERT_BASE_URL` | `http://core:8088` | `http://core:8098` | Talon address used in alert links |
| `SOC_ALERT_*` (severity, quiet hours, reminders, detail, language) | defaults | quiet 23:00–07:00 | Tuning; full list in SOC-ALERTS.md |
| `SOC_RESPONSE_MODE` | off (compose default) | dryrun | `off`, `dryrun` or `live` |
| `SOC_RESPONSE_APPROVAL_CODE`, `SOC_RESPONSE_PROTECT`, `SOC_FGT_HOST`, `SOC_FGT_TOKEN`, `SOC_FGT_FINGERPRINT` | secrets.env | secrets.env | Approval code, never-block list, FortiGate API access and its pinned certificate |
| `SOC_FGT_BLOCK_GROUP`, `SOC_FGT_VDOM`, `SOC_RESPONSE_MAX_*` | TALON-BLOCK, root, 200 / 20 | same | Block group, VDOM, limits |
| `OT_ENABLED` | off (compose default) | on | Mount Talon OT at `/api/ot` |
| `OT_DATA_DIR` | `/app/data/ot` | `/app/data/ot` | Talon OT database and evidence folder |
| `OT_SETUP_CODE` | secrets.env (optional) | secrets.env (optional) | Code needed to create the first OT admin |
| `SOC_HOT_DIR` | `/home/eddy/eagle-soc/hot` (compose default: empty `soc/no-hot-store`) | `/home/eddy/eagle-soc/hot` | Host folder mounted read-only at `/soc-hot` for the Events view |

## Ports on core used by Eagle

| Port | What | Bound to |
|---|---|---|
| 8088 / 8000 | Talon prod web / API | all / all |
| 8098 / 8100 | Talon staging web / API | all / loopback |
| 8089 / 8001 | Eagle Eye web / API | all / all |
| 5514/udp | existing rootless container (likely Wazuh syslog) — not Eagle | — |
| 5516/udp | SOC collector syslog in | all (UFW: FortiGate only) |
| 8686 | SOC collector health API | loopback |
| 8090 | Talon OT standalone (`deploy/ot/`), only if run on core | loopback by default (`OT_BIND`) |

## UI safety rule
Everything in a log line is attacker-controlled. In `frontend/index.html`, event
values only reach the page through `escH()` or `textContent`, never raw
`innerHTML`. The tests and a browser check use a signature containing
`<img onerror=…>` to prove it.

The response form shows exactly what will change on the FortiGate, and the
address it blocks always comes from the case's evidence, never from Claude's text.

Talon OT's page (`frontend/ot.html`) follows the same rule for everything that
came from a person or a spreadsheet.

## Known limits
- CORS is `*` and there is no auth on the Talon API. It is reachable only over
  Tailscale, and this must be fixed before any client-facing exposure.
- SQLite is single-writer. The planned log/SOC pipeline will use its own store
  (see [ROADMAP.md](ROADMAP.md)) rather than this DB.
