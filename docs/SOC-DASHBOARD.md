# SOC dashboard (Phase 3)

Top bar → **Dashboard**. It's read-only. It refreshes every 30 s while open.
The reasoning behind it is in [adr/0005](adr/0005-dashboard-and-offline-geo.md).

## What's on it

| Part | Source | Notes |
|---|---|---|
| KPI tiles | `/api/soc/dashboard` → `kpis`, `posture`, `sensors` | Open cases (bar = severity mix), new in 24 h, the three response times, events and blocked in 24 h, sensors reporting. Click a tile to open Cases or Events. |
| Traffic map | `/api/soc/map?range=1h\|6h\|24h\|7d` | One arc per remote country and direction. A thicker arc or bigger dot means more traffic (log scale). A dashed arc means everything was blocked; moving dots mean some traffic was allowed. Countries we talked to are shaded. **Zoom** with the scroll wheel, a pinch, a double-click (Shift+double-click zooms out) or the + / − / ⟲ buttons. **Drag** to move. Country names appear once you've zoomed in. **Hover** a country, arc or dot to highlight its traffic and see events, blocked, bytes, remote IPs, top ports and top IPs. **Click** to open its details. |
| Country details (drawer) | `/api/soc/map/country?country=…&range=…` | Opens from the map or the countries table. Shows a direction switch, totals per direction (events, % blocked, remote IPs, data, first and last seen), an activity timeline, related cases (open, or seen in the last 7 days, whose evidence names the country), the top 15 remote IPs and top 10 ports per direction, and the 25 latest events per direction. Click an event to see all its fields; click an IP or port to search Events; click a case to open it. **Zoom to it on the map** centres the map on the country. |
| Needs attention | `callouts` | Sensor and system problems, then open cases by severity (max 6). Each case card shows Claude's headline and recommended option, plus **Open case**, **View events** and **Mark resolved** (asks first; reopen from Cases). Cases Claude rated *info + likely benign* are left off the dashboard but stay in Cases. |
| MITRE ATT&CK | `attack` | Techniques Claude named on cases from the last 30 days, grouped by tactic. Sub-techniques count under their parent's tactic. Unknown ids go under *Other*. |
| Top remote countries | same as the map | The 12 biggest flows for the selected direction. Hover to highlight the flow on the map, click to open its details. Values the map can't place are listed underneath. |

## KPI definitions (medians, last 30 days)
- **Time to detect (MTTD):** first event of a case → case created. This is bounded by the detection interval (`SOC_DETECT_INTERVAL_S`, 5 min).
- **Time to explain:** case created → Claude's triage stored.
- **Time to resolve (MTTR):** case created → a person marked it resolved (`soc_cases.resolved_at`).
- `n=` is how many cases the median is based on.

## Callouts raised by the system
| Code | When | Severity |
|---|---|---|
| `hot_store_missing` | The API can't read the hot store | high |
| `sensor_stale` | A FortiGate dataset has had no new file for 15 min, or a Suricata dataset for 24 h | high (FortiGate) / medium (Suricata) |
| `no_ids` | No Suricata dataset at all | low |
| `triage_off` | Detection on, Claude triage off | info |
| `triage_errors` | Open cases whose triage failed | low |

Freshness uses file times in the hot store, not the event timestamps.

## Safety
Country names, IPs, case titles and Claude's text all come from
attacker-controlled logs. The UI escapes every value with `escH()`. The tests
and the browser check use `<img onerror=…>` in a country name and in a Claude
headline to prove it. The country drill-down matches the country name exactly, as a bound
parameter (no wildcards), and is capped at 80 characters. The only buttons that change anything are **Mark
resolved** (the same human switch as in Cases) and navigation.

## Changing the map data
Only needed to change the projection or the country list:
```
mkdir /tmp/geo
```
```
cd /tmp/geo
```
```
npm init -y
```
```
npm install world-atlas@2.0.2 d3-geo@3.1.1 topojson-client@3.1.0 i18n-iso-countries@7.14.0
```
Then, from the repo root:
```
NODE_PATH=/tmp/geo/node_modules node tools/build-world-map.js
```
Commit `frontend/world-110m.json` and `backend/soc_geo_countries.json`. To
teach the lookup a new FortiGate spelling, add it to `EXTRA_ALIASES` in the tool.

## Not yet
- **Network topology from UniFi.** This needs a UniFi controller API key in `deploy/secrets.env`.
- City-level points (GeoLite2, see ADR 0005).
