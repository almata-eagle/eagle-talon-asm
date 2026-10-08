# ADR 0005 — Read-only SOC dashboard with offline, country-level geo

- **Status:** accepted
- **Date:** 2026-10-08

## Context
Phase 3 (ADR 0002) adds a dashboard: a global traffic map, callout cards with
response options, and response-time KPIs. The map needs a location for each
remote address. Options:

1. **FortiGate's own country tag.** Every FortiGate session already carries
   `srccountry`/`dstcountry` from Fortinet's geo database, and the collector
   keeps them (`src_country`/`dst_country`).
2. **MaxMind GeoLite2 City** in the collector (a Vector enrichment table). That
   gives city-level points, but it needs a MaxMind account, a licence key, a
   monthly database refresh, and an attribution notice.
3. **A hosted tile map** (Leaflet, Mapbox and similar). It looks rich, but it
   loads third-party tiles at runtime and leaks which countries we look at.

Talon's UI is a single static file with self-hosted fonts, so it also works
offline.

## Decision
1. **Country level, from the firewall's tag (option 1).** `backend/soc_geo.py`
   maps FortiGate's country names (any common spelling, EN and JA) to an ISO
   code and the country's centroid. Values that aren't countries, such as
   `Reserved` and anonymizers, are never placed. Unknown values are listed
   under the map instead of being guessed.
2. **Geography is generated offline and committed.**
   `tools/build-world-map.js` turns Natural Earth 1:110m (public domain, via
   `world-atlas`, ISC) into `frontend/world-110m.json` (pre-projected SVG
   paths, Natural Earth 1 projection) and `backend/soc_geo_countries.json`
   (names and centroids). Nothing is fetched from the internet at runtime, and
   no new runtime dependency is added.
3. **The dashboard is read-only, like triage.** Callout options either
   navigate (open the case, open the matching events) or use the existing
   human "resolve" switch, with a confirmation. Claude's recommended option is
   shown as text. There is still no execution path; that's Phase 4.
4. **KPIs are medians over 30 days:** MTTD (first event → case), time to
   explain (case → Claude), MTTR (case → resolved by a person). A new
   `soc_cases.resolved_at` column (additive migration) records resolution.
   Older resolved cases fall back to `updated_at`.

## Consequences
- Arcs point at a country's centre, not the actual city. That's enough to
  see where traffic comes from and goes to. GeoLite2 can be added later in the
  collector without changing the API shape (flows would gain `lat`/`lon` per
  city).
- Countries smaller than the 1:110m outlines (Singapore, Hong Kong, Malta and
  others) are still placed, from a hand-kept centroid list, but have no
  outline to shade.
- Non-FortiGate sources without a country tag (for example Suricata) don't
  appear on the map until they're enriched.
- Updating the map data is a deliberate dev step (rerun the tool and commit),
  never something that happens on Core.
