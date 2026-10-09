# Eagle Talon — Roadmap

The direction is in [adr/0002](adr/0002-managed-soc-direction.md). Everything is
built and proven in **staging** first. Each phase ships as a minor version.
Phases 0–3 were released to prod together as **v0.5.0** (2026-10-09).

| Phase | Version | Scope | Done when |
|---|---|---|---|
| 0 | 0.2.0 | Staging environment, versioning, runbook, backups | Staging runs at :8098 with prod data; first tagged prod deploy through `deploy.sh` |
| 1 | 0.3.0 | **Ingest** *(built in staging: collector live with real FortiGate logs, Events view in Talon; next: a week of volume/retention measurement, then release)*. NAS `logs` share mounted on core; Vector collecting FortiGate syslog, Suricata `eve.json` and Wazuh alerts; hot store with 14–30 days; cold archive on the NAS (compressed, about a year) | Logs searchable from Talon; disk use and retention measured |
| 2 | 0.4.0 | **Cases + Claude triage (read-only)** *(built in staging; next: a week of reviewing cases with 👍/👎, then tune)*. Correlator, cases table, plain-language explanation, severity, confidence, evidence and suggested options. No actions yet | One week of home-lab cases reviewed; noise tuned |
| 3 | 0.5.0 | **Dashboard** *(built in staging: map, callouts, ATT&CK, MTTD/MTTR; next: UniFi topology, which needs a controller API key)*. Global traffic map (inbound and outbound arcs, GeoLite2), callout cards with options, topology from UniFi, ATT&CK heatmap, MTTD/MTTR | Daily use replaces Grafana for security review |
| 3b | 0.6.0 | **Threat intelligence** *(built in staging)*. Public feeds matched locally, `intel_match` rule, badges, dashboard panel, Claude evidence. Next: AbuseIPDB/GreyNoise lookups, STIX/TAXII (Blackwired) | Known-bad addresses flagged on real traffic; feed licences checked |
| — | — | **Sellable platform** (planned before Respond): tenants (one per client), login and roles (MSSP admin, analyst, client viewer), audit log, per-site collectors, per-client Claude budget | Two tenants isolated end to end |
| 4 | 0.7.0 | **Respond.** Executor with Tier 0–2 actions (FortiGate block with expiry, UniFi client block, Tailscale revoke), approval in UI and Slack, Undo, kill switch, audit log | Purple-team run from the Kali laptop is detected and contained with approval |
| 5 | 0.8.0 | **Improve.** Claude-drafted Sigma rules from closed cases, false-positive feedback loop, ask-your-logs hunting in EN and JP, shift briefings, honeypot and canaries on VLAN 30 | Detection coverage scored release over release |
| OT | — | **Talon OT** (design in [OT-DESIGN.md](OT-DESIGN.md), ADR 0007): FRCS assessments against UFC 4-010-06 / NIST SP 800-82. OT-1 checklist and evidence (spreadsheet in and out, offline), OT-2 asset inventory, OT-3 opt-in Claude assist, OT-4 passive ICS sensor, OT-5 field↔HQ sync | One real checklist worked end to end offline |
| — | — | Later: Eagle Eye client views of cases, DNS resolver logs, Workspace/M365 identity, AWS CloudTrail, APPI breach-reporting support, multi-tenant MSSP | — |
