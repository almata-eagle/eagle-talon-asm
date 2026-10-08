# Eagle Talon — Roadmap

The direction is in [adr/0002](adr/0002-managed-soc-direction.md). Everything is
built and proven in **staging** first. Each phase ships as a minor version.

| Phase | Version | Scope | Done when |
|---|---|---|---|
| 0 | 0.2.0 | Staging environment, versioning, runbook, backups | Staging runs at :8098 with prod data; first tagged prod deploy through `deploy.sh` |
| 1 | 0.3.0 | **Ingest** *(in progress: collector built; Talon search next)*. NAS `logs` share mounted on core; Vector collecting FortiGate syslog, Suricata `eve.json` and Wazuh alerts; hot store with 14–30 days; cold archive on the NAS (compressed, about a year) | Logs searchable from Talon; disk use and retention measured |
| 2 | 0.4.0 | **Cases + Claude triage (read-only).** Correlator, cases table, plain-language explanation, severity, confidence, evidence and suggested options. No actions yet | One week of home-lab cases reviewed; noise tuned |
| 3 | 0.5.0 | **Dashboard.** Global traffic map (inbound and outbound arcs, GeoLite2), callout cards with options, topology from UniFi, ATT&CK heatmap, MTTD/MTTR | Daily use replaces Grafana for security review |
| 4 | 0.6.0 | **Respond.** Executor with Tier 0–2 actions (FortiGate block with expiry, UniFi client block, Tailscale revoke), approval in UI and Slack, Undo, kill switch, audit log | Purple-team run from the Kali laptop is detected and contained with approval |
| 5 | 0.7.0 | **Improve.** Claude-drafted Sigma rules from closed cases, false-positive feedback loop, ask-your-logs hunting in EN and JP, shift briefings, honeypot and canaries on VLAN 30 | Detection coverage scored release over release |
| — | — | Later: Eagle Eye client views of cases, DNS resolver logs, Workspace/M365 identity, AWS CloudTrail, APPI breach-reporting support, multi-tenant MSSP | — |
