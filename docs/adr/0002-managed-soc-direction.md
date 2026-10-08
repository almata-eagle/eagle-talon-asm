# ADR 0002 — Grow Talon from passive ASM into an AI-assisted managed SOC

- **Status:** proposed
- **Date:** 2026-10-08

## Context
Talon sees the attack surface from outside (passive DNS, TLS, headers, CT, RDAP).
The goal is managed-SOC capability: ingest logs, interrogate them with Claude
in near real time, alert, explain alerts in plain language with response
options, auto-respond within limits, and ask a human when it matters. The PoC
target is Eddy's home lab (FortiGate 60F, UniFi switch, Core, Edge, Synology
NAS, Suricata, Wazuh), with logs captured and checked on the NAS.

## Decision
1. **Rules detect, Claude investigates.** Suricata, Wazuh, Sigma rules and
   baselines handle volume. A correlator groups alerts into **cases**. Claude
   works per case, not per log line: a small fast model for triage and
   summaries, a stronger model for investigation.
2. **Agents propose, humans approve.** The investigator has read-only tools
   (log query, GeoIP, threat intel, asset and ASM lookups) and writes
   proposals. A separate **executor** holds write credentials (FortiGate,
   UniFi, Tailscale, Wazuh active response), enforces an allowlist policy, and
   records the prior state so every action can be undone.
3. **Autonomy tiers.**
   - Tier 0 runs automatically: enrich and notify.
   - Tier 1 runs automatically with an expiry, e.g. block a known-bad external IP for 24h.
   - Tier 2 needs approval: quarantine a host, revoke a device, disable an account.
   - Tier 3 is never automated.
   There is a global kill switch and a full audit log.
4. **Log content is untrusted input.** Attacker-controlled strings (user agents,
   DNS names, paths) are marked as data in prompts. The executor never trusts
   model output; it validates against policy.
5. **Separation from existing systems.** The NAS gets its own `logs` share,
   separate from `finance`. The SOC gets its own Postgres database and roles,
   never the `cfo` database. It gets its own Anthropic workspace and key, with
   the model chosen by an env var. New ports avoid those already used on core.
6. **ASM + SOC fusion is the differentiator.** Inbound activity is correlated
   with what Talon already knows is exposed and vulnerable.

## Consequences
- New services: a log shipper (Vector), a hot store (the Wazuh
  indexer/OpenSearch already on core), a cold archive on the NAS, a
  correlator, the agent, and the executor. They are built and proven in
  staging first.
- Disk and retention must be planned before ingesting at volume, because the
  NAS also holds finance records.
- FortiGate and UniFi syslog arrive on the LAN, so they need one narrow UFW
  rule (the FortiGate source IP to the syslog port) in addition to the
  tailscale0-only rules.
