# SOC threat intelligence (v0.6)

Talon downloads public lists of known-bad addresses and checks every remote
address it sees against them **on Core**. Your addresses are never sent to the
feed providers. The design is in [adr/0006](adr/0006-threat-intelligence.md).

## Where it shows up
| Place | What you see |
|---|---|
| Anywhere | **Click any ⚑ badge** for a plain-language explanation (EN/JA): a verdict for *this* traffic (urgent / worth checking / no action), what the list means, what your network did with that address over 7 days (which of your devices, how, what the firewall did, data volume, a note when it was only pings), numbered steps to follow, and a link to check the listing on the source's own site. |
| Events | A ⚑ badge next to a listed source or destination IP. |
| Cases | A **Threat intelligence** section listing the case's listed addresses. New rule **Known-bad address** (`intel_match`): allowed traffic to or from a listed address. |
| Dashboard | KPI **Known-bad IPs (24h)**, red when any were allowed. The **Known-bad addresses (24 h)** panel lists the worst first; click one to search Events. Map dots with listed IPs get a red ring and a line in the tooltip, and the country drawer badges its IPs. Callouts appear when feeds stop updating. |
| Claude triage | Hits for the case's addresses are added to the evidence as `threat_intel` (untrusted data, supporting not proof). |

## When a case opens (`intel_match`, checked every 5 minutes over the last 15)
| Listed as | Traffic | Severity |
|---|---|---|
| malicious (botnet C2, malware, hijacked network) | allowed **outbound** (our host reached it) | critical |
| malicious | allowed inbound | high |
| suspicious (reported attacker) | allowed inbound | medium |
| info (Tor exit) | allowed inbound | low |
| anything | only blocked | no case, badge only |

## Feeds
| Id | Source | Category | Refresh | Licence / terms |
|---|---|---|---|---|
| `feodo` | abuse.ch Feodo Tracker (recommended list) | botnet C2 | 1 h | CC0, commercial use allowed |
| `spamhaus_drop`, `spamhaus_drop_v6` | Spamhaus DROP | hijacked network | 24 h | Free, commercial included; credit The Spamhaus Project; at most one download a day, so prod only |
| `tor_exits` | Tor Project bulk exit list | Tor exit (info) | 6 h | Public |
| `blocklist_de` | blocklist.de all attacks, 48 h | attacker | 6 h | Commercial terms not stated: **review before selling** |
| `threatfox` | abuse.ch ThreatFox API, IP:port IOCs, 7 days | malware | 6 h | Needs a free abuse.ch Auth-Key (`ABUSECH_AUTH_KEY` in `secrets.env`) |

Feeds are checked every 10 minutes and fetched when due. **Refresh feeds** on
the dashboard fetches any feed not fetched in the last hour; nothing is ever
fetched more often than hourly. One failing feed doesn't affect the others, and a
failed or empty download keeps the previous list.

## Settings (`deploy/env/<env>.env`)
| Variable | Prod | Staging | Meaning |
|---|---|---|---|
| `SOC_INTEL` | on | on | Master switch (compose default off) |
| `SOC_INTEL_FEEDS` | all | no Spamhaus | Comma-separated feed ids |
| `ABUSECH_AUTH_KEY` | secrets.env, optional | secrets.env, optional | Turns on ThreatFox |

To add the abuse.ch key, without it ever showing on screen (on Core, in each
checkout that should use it):
```
nano ~/eagle-talon-asm/deploy/secrets.env
```
Add the line `ABUSECH_AUTH_KEY=<your key>`, save, then redeploy.

## The explainer
`GET /api/soc/intel/explain?ip=…&range=7d` returns the hits plus what our logs
saw: per-direction outcomes, local devices, services and bytes. The verdict and
steps are fixed text in the UI, chosen from the list category and whether
traffic was allowed in or out. Claude isn't involved. "Check on the source"
links open the feed's public page for that address.

## Safety
- Feed files are third-party data. Only values that parse as IP addresses or
  networks are stored, plus a tag stripped to letters, digits and `. _ - /`.
- Private, loopback and reserved addresses never match.
- Downloads are capped at 30 MB, use fixed HTTPS URLs and time out after 60 s.
- The UI escapes feed names and tags like log values.

## Next
- AbuseIPDB and GreyNoise lookups for case addresses only, cached (keys needed).
- STIX/TAXII import for Blackwired and client-supplied feeds.
- Cross-client sightings once tenants exist.
