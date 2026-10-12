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

## Drill indicator (end-to-end check)
A way to prove that detection, alerting and blocking work together, without
waiting for a real attack. For up to 2 hours, Talon treats the addresses of
**example.com** (a harmless domain reserved for examples) as a known-bad server.
- Any allowed connection to them opens a **critical** `intel_match` case labelled TEST.
- The case is alerted, and it can be blocked through Response (dry run or live).
- The Cases toolbar shows **DRILL ACTIVE** while it runs.
- The indicator lives in memory only. It clears itself after the chosen time,
  on restart, or on request.

Start it (on core; staging API shown):
```
curl -s -X POST http://127.0.0.1:8100/api/soc/intel/test-indicator -H 'Content-Type: application/json' -d '{"minutes":60}'
```
Then open `http://example.com` in a browser on any device behind the
FortiGate. Within about 5–15 minutes you should see:
1. a critical TEST case in **Cases**;
2. the alert on your phone;
3. after **Block…** in live mode, example.com no longer loading from the LAN;
4. after **Undo**, it loading again.

Stop it:
```
curl -s -X DELETE http://127.0.0.1:8100/api/soc/intel/test-indicator
```
Resolve the TEST case afterwards and mark it 👍, so it doesn't skew the numbers.
Only public IPv4 addresses are accepted, 8 at most, for at most 2 hours.

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
