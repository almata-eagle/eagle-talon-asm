# Eagle SOC — Cases and Claude triage (Phase 2)

Phase 2 turns the event stream into **cases** and has Claude explain each one
in plain English and Japanese, with response options. It is **read-only**:
nothing is ever changed on the network. Options are suggestions for a human.

```
hot store ──► detection rules (every 5 min) ──► cases (SQLite) ──► Claude triage ──► Cases view
              backend/soc_rules.py               backend/soc_cases.py  backend/soc_triage.py
```

## Detection rules

| Rule | Fires when (in its window) | Window | Rule severity |
|---|---|---|---|
| `inbound_port_scan` | one remote IP hits ≥ 10 different ports | 15 min | low; medium if anything was allowed |
| `inbound_brute_force` | ≥ 20 attempts from one IP to one sensitive port (SSH, RDP, SMB, DBs…) | 15 min | low; **high** if any attempt was allowed |
| `ids_alert` | any Suricata alert or FortiGate IPS/AV/anomaly event | 15 min | from the device level; one notch lower if fully blocked |
| `allowed_inbound` | internet traffic **allowed** in to an internal host | 15 min | medium; **high** for sensitive ports |
| `outbound_volume` | one internal host sends ≥ 500 MB to one destination | 60 min | medium |
| `outbound_new_country` | an internal host contacts a country it hasn't contacted in 7 days (needs ≥ 24 h of history) | 60 min | low |

The collector's self-test events are always ignored. Thresholds live at the top
of `backend/soc_rules.py`; change them there, with a test.

## Cases
- A case is **one entity doing one thing**: a rule plus its key (e.g. scanner IP).
- While a case is open and the same rule and entity fire again within 6 hours,
  the case grows instead of a new one appearing. Statistics and the 20 newest
  sample events always describe the case's whole lifetime.
- **Resolve** a case when you're done. If the activity comes back later, it
  becomes a new case.
- **👍 Useful / 👎 Noise** is your verdict, and it's what we tune the rules on.
  Please use it during the review week.

## Claude triage
- **Model:** `SOC_TRIAGE_MODEL` (default `claude-sonnet-5-5`).
- **Key:** `ANTHROPIC_API_KEY` in `deploy/secrets.env`, using the `eagle-soc`
  workspace and service-account key, with the workspace spend limit as a backstop.
- **Output:** verdict, severity, confidence, what happened, why it matters, what's
  unknown, and 2–4 options with exactly one recommended. Everything is in EN and
  JA, plus MITRE ATT&CK ids. Claude must answer through a forced tool call with
  a strict schema, and the result is validated again before it's stored.
- **Network context:** `backend/soc_context.md` describes your network to Claude.
  Keep it current and factual, and never put secrets in it.

### Cost controls
| Control | Default | Setting |
|---|---|---|
| Triages per hour (all cases) | 20 | `SOC_TRIAGE_MAX_PER_HOUR` |
| Triages per case | 3 automatic (+2 on request) | `MAX_TRIAGES_PER_CASE` in `soc_cases.py` |
| Re-triage trigger | case at least doubles, or severity rises | `RETRIAGE_GROWTH` |
| Prompt caching | system prompt + network context cached | — |
| Hard cap | workspace monthly spend limit in the Claude Console | Console |

The Cases view header shows how many cases were triaged in the last 24 h. Each
case's footer shows its token use.

### Kill switches
- Stop Claude calls: set `SOC_TRIAGE=off` in `deploy/env/staging.env`, then run `deploy/deploy.sh staging`.
- Stop detection: set `SOC_DETECT=off` the same way.
- Emergency: disable the key in the Claude Console (Settings → API keys). Cases
  then show "triage failed"; nothing else breaks.

## Prompt-injection defences
Logs are attacker-controlled. A signature, URL or DNS name can contain text like
"ignore previous instructions". The defences, all covered by tests in
`backend/tests/test_soc_cases.py`:
1. Evidence goes into one fenced `<case_evidence>` block as JSON, with `<`, `>`
   and `&` escaped, so log text can't close the fence.
2. Strings are truncated to 300 characters, control characters are stripped,
   and only an allowlist of raw fields is passed.
3. The system prompt tells Claude the evidence is untrusted, and to report
   AI-directed text as an indicator (`injection_suspected`, which the UI shows
   as a red banner).
4. Forced tool call with a strict schema, then re-validation: enums, lengths,
   one recommended option, and MITRE id format.
5. Threat-intel hits (`threat_intel`) are added inside the same fence. Feed
   tags are stripped to a safe character set before they are stored.
6. No tool can act, and every value is escaped in the UI. Even a "successful"
   injection can only produce a wrong explanation, never an action.

## API
| Method | Path | |
|---|---|---|
| GET | `/api/soc/engine` | detection/triage state, last run, 24 h usage |
| POST | `/api/soc/detect/run` | run detection + triage now (background) |
| GET | `/api/soc/cases?status=open\|resolved` | case list (no evidence) |
| GET | `/api/soc/cases/{id}` | full case incl. stats, samples, triage |
| POST | `/api/soc/cases/{id}/status` | `{"status": "open" \| "resolved"}` |
| POST | `/api/soc/cases/{id}/feedback` | `{"verdict": "useful" \| "noise" \| null, "note": "…"}` |
| POST | `/api/soc/cases/{id}/retriage` | ask Claude again (within limits) |


## Ask Claude about a country or a device (v0.6)
The country drawer and the device view have an **Ask Claude to explain this**
button. Claude gets the aggregated traffic profile from
`backend/soc_insights.py`: counts per direction and outcome, protocols and
ports, busiest local devices and remote /24 networks, countries, timing,
threat-list counts and the patterns already recognised. It also gets the
network context. It never gets raw log lines or packet content.

- Same defences as triage: the profile is fenced in `<traffic_summary>` and
  escaped, there's a forced `record_explanation` tool call with a strict
  schema, and the output is re-validated. Nothing is executed.
- Only on a click. Each answer is cached for 30 minutes per slice (in
  `soc_explanations`), and `SOC_ASK_MAX_PER_HOUR` (default 10) caps calls.
  It shares the Claude key and model with triage.


## Known devices in Claude's context (v0.6)
Device names and notes entered in Talon (device view → "Name this device")
are appended to the network context as "KNOWN DEVICES". That way, Claude can
say "Eddy's MacBook" instead of an IP and knows what the owner considers
normal. They're operator input: stripped of control characters, length-capped,
and escaped in the UI.

Kinds that the owner marked as normal for a device (`outbound_new_country`,
`outbound_volume`, `allowed_inbound`) are skipped when findings merge into
cases. Attacks from outside (scans, brute force, IDS alerts, threat-intel
matches) can't be quieted.
