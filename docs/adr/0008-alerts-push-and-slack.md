# ADR 0008 — Alerts: push (ntfy) and Slack, explanation only, notify-only

- **Status:** accepted
- **Date:** 2026-10-09

## Context
Cases and Claude's explanations sat on a dashboard until someone opened it. An
attack at 2 a.m. would be explained well and seen the next afternoon. Detection
only protects if a person hears about it within minutes, so this is the first
item in "Phase 1: prove it protects" (the sellable-platform checklist).

Options:
1. **Push to a phone app (ntfy) and post to Slack**, from the API process, after each detection run.
2. **Email**: universal, but slow to notice, and easy to filter or ignore.
3. **LINE**: common in Japan, but a LINE Official Account and Messaging API setup is heavier. Keep it for later.
4. **A paging service** (PagerDuty, Opsgenie): built for this, but too costly and complex for one operator today.

## Decision
1. **ntfy and Slack now** (`backend/soc_alerts.py`). Either or both, from
   `SOC_NTFY_TOPIC` and `SOC_SLACK_WEBHOOK` in `deploy/secrets.env`. ntfy can run
   on ntfy.sh or self-hosted (`SOC_NTFY_URL`). Further channels plug into the same `SENDERS` table.
2. **What alerts.** An open case whose severity reaches `SOC_ALERT_MIN_SEVERITY`
   (default `high`). The severity is Claude's when triage is done, else the rule's.
   - The alert waits up to `SOC_ALERT_TRIAGE_WAIT_S` (10 min) for the explanation, then goes without it.
   - Severity raised → alert again.
   - Not acknowledged → reminders every `SOC_ALERT_RENOTIFY_MIN` (30 min), at most `SOC_ALERT_MAX_SENDS` (3) sends in total.
   - Acknowledging (Talon button, or the phone's button) or resolving the case stops them.
   - A collector with no new log for `SOC_ALERT_SILENT_MIN` (30 min) is an alert too. It is sent once, plus a "recovered" message.
3. **Quiet hours** (`SOC_ALERT_QUIET`, e.g. `23:00-07:00`, `SOC_ALERT_TZ`): only critical alerts go out. Others wait until morning.
4. **What leaves Core.** Only the case's severity, Claude's headline, what happened, and the suggested option (or the rule title), plus a link back to Talon.
   - Never raw log lines.
   - `SOC_ALERT_DETAIL=minimal` sends severity and a link only. Use it for client data on a third-party service, or self-host ntfy.
5. **Untrusted text.**
   - Case text comes from logs and from Claude's reading of them. It is sent as plain text, control characters stripped, length-capped.
   - Slack's `& < >` are escaped, so text cannot form `<!channel>` mentions or disguised links.
   - Link unfurling is off.
   - A suspected prompt injection is called out in the alert.
6. **Notify only.** Nothing in alerting changes the network. Acting on an alert is a separate, human-approved step (Phase 1 response, its own ADR).
7. **Acknowledge from the phone.**
   - The ntfy alert carries an "Acknowledge" button that POSTs to Talon.
   - It authenticates with an HMAC of the case id (`SOC_ALERT_SECRET`), because Talon has no login yet.
   - The token can only acknowledge that one case. Without a secret, the button is not shown.
8. **Off by default.** `SOC_ALERTS` defaults to off in compose (the prod value until v0.6.0). Staging turns it on.
   - Prod and staging read the same logs. Once prod alerts, staging should alert to a different topic, or be switched off, to avoid double alerts.

## Consequences
- Alerts depend on the detection loop (`SOC_DETECT=on`). If the API is down, nothing alerts. An external uptime check (Uptime Kuma) on `/api/version` covers that.
- Two new tables in the shared DB, `soc_alert_state` and `soc_alert_log` (additive).
- Escalation to a second person, an on-call rota and LINE come later.
