# SOC alerts

Talon tells you within minutes when a case matters, on your phone (ntfy) and in
Slack. The decision record is [ADR 0008](adr/0008-alerts-push-and-slack.md).

## What you get
- **A push and/or a Slack message** for every open case at or above the
  threshold (default **high**). It carries Claude's one-line headline, what
  happened, the suggested option, and a link that opens the case in Talon.
- **Severity raised:** the alert goes out again, marked as raised.
- **Reminders:** while nobody has acknowledged it, a reminder every 30 minutes,
  up to 3 sends in total.
- **Acknowledge:** tap **Acknowledge** on the phone, or the button on the case
  in Talon, to stop the reminders. Resolving the case also stops them.
- **No logs arriving:** if the collector sends nothing for 30 minutes, you get
  one alert, plus a message when it recovers. A silent collector means
  detection is blind.
- **Quiet hours:** with quiet hours set (for example 23:00–07:00 Tokyo time),
  only critical alerts wake you. The rest arrive in the morning.

The Cases view shows the alert settings in its toolbar, with a **Send test
alert** button. Each case shows 🔔 when it has been alerted and ✓ once
acknowledged.

## Setup
1. **Phone (ntfy):**
   1. Install the ntfy app (iOS or Android).
   2. Subscribe to a topic name nobody can guess, for example
      `talon-` followed by 20 random letters. On the public ntfy.sh server,
      anyone who knows the topic name can read it.
   3. Put that name in the checkout's `deploy/secrets.env` as
      `SOC_NTFY_TOPIC=<topic>`.
2. **Slack (optional):** create an incoming webhook for the channel. Put it in
   `deploy/secrets.env` as `SOC_SLACK_WEBHOOK=https://hooks.slack.com/services/...`.
3. **Acknowledge button (optional):** add `SOC_ALERT_SECRET=<a long random string>`
   to `deploy/secrets.env`. The phone must reach Talon to use the button, for
   example over Tailscale.
4. Redeploy. In Talon, open **Cases** and click **Send test alert**.

[RUNBOOK.md](RUNBOOK.md) has the exact commands.

## Settings
| Variable | Default | Meaning |
|---|---|---|
| `SOC_ALERTS` | `off` (compose); `on` in staging | Master switch |
| `SOC_NTFY_TOPIC` | — (secrets.env) | ntfy topic; set it to enable push |
| `SOC_NTFY_URL` | `https://ntfy.sh` | Your own ntfy server, if self-hosted |
| `SOC_NTFY_TOKEN` | — (secrets.env) | Access token for a protected ntfy topic |
| `SOC_SLACK_WEBHOOK` | — (secrets.env) | Slack incoming webhook; set it to enable Slack |
| `SOC_ALERT_SECRET` | — (secrets.env) | Signs the phone's Acknowledge button |
| `SOC_ALERT_BASE_URL` | — | Talon address used in links, e.g. `http://core:8098` |
| `SOC_ALERT_MIN_SEVERITY` | `high` | `info`, `low`, `medium`, `high` or `critical` |
| `SOC_ALERT_QUIET` | — | Quiet hours, e.g. `23:00-07:00` (only critical alerts then) |
| `SOC_ALERT_TZ` | `Asia/Tokyo` | Time zone for quiet hours |
| `SOC_ALERT_RENOTIFY_MIN` | `30` | Minutes between reminders |
| `SOC_ALERT_MAX_SENDS` | `3` | Most sends per case (first alert + reminders); a raised severity still alerts |
| `SOC_ALERT_TRIAGE_WAIT_S` | `600` | How long to wait for Claude's explanation before alerting without it |
| `SOC_ALERT_SILENT_MIN` | `30` | Minutes without new logs before the "no logs" alert |
| `SOC_ALERT_DETAIL` | `summary` | `minimal` sends only severity and a link |
| `SOC_ALERT_LANG` | `en` | `en`, `ja` or `both` |

## What leaves Core
Only the case's severity, Claude's headline, what happened, and the suggested
option (or the rule's title when there is no explanation), plus a link. Raw
log lines are never sent. For client data on a third-party service, use
`SOC_ALERT_DETAIL=minimal`, or run your own ntfy server.

## Safety
- Alert text comes from logs and from Claude's reading of them, so it is
  untrusted. It is sent as plain text, length-capped, with Slack control
  syntax escaped.
- Alerts only notify. Nothing in alerting changes the network.
- Each Acknowledge link is signed for one case. It can only stop that case's
  reminders.

## API
- `GET /api/soc/alerts`: settings, channels and recent sends.
- `POST /api/soc/alerts/test`: sends a test alert to every configured channel.
- `POST /api/soc/cases/{id}/ack`: acknowledge from Talon.
- `POST /api/soc/alerts/ack/{id}?token=…`: acknowledge from the phone (signed).
- Cases include an `alert` object: `sends`, `last_sent_at`, `acked_at`, `acked_by`.
