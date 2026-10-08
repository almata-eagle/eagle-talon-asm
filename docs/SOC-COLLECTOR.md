# Eagle SOC — log collector (Phase 1)

The collector receives security logs on **core**, reshapes them into one
common format, and writes them to two places:

| Store | Where | Format | Kept | Used for |
|---|---|---|---|---|
| Hot | `~/eagle-soc/hot/<dataset>/<YYYY-MM-DD>/<HH>.ndjson` on Core's NVMe | one JSON event per line | 30 days | Talon search, dashboard, Claude investigations |
| Archive | `/mnt/nas/logs/eagle-soc/archive/<dataset>/<YYYY>/<MM>/<DD>/<HH>.ndjson.gz` on the NAS `logs` share | gzip JSON lines | 400 days | long-term evidence, re-investigation |

Folder dates and hours are **UTC**. Retention is set in `soc/collector/collector.env`.
The `finance` share is never used. Preflight fails if the logs mount points at it.

```
FortiGate 60F ──syslog udp/5516──┐
                                 ├─► Vector (eagle-soc-collector) ─► normalize ─┬─► hot (Core)
Suricata eve.json on core ───────┘                                              └─► archive (NAS)
```

## Sources (Phase 1)
- **FortiGate**: traffic logs (forwarded and local, allowed and denied), UTM/IPS, and system events. Sent as syslog over UDP on the LAN.
- **Suricata** (if running on core): alerts, DNS, TLS, HTTP and anomalies.
  Its bulky `flow`, `stats` and `netflow` events go to the archive only.

Wazuh, UniFi, DNS resolver and identity logs come in later phases (see `ROADMAP.md`).

## Common event format (schema 1)

Every event has these top-level fields. Any of them may be `null`.

| Field | Example | Notes |
|---|---|---|
| `timestamp` | `2026-10-08T03:37:48Z` | When it happened (device time, in UTC) |
| `source` | `fortigate`, `suricata` | Which product produced it |
| `dataset` | `fortigate.traffic`, `fortigate.utm`, `suricata.alert`, `suricata.dns` | `source.type`; also the folder name |
| `subtype` | `forward`, `local`, `ips` | FortiGate subtype |
| `host` | `FGT60F` | Device that logged it |
| `action` | `accept`, `deny`, `dropped`, `allowed` | |
| `src_ip`, `src_port`, `dst_ip`, `dst_port` | | |
| `proto` | `tcp`, `udp`, `icmp` | |
| `direction` | `inbound`, `outbound`, `internal`, `external` | From FortiGate interface roles, else from private address ranges |
| `src_country`, `dst_country` | `Netherlands` | FortiGate's own country lookup (`Reserved` = private) |
| `bytes_out`, `bytes_in` | | Traffic logs only |
| `app` | `HTTPS.BROWSER`, `dns` | |
| `policy` | `1`, `2013028` | FortiGate policy ID or Suricata signature ID |
| `level` | `notice`, `2` | Severity as the device reports it |
| `signature` | IPS attack name, Suricata signature, DNS query, TLS SNI | The "what" in one string |
| `collector_from` | `192.168.10.1` | Address the syslog packet came from |
| `raw` | `{…}` | Every original field, untouched |
| `schema` | `1` | Bumped if this table changes incompatibly |

Changing this format is an ADR-level decision, because Talon, the map and the Claude prompts all read it.

## Deploy (from the staging checkout, until v0.3.0 is released)

On core:
```
cd ~/eagle-talon-staging
```
```
git pull
```
Check readiness. This changes nothing, and its output is safe to paste:
```
soc/preflight.sh
```
Fix every **FAIL** line. Each one prints its `fix:` command. **WARN** lines are
fine to start with; for example, without Suricata you still get FortiGate logs.

Allow the FortiGate to send syslog. Use the exact command preflight prints; it will look like:
```
sudo ufw allow in on enp0s31f6 from 192.168.10.1 to any port 5516 proto udp comment 'FortiGate syslog to eagle-soc'
```
Start the collector. It runs preflight again, starts the collector, and then
sends a test event through the real pipeline:
```
soc/deploy-collector.sh
```
Expect `PASS: test event reached the hot store`.

Daily retention, added to eddy's crontab (`crontab -e`):
```
23 4 * * * $HOME/eagle-talon-staging/soc/retention.sh >> $HOME/eagle-soc/retention.log 2>&1
```

## FortiGate (FortiOS 7.4)

Core's 5514/udp already receives a FortiGate feed for another tool (likely
Wazuh), probably through the FortiGate's first syslog slot (`syslogd`). Eagle
uses the **second slot, `syslogd2`**, on port **5516**, so neither feed disturbs
the other. Check what the first slot holds before changing anything:
```
show log syslogd setting
```
If it shows `server "192.168.10.109"` and `port 5514`, that's the existing feed.
Leave it as it is.

**CLI** (System → CLI Console, or SSH to the FortiGate):
```
config log syslogd2 setting
    set status enable
    set server "192.168.10.109"
    set mode udp
    set port 5516
    set format default
end
```
```
config log syslogd2 filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
    set anomaly enable
end
```
In **Log & Report → Log Settings**, enable *Log allowed traffic → All sessions*.
Then in each firewall policy you care about, set **Log allowed traffic → All sessions**.
Without that, only denied traffic arrives, and the map shows just half the picture.

Check from core that logs are arriving:
```
ls ~/eagle-soc/hot/
```
```
tail -n 2 ~/eagle-soc/hot/fortigate.traffic/$(date -u +%F)/$(date -u +%H).ndjson
```

## View in Talon
Open Talon **staging** (http://core:8098) and click **Events** in the top bar.
- **Filters:** time range (1 h to 7 d), source, allowed/blocked, direction, and
  free text that matches IPs, countries, ports, signatures and apps.
- **Tiles** (click *Blocked*, *Inbound* or *Outbound* to filter), a timeline
  with the blocked share in red, top remote countries and inbound ports (click to search).
- **Rows**: click one to see the full original log, including every FortiGate field under `raw`.
- The dot at the top right shows collector freshness. It turns amber when no
  new log has been written for 15 minutes.
- It auto-refreshes every 30 s while "Live" is ticked. Self-test events are hidden.

Prod shows "not connected" until SOC Phase 1 is released (v0.3.0).

## Operate

| Task | Command |
|---|---|
| Health | `curl -s http://127.0.0.1:8686/health` |
| Collector logs | `docker logs --tail 50 eagle-soc-collector` |
| Events per dataset today | `wc -l ~/eagle-soc/hot/*/$(date -u +%F)/*.ndjson` |
| Update after `git pull` | `soc/deploy-collector.sh` |
| Stop (data kept) | `soc/deploy-collector.sh --stop` |
| Preview retention | `soc/retention.sh --dry-run` |

**If the NAS goes offline**, the hot store keeps working. Up to 5 GB of archive
data waits on Core's disk (`~/eagle-soc/vector`) and is written to the NAS when it
returns. Beyond 5 GB, the newest archive events are dropped rather than
stalling the hot path.

## Tests
`soc/collector/tests.yaml` holds Vector unit tests built from real-shaped
FortiOS 7.4 and Suricata 7 lines. Run them whenever `vector.yaml` changes:
```
docker run --rm -v "$PWD/soc/collector:/c:ro" timberio/vector:0.58.0-debian test /c/vector.yaml /c/tests.yaml
```
