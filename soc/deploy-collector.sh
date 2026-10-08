#!/usr/bin/env bash
# Deploy (or update) the Eagle SOC log collector on this host.
#
#   soc/deploy-collector.sh            preflight → start/update → self-test
#   soc/deploy-collector.sh --dry-run  preflight + print the resolved compose config
#   soc/deploy-collector.sh --stop     stop and remove the collector (data is kept)
#
# One collector per host, shared by Talon staging and prod. Data it writes:
#   hot store   ~/eagle-soc/hot            (Core disk, searched by Talon)
#   buffers     ~/eagle-soc/vector
#   archive     /mnt/nas/logs/eagle-soc/archive   (NAS `logs` share)
set -euo pipefail

SOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SOC_DIR/collector/collector.env"
COMPOSE_FILE="$SOC_DIR/collector/docker-compose.yml"
MODE="${1:-up}"

env_value() { local v; v="$(grep -E "^$1=" "$ENV_FILE" | tail -n1 | cut -d= -f2-)"; echo "${v/#\~/$HOME}"; }

SOC_HOT_DIR="$(env_value SOC_HOT_DIR)"
SOC_STATE_DIR="$(env_value SOC_STATE_DIR)"
SOC_ARCHIVE_DIR="$(env_value SOC_ARCHIVE_DIR)"
SURICATA_LOG_DIR="$(env_value SURICATA_LOG_DIR)"
SOC_UID="$(id -u)"
SOC_GID="$(id -g)"
export SOC_HOT_DIR SOC_STATE_DIR SOC_ARCHIVE_DIR SURICATA_LOG_DIR SOC_UID SOC_GID

COMPOSE=(docker compose -p eagle-soc -f "$COMPOSE_FILE")

if [[ "$MODE" == "--stop" ]]; then
  SOC_LOG_GID="$SOC_GID" "${COMPOSE[@]}" down
  echo "Collector stopped. Hot store and archive are untouched."
  exit 0
fi

"$SOC_DIR/preflight.sh" || { echo; echo "REFUSING to deploy: fix the FAIL lines above first." >&2; exit 1; }

# Suricata may be missing; never let Docker create /var/log/suricata as root.
if ! sudo -n test -d "$SURICATA_LOG_DIR" 2>/dev/null && [[ ! -d "$SURICATA_LOG_DIR" ]]; then
  echo "(no $SURICATA_LOG_DIR — mounting an empty folder instead; Suricata events will be skipped)"
  SURICATA_LOG_DIR="$HOME/eagle-soc/no-suricata"
  mkdir -p "$SURICATA_LOG_DIR"
  export SURICATA_LOG_DIR
fi
# Least privilege: if eve.json is world-readable the collector needs no extra
# group. Otherwise it joins the file's group — but never root (gid 0).
EVE_META="$(stat -c '%a %g' "$SURICATA_LOG_DIR/eve.json" 2>/dev/null || sudo -n stat -c '%a %g' "$SURICATA_LOG_DIR/eve.json" 2>/dev/null || echo "0 $SOC_GID")"
EVE_MODE="${EVE_META% *}"
EVE_GID="${EVE_META#* }"
if (( 8#$EVE_MODE & 8#004 )) || [[ "$EVE_GID" == 0 ]]; then
  SOC_LOG_GID="$SOC_GID"
else
  SOC_LOG_GID="$EVE_GID"
fi
export SOC_LOG_GID

mkdir -p "$SOC_HOT_DIR" "$SOC_STATE_DIR" "$SOC_ARCHIVE_DIR"

if [[ "$MODE" == "--dry-run" ]]; then
  "${COMPOSE[@]}" config
  exit 0
fi

echo
echo "== Starting eagle-soc-collector (Vector) — runs as $(id -un), log group $SOC_LOG_GID"
"${COMPOSE[@]}" up -d

echo "== Waiting for the collector"
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:8686/health >/dev/null 2>&1 && break
  sleep 1
done
if ! curl -fsS http://127.0.0.1:8686/health >/dev/null 2>&1; then
  echo "Collector is NOT healthy. Last log lines:" >&2
  docker logs --tail 30 eagle-soc-collector >&2
  exit 1
fi
echo "Collector healthy."

# Self-test: send one synthetic FortiGate-style line through the real pipeline
# and look for it in the hot store. Marked devname="eagle-soc-selftest" so the
# SOC ignores it later.
echo "== Self-test"
MARK="selftest-$(date +%s)"
SYSLOG_PORT="$(grep -A4 'fortigate_syslog:' "$SOC_DIR/collector/vector.yaml" | sed -n 's/.*address: "0.0.0.0:\([0-9]*\)".*/\1/p')"
printf '<189>date=%s time=%s devname="eagle-soc-selftest" tz="%s" type="traffic" subtype="forward" srcip=192.168.10.250 srcport=40000 srcintfrole="lan" dstip=192.0.2.10 dstport=443 dstintfrole="wan" dstcountry="Reserved" action="accept" proto=6 msg="%s"' \
  "$(date +%F)" "$(date +%T)" "$(date +%z)" "$MARK" > "/dev/udp/127.0.0.1/$SYSLOG_PORT"
FOUND=""
for _ in $(seq 1 20); do
  if grep -rqs "$MARK" "$SOC_HOT_DIR/fortigate.traffic/" 2>/dev/null; then FOUND=1; break; fi
  sleep 1
done
if [[ -n "$FOUND" ]]; then
  echo "PASS: test event reached the hot store ($SOC_HOT_DIR/fortigate.traffic/)"
  echo "      it reaches the NAS archive within ~5 minutes (gzip files are closed after 5 min idle)"
else
  echo "FAIL: test event did not reach the hot store within 20s" >&2
  docker logs --tail 30 eagle-soc-collector >&2
  exit 1
fi

echo
echo "== Done. Next: point the FortiGate at this host on udp/$SYSLOG_PORT (docs/SOC-COLLECTOR.md, 'FortiGate')."
