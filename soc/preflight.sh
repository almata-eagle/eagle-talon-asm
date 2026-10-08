#!/usr/bin/env bash
# Eagle SOC preflight — checks core is ready for the log collector.
# READ-ONLY: it changes nothing, except creating and deleting one empty test
# file on the NAS `logs` share to prove it is writable.
# Its output contains no secrets and is safe to paste into chat.
#
#   soc/preflight.sh            run all checks (exit 1 if anything FAILs)
#
# deploy-collector.sh runs this first and refuses to deploy on any FAIL.
set -uo pipefail

SOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SOC_DIR/collector/collector.env"
VECTOR_CFG="$SOC_DIR/collector/vector.yaml"

PASS=0; WARN=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$*"; }
warn() { WARN=$((WARN+1)); printf '  \033[33mWARN\033[0m %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
info() { printf '  INFO %s\n' "$*"; }
fix()  { printf '       fix: %s\n' "$*"; }
section() { printf '\n== %s\n' "$*"; }

env_value() { local v; v="$(grep -E "^$1=" "$ENV_FILE" | tail -n1 | cut -d= -f2-)"; echo "${v/#\~/$HOME}"; }

HOT_DIR="$(env_value SOC_HOT_DIR)"
NAS_MOUNT="$(env_value SOC_NAS_MOUNT)"
ARCHIVE_DIR="$(env_value SOC_ARCHIVE_DIR)"
SURI_DIR="$(env_value SURICATA_LOG_DIR)"
ALLOW_FROM="$(env_value SOC_SYSLOG_ALLOW_FROM)"
SYSLOG_PORT="$(grep -A4 'fortigate_syslog:' "$VECTOR_CFG" | sed -n 's/.*address: "0.0.0.0:\([0-9]*\)".*/\1/p')"
API_PORT="$(grep -A3 '^api:' "$VECTOR_CFG" | sed -n 's/.*address: "127.0.0.1:\([0-9]*\)".*/\1/p')"
COLLECTOR_RUNNING="$(docker ps --filter name=^eagle-soc-collector$ --format '{{.Names}}' 2>/dev/null)"

echo "Eagle SOC preflight — $(hostname) — $(date '+%Y-%m-%d %H:%M %Z')"
echo "(sudo is used only to READ: ufw status and Suricata file permissions)"
sudo -v 2>/dev/null || echo "  (no sudo — firewall and Suricata checks will be partial)"

section "Tools"
command -v docker >/dev/null && pass "docker $(docker --version | awk '{print $3}' | tr -d ,)" || fail "docker not found"
docker compose version >/dev/null 2>&1 && pass "docker compose $(docker compose version --short 2>/dev/null)" || fail "docker compose plugin not found"
command -v curl >/dev/null && pass "curl" || { fail "curl not found"; fix "sudo apt install -y curl"; }
if command -v mount.cifs >/dev/null || [[ -x /sbin/mount.cifs || -x /usr/sbin/mount.cifs ]]; then pass "cifs-utils (mount.cifs)"; else fail "cifs-utils not installed — NAS credentials file can't be used"; fix "sudo apt install -y cifs-utils"; fi

section "Host"
info "CPUs: $(nproc)   RAM: $(free -h | awk '/^Mem:/{print $2" total, "$7" available"}')"
GW="$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')"
info "default gateway (likely the FortiGate): ${GW:-unknown}"
mkdir -p "$HOT_DIR" 2>/dev/null
HOT_FREE_GB="$(df -BG --output=avail "$(dirname "$HOT_DIR")" 2>/dev/null | tail -1 | tr -dc 0-9)"
if [[ -n "$HOT_FREE_GB" && "$HOT_FREE_GB" -ge 50 ]]; then pass "hot store disk ($(dirname "$HOT_DIR")): ${HOT_FREE_GB}G free"
elif [[ -n "$HOT_FREE_GB" ]]; then warn "hot store disk only ${HOT_FREE_GB}G free — lower SOC_HOT_DAYS"
else fail "can't read free space for $HOT_DIR"; fi

section "NAS logs share"
ls "$NAS_MOUNT" >/dev/null 2>&1   # wakes the systemd automount
FSTYPE="$(findmnt -n -o FSTYPE --target "$NAS_MOUNT" 2>/dev/null | tail -1)"
FSSRC="$(findmnt -n -o SOURCE --target "$NAS_MOUNT" 2>/dev/null | tail -1)"
if [[ "$FSTYPE" == "cifs" ]]; then
  pass "$NAS_MOUNT is mounted from $FSSRC"
  case "$FSSRC" in
    */finance*) fail "$NAS_MOUNT points at the finance share — logs must never go there" ;;
  esac
  NAS_FREE_GB="$(df -BG --output=avail "$NAS_MOUNT" | tail -1 | tr -dc 0-9)"
  NAS_SIZE_GB="$(df -BG --output=size "$NAS_MOUNT" | tail -1 | tr -dc 0-9)"
  if [[ "$NAS_FREE_GB" -ge 200 ]]; then pass "NAS free space: ${NAS_FREE_GB}G of ${NAS_SIZE_GB}G"
  else warn "NAS free space only ${NAS_FREE_GB}G of ${NAS_SIZE_GB}G — lower SOC_ARCHIVE_DAYS"; fi
  T="$NAS_MOUNT/.eagle-soc-preflight-$$"
  if touch "$T" 2>/dev/null && rm -f "$T"; then pass "NAS share is writable by $(id -un)"
  else fail "NAS share is not writable by $(id -un)"; fix "DSM: give talon-logs Read/Write on 'logs'; fstab line needs uid=$(id -un)"; fi
else
  fail "$NAS_MOUNT is not a mounted NAS share (found: ${FSTYPE:-nothing}, ${FSSRC:-})"
  fix "sudo mount $NAS_MOUNT    (then: sudo dmesg | tail -5 if it fails)"
fi
case "$ARCHIVE_DIR" in
  "$NAS_MOUNT"/*) pass "archive path is inside the NAS logs share ($ARCHIVE_DIR)" ;;
  *) fail "SOC_ARCHIVE_DIR ($ARCHIVE_DIR) is not under $NAS_MOUNT" ;;
esac

section "Ports"
port_check() { # proto port label
  local proto="$1" port="$2" label="$3" flag
  [[ "$proto" == udp ]] && flag=-uln || flag=-tln
  if ss -H $flag "sport = :$port" 2>/dev/null | grep -q .; then
    if [[ -n "$COLLECTOR_RUNNING" ]]; then pass "$port/$proto in use by eagle-soc-collector ($label)"
    else fail "$port/$proto is already used by something else ($label)"; fix "sudo ss -${flag#-}p 'sport = :$port'   to see what"; fi
  else pass "$port/$proto free ($label)"; fi
}
port_check udp "$SYSLOG_PORT" "FortiGate syslog in"
port_check tcp "$API_PORT" "collector health API, loopback"
for p in 8000 8001 8010 8012 8088 8089 8098 8100 5433; do
  [[ "$p" == "$SYSLOG_PORT" || "$p" == "$API_PORT" ]] && fail "collector port $p clashes with an existing core service"
done

section "Suricata"
SURI_STATE="$(systemctl is-active suricata 2>/dev/null)"
if [[ "$SURI_STATE" == active ]]; then pass "suricata service is active"
else
  SURI_CTR="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i suricata | head -1)"
  if [[ -n "$SURI_CTR" ]]; then info "suricata runs as container '$SURI_CTR' — check SURICATA_LOG_DIR points at its log folder"
  else warn "suricata isn't running (systemd: ${SURI_STATE:-unknown}) — FortiGate logs will still flow"; fi
fi
EVE="$SURI_DIR/eve.json"
if sudo -n test -e "$EVE" 2>/dev/null || [[ -e "$EVE" ]]; then
  EVE_STAT="$(stat -c '%U:%G %a %s' "$EVE" 2>/dev/null || sudo -n stat -c '%U:%G %a %s' "$EVE" 2>/dev/null)"
  EVE_MTIME="$(stat -c %Y "$EVE" 2>/dev/null || sudo -n stat -c %Y "$EVE" 2>/dev/null || echo 0)"
  AGE_MIN=$(( ( $(date +%s) - EVE_MTIME ) / 60 ))
  read -r OWNER MODE SIZE <<<"$EVE_STAT"
  info "eve.json: owner $OWNER, mode $MODE, $(numfmt --to=iec "${SIZE:-0}" 2>/dev/null || echo "$SIZE")B, last write ${AGE_MIN} min ago"
  EVE_GROUP="${OWNER#*:}"
  if (( 8#${MODE:-0} & 8#004 )); then pass "eve.json is world-readable — the collector reads it as $(id -un), no extra group"
  elif (( 8#${MODE:-0} & 8#040 )) && [[ "$EVE_GROUP" != root ]]; then pass "eve.json is group-readable (collector joins group $EVE_GROUP)"
  elif [[ "$EVE_GROUP" == root ]]; then
    warn "eve.json is readable only by group root — the collector will NOT join root, so Suricata events are skipped"
    fix "sudo chgrp adm $EVE && sudo chmod 640 $EVE   (and set 'filemode: 640' for eve-log in /etc/suricata/suricata.yaml)"
  else warn "eve.json is not group-readable — the collector won't see Suricata events"; fix "sudo chmod g+r $EVE   (and set 'filemode: 640' for eve-log in /etc/suricata/suricata.yaml)"; fi
  DIR_MODE="$(stat -c %a "$SURI_DIR" 2>/dev/null || sudo -n stat -c %a "$SURI_DIR" 2>/dev/null)"
  if (( (8#${DIR_MODE:-0} & 8#050) == 8#050 )); then pass "$SURI_DIR is group-traversable"
  else warn "$SURI_DIR (mode $DIR_MODE) is not group-readable/traversable"; fix "sudo chmod g+rx $SURI_DIR"; fi
  (( AGE_MIN > 60 )) && warn "eve.json hasn't been written for ${AGE_MIN} min — is Suricata watching the right interface?"
else
  warn "no $EVE — Suricata events will be skipped until it exists"
fi

section "Firewall (UFW)"
UFW_OUT="$(sudo -n ufw status 2>/dev/null)" || UFW_OUT=""
LAN_IF="$(ip route get "${ALLOW_FROM:-${GW:-192.168.10.1}}" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)"
SRC="${ALLOW_FROM:-$GW}"
if [[ -z "$UFW_OUT" ]]; then
  warn "couldn't read 'ufw status' (needs sudo)"
elif ! grep -q "Status: active" <<<"$UFW_OUT"; then
  info "ufw is not active — syslog will be accepted from anywhere on the LAN"
elif grep -Eq "^$SYSLOG_PORT/udp( on $LAN_IF)? +ALLOW( IN)? +$SRC\b" <<<"$UFW_OUT"; then
  pass "ufw allows $SYSLOG_PORT/udp from $SRC on $LAN_IF"
else
  warn "ufw has no rule letting the FortiGate ($SRC) send syslog to $SYSLOG_PORT/udp"
  fix "sudo ufw allow in on $LAN_IF from $SRC to any port $SYSLOG_PORT proto udp comment 'FortiGate syslog to eagle-soc'"
fi

section "Other security services on core"
OTHERS="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -Ei 'wazuh|opensearch|elastic|graylog|loki|thehive' | tr '\n' ' ')"
info "${OTHERS:-none found} (Phase 1 doesn't depend on these)"
info "collector container: ${COLLECTOR_RUNNING:-not running}"

printf '\n== Result: %d PASS, %d WARN, %d FAIL\n' "$PASS" "$WARN" "$FAIL"
[[ "$FAIL" -eq 0 ]]
