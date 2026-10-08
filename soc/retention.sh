#!/usr/bin/env bash
# Delete Eagle SOC log data older than the retention set in collector.env.
#   hot store:  ~/eagle-soc/hot/<dataset>/<YYYY-MM-DD>/         older than SOC_HOT_DAYS
#   archive:    /mnt/nas/logs/eagle-soc/archive/<dataset>/<YYYY>/<MM>/<DD>/  older than SOC_ARCHIVE_DAYS
#
#   soc/retention.sh            delete
#   soc/retention.sh --dry-run  only list what would be deleted
#
# Decides by the date in the folder NAME, not file times, so copying or
# touching files never changes what is kept. Run daily from cron (see docs).
set -euo pipefail

SOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SOC_DIR/collector/collector.env"
DRY=0; [[ "${1:-}" == "--dry-run" ]] && DRY=1

env_value() { local v; v="$(grep -E "^$1=" "$ENV_FILE" | tail -n1 | cut -d= -f2-)"; echo "${v/#\~/$HOME}"; }
HOT_DIR="$(env_value SOC_HOT_DIR)"
ARCHIVE_DIR="$(env_value SOC_ARCHIVE_DIR)"
NAS_MOUNT="$(env_value SOC_NAS_MOUNT)"
HOT_DAYS="$(env_value SOC_HOT_DAYS)"
ARCHIVE_DAYS="$(env_value SOC_ARCHIVE_DAYS)"

mkdir -p "$HOME/eagle-soc"
exec 9>"$HOME/eagle-soc/.retention.lock"
flock -n 9 || { echo "retention already running"; exit 0; }

HOT_CUTOFF="$(date -u -d "-$HOT_DAYS days" +%Y-%m-%d)"
ARCH_CUTOFF="$(date -u -d "-$ARCHIVE_DAYS days" +%Y-%m-%d)"
echo "$(date -u +%FT%TZ) retention: hot < $HOT_CUTOFF, archive < $ARCH_CUTOFF"

remove() { if [[ "$DRY" -eq 1 ]]; then echo "would delete $1"; else rm -rf -- "$1"; echo "deleted $1"; fi; }

# Hot: <dataset>/<YYYY-MM-DD>
if [[ -d "$HOT_DIR" ]]; then
  while IFS= read -r d; do
    day="$(basename "$d")"
    if [[ "$day" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ && "$day" < "$HOT_CUTOFF" ]]; then remove "$d"; fi
  done < <(find "$HOT_DIR" -mindepth 2 -maxdepth 2 -type d)
fi

# Archive: only when the NAS is really mounted (never prune an empty mount point).
if [[ "$(findmnt -n -o FSTYPE --target "$NAS_MOUNT" 2>/dev/null | tail -1)" == "cifs" && -d "$ARCHIVE_DIR" ]]; then
  while IFS= read -r d; do
    rel="${d#"$ARCHIVE_DIR"/}"           # <dataset>/YYYY/MM/DD
    ymd="$(cut -d/ -f2- <<<"$rel" | tr / -)"
    if [[ "$ymd" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ && "$ymd" < "$ARCH_CUTOFF" ]]; then remove "$d"; fi
  done < <(find "$ARCHIVE_DIR" -mindepth 4 -maxdepth 4 -type d)
  if [[ "$DRY" -eq 0 ]]; then find "$ARCHIVE_DIR" -mindepth 2 -type d -empty -delete; fi
else
  echo "archive skipped: $NAS_MOUNT is not mounted"
fi
