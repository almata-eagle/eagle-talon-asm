#!/usr/bin/env bash
# Replace STAGING's database with a fresh copy of PROD's.
#
#   deploy/seed-staging-db.sh            backs up prod, then loads that backup into staging
#   deploy/seed-staging-db.sh <file.db>  loads a specific backup into staging instead
#
# Prod is only ever READ (via backup-db.sh, read-only mount). Staging's current
# DB is backed up first, so this is reversible: re-run with that file to undo.
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGING_ENV="$DEPLOY_DIR/env/staging.env"
STAGING_VOLUME="$(grep -E '^DATA_VOLUME=' "$STAGING_ENV" | tail -n1 | cut -d= -f2-)"
STAGING_STACK="$(grep -E '^STACK_NAME=' "$STAGING_ENV" | tail -n1 | cut -d= -f2-)"
BACKUP_DIR="${BACKUP_DIR:-$HOME/eagle-talon-backups}"

if [[ "$STAGING_VOLUME" == "eagle-talon-data" ]]; then
  echo "REFUSING: staging volume is set to prod's volume." >&2
  exit 1
fi

SOURCE="${1:-}"
if [[ -z "$SOURCE" ]]; then
  "$DEPLOY_DIR/backup-db.sh" prod
  SOURCE="$(ls -1t "$BACKUP_DIR"/prod/eagle_talon-*.db | head -n1)"
fi
[[ -f "$SOURCE" ]] || { echo "Not found: $SOURCE" >&2; exit 1; }
SOURCE="$(cd "$(dirname "$SOURCE")" && pwd)/$(basename "$SOURCE")"

echo "This replaces the STAGING database ($STAGING_VOLUME) with:"
echo "  $SOURCE"
read -r -p "Type 'staging' to continue: " CONFIRM
[[ "$CONFIRM" == "staging" ]] || { echo "Cancelled."; exit 1; }

"$DEPLOY_DIR/backup-db.sh" staging || true

docker volume create "$STAGING_VOLUME" >/dev/null
docker stop "$STAGING_STACK-api" >/dev/null 2>&1 || true

docker run --rm \
  -v "$STAGING_VOLUME":/dst \
  -v "$SOURCE":/seed.db:ro \
  python:3.12-slim \
  sh -c 'cp /seed.db /dst/eagle_talon.db.new && mv /dst/eagle_talon.db.new /dst/eagle_talon.db && rm -f /dst/eagle_talon.db-journal'

docker start "$STAGING_STACK-api" >/dev/null 2>&1 || echo "(staging API not created yet — run deploy/deploy.sh staging)"
echo "Staging seeded from $(basename "$SOURCE")."
