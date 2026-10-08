#!/usr/bin/env bash
# Consistent snapshot of an environment's SQLite DB, taken while it keeps running.
#
#   deploy/backup-db.sh prod        → $BACKUP_DIR/prod/eagle_talon-<UTC time>-v<version>.db
#   deploy/backup-db.sh staging
#
# Uses SQLite's online backup API (not a file copy), mounting the data volume
# READ-ONLY, so it is safe to run against live prod. Keeps the newest
# $BACKUP_KEEP files per environment (default 30).
# BACKUP_DIR defaults to ~/eagle-talon-backups; point it at the NAS once a
# share is mounted (e.g. BACKUP_DIR=/mnt/nas/logs/eagle-talon-backups).
set -euo pipefail
trap 'echo "backup-db.sh: failed at line $LINENO" >&2' ERR

ENV_NAME="${1:-}"
case "$ENV_NAME" in
  prod|staging) ;;
  *) echo "Usage: deploy/backup-db.sh <prod|staging>" >&2; exit 2 ;;
esac

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$DEPLOY_DIR/env/$ENV_NAME.env"
DATA_VOLUME="$(grep -E '^DATA_VOLUME=' "$ENV_FILE" | tail -n1 | cut -d= -f2-)"
BACKUP_DIR="${BACKUP_DIR:-$HOME/eagle-talon-backups}"
BACKUP_KEEP="${BACKUP_KEEP:-30}"
API_PORT="$(grep -E '^API_PORT=' "$ENV_FILE" | tail -n1 | cut -d= -f2-)"

# Label the backup with the version that environment is actually RUNNING,
# not this checkout's VERSION file (the staging checkout backs up prod too).
# Releases before 0.2.0 have no /api/version, so they're labelled "pre-0.2.0".
# `|| true`: under `set -e -o pipefail` a failing curl (an old release answers
# 404) would otherwise end the script here, silently.
VERSION="$( { curl -fsS --max-time 3 "http://127.0.0.1:$API_PORT/api/version" 2>/dev/null \
  | sed -n 's/.*"version":"\([^"]*\)".*/\1/p'; } || true)"
if [[ -z "$VERSION" ]]; then
  if curl -fsS --max-time 3 "http://127.0.0.1:$API_PORT/api/health" >/dev/null 2>&1; then
    VERSION="pre-0.2.0"
  else
    VERSION="unknown"
  fi
fi

if ! docker volume inspect "$DATA_VOLUME" >/dev/null 2>&1; then
  echo "No volume $DATA_VOLUME yet — nothing to back up." >&2
  exit 0
fi

OUT_DIR="$BACKUP_DIR/$ENV_NAME"
mkdir -p "$OUT_DIR"
chmod 700 "$BACKUP_DIR" "$OUT_DIR"
NAME="eagle_talon-$(date -u +%Y%m%dT%H%M%SZ)-v$VERSION.db"

docker run --rm \
  -v "$DATA_VOLUME":/src:ro \
  -v "$OUT_DIR":/dst \
  python:3.12-slim \
  python -c "
import sqlite3, sys
src = sqlite3.connect('file:/src/eagle_talon.db?mode=ro', uri=True)
dst = sqlite3.connect('/dst/$NAME')
src.backup(dst)
ok = dst.execute('PRAGMA integrity_check').fetchone()[0]
dst.close(); src.close()
if ok != 'ok':
    sys.exit('integrity_check failed: ' + ok)
"

# Files written by the container are root-owned; hand them back to this user.
docker run --rm -v "$OUT_DIR":/dst python:3.12-slim chown "$(id -u):$(id -g)" "/dst/$NAME"
chmod 600 "$OUT_DIR/$NAME"

echo "Backup: $OUT_DIR/$NAME ($(du -h "$OUT_DIR/$NAME" | cut -f1))"

# Retention: keep the newest $BACKUP_KEEP.
ls -1t "$OUT_DIR"/eagle_talon-*.db 2>/dev/null | tail -n +"$((BACKUP_KEEP + 1))" | xargs -r rm -f
