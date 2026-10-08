#!/usr/bin/env bash
# Deploy Eagle Talon to one environment on this host.
#
#   deploy/deploy.sh staging          build + (re)start staging from this checkout
#   deploy/deploy.sh prod             same for prod — refuses unless HEAD is a
#                                     release tag (vX.Y.Z) and the tree is clean,
#                                     and backs up the prod DB first
#   deploy/deploy.sh prod --force     skip the tag/clean checks (emergencies only)
#   deploy/deploy.sh <env> --dry-run  print the resolved compose config, change nothing
#
# Everything environment-specific comes from deploy/env/<env>.env; secrets come
# from deploy/secrets.env (gitignored). See docs/RUNBOOK.md.
set -euo pipefail

ENV_NAME="${1:-}"
shift || true
FORCE=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

case "$ENV_NAME" in
  prod|staging) ;;
  *) echo "Usage: deploy/deploy.sh <prod|staging> [--dry-run] [--force]" >&2; exit 2 ;;
esac

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$DEPLOY_DIR/.." && pwd)"
ENV_FILE="$DEPLOY_DIR/env/$ENV_NAME.env"
cd "$DEPLOY_DIR"

# Shell variables override env files in compose, so clear the identity
# variables to make sure only env/<env>.env decides names, ports and volume.
unset EAGLE_TALON_ENV STACK_NAME DATA_VOLUME EAGLE_TALON_WEB_PORT API_HOST API_PORT EAGLE_TALON_SCHEDULER

# Read one KEY=value from the environment file (no sourcing, no eval).
env_value() { grep -E "^$1=" "$ENV_FILE" | tail -n1 | cut -d= -f2-; }

STACK_NAME="$(env_value STACK_NAME)"
DATA_VOLUME="$(env_value DATA_VOLUME)"
API_PORT="$(env_value API_PORT)"
WEB_PORT="$(env_value EAGLE_TALON_WEB_PORT)"

# Guard rails: staging must never touch prod's names or data, and prod must
# keep the volume Eagle Eye depends on.
if [[ "$ENV_NAME" == "staging" ]]; then
  if [[ "$STACK_NAME" == "eagle-talon" || "$DATA_VOLUME" == "eagle-talon-data" || "$WEB_PORT" == "8088" || "$API_PORT" == "8000" ]]; then
    echo "REFUSING: env/staging.env points at a prod name, volume or port." >&2
    exit 1
  fi
fi
if [[ "$ENV_NAME" == "prod" && "$DATA_VOLUME" != "eagle-talon-data" ]]; then
  echo "REFUSING: prod must use the eagle-talon-data volume (Eagle Eye mounts it)." >&2
  exit 1
fi

# Version stamp: VERSION file + git commit (+ "-dirty" for uncommitted changes).
VERSION="$(tr -d '[:space:]' < "$REPO_DIR/VERSION")"
GIT_SHA="$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
DIRTY=0
if [[ -n "$(git -C "$REPO_DIR" status --porcelain 2>/dev/null)" ]]; then
  DIRTY=1
  GIT_SHA="$GIT_SHA-dirty"
fi

if [[ "$ENV_NAME" == "prod" && "$FORCE" -eq 0 ]]; then
  TAG="$(git -C "$REPO_DIR" describe --tags --exact-match HEAD 2>/dev/null || true)"
  if [[ "$TAG" != "v$VERSION" ]]; then
    echo "REFUSING: prod deploys must be from release tag v$VERSION (HEAD is '${TAG:-untagged}')." >&2
    echo "Promote first (docs/RUNBOOK.md), or use --force in an emergency." >&2
    exit 1
  fi
  if [[ "$DIRTY" -eq 1 ]]; then
    echo "REFUSING: working tree has uncommitted changes." >&2
    exit 1
  fi
fi

export EAGLE_TALON_VERSION="$VERSION"
export EAGLE_TALON_GIT_SHA="$GIT_SHA"

# Env files: legacy .env and secrets.env first, environment identity LAST
# (later files win), so a stray port in .env can never leak into staging.
ENV_ARGS=()
[[ -f "$DEPLOY_DIR/.env" ]] && ENV_ARGS+=(--env-file "$DEPLOY_DIR/.env")
[[ -f "$DEPLOY_DIR/secrets.env" ]] && ENV_ARGS+=(--env-file "$DEPLOY_DIR/secrets.env")
ENV_ARGS+=(--env-file "$ENV_FILE")

COMPOSE=(docker compose -p "$STACK_NAME" "${ENV_ARGS[@]}" -f "$DEPLOY_DIR/docker-compose.yml")

echo "== Eagle Talon $ENV_NAME: v$VERSION ($GIT_SHA) → project $STACK_NAME, web :$WEB_PORT, api :$API_PORT, volume $DATA_VOLUME"

if [[ "$DRY_RUN" -eq 1 ]]; then
  "${COMPOSE[@]}" config
  exit 0
fi

if [[ "$ENV_NAME" == "prod" ]]; then
  echo "== Backing up the prod DB before deploying"
  "$DEPLOY_DIR/backup-db.sh" prod
fi

"${COMPOSE[@]}" up -d --build

echo "== Waiting for the API"
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$API_PORT/api/version" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
echo "API:  $(curl -fsS "http://127.0.0.1:$API_PORT/api/version" || echo 'NOT RESPONDING — check: docker logs '"$STACK_NAME"'-api')"
echo "Web:  $(curl -fsS -o /dev/null -w 'HTTP %{http_code}' "http://127.0.0.1:$WEB_PORT/" || echo 'NOT RESPONDING — check: docker logs '"$STACK_NAME"'-web')"
echo "== Done. Record this deploy in CHANGELOG.md if it is a release."
