#!/usr/bin/env bash
set -Eeuo pipefail

# Production deployment guardrails for the EC2 Compose deployment.
# This script never removes volumes, drops production databases, or runs
# destructive Alembic operations. It fails closed on build/deploy errors.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

EXPECTED_SERVICE="threatfade"
EXPECTED_CONTAINER="threatfade-engine-threatfade-1"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

command -v docker >/dev/null || fail "docker is required"
command -v git >/dev/null || fail "git is required"

if ! docker compose version >/dev/null 2>&1; then
  fail "Docker Compose v2 is required"
fi

# Compose builds use BuildKit/buildx. Fail before changing the running service
# rather than silently reusing a stale image.
if ! docker buildx version >/dev/null 2>&1; then
  fail "Docker buildx plugin is required; install/enable buildx before deploying"
fi

BRANCH="$(git branch --show-current)"
[[ "$BRANCH" == "main" ]] || fail "deployment must run from main (current: $BRANCH)"

git diff --quiet && git diff --cached --quiet || fail "working tree is not clean"

git fetch origin
LOCAL_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse origin/main)"
[[ "$LOCAL_SHA" == "$REMOTE_SHA" ]] || fail "local main is not exactly origin/main; pull/reconcile first"

echo "Deploying ThreatFade commit: $LOCAL_SHA"

echo "Compose config validation..."
docker compose config >/dev/null

echo "Compose config: OK"

echo "Building image..."
docker compose build "$EXPECTED_SERVICE"
echo "Build: OK"

echo "Recreating application service only..."
docker compose up -d --no-deps "$EXPECTED_SERVICE"
echo "Service recreation: OK"

echo "Waiting for container health..."
for _ in $(seq 1 30); do
  HEALTH_STATUS="$(
    docker inspect "$EXPECTED_CONTAINER" \
      --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}'
  )"

  echo "Container health: $HEALTH_STATUS"

  if [[ "$HEALTH_STATUS" == "healthy" ]]; then
    break
  fi

  if [[ "$HEALTH_STATUS" == "unhealthy" ]]; then
    docker inspect "$EXPECTED_CONTAINER" \
      --format '{{range .State.Health.Log}}{{.Start}} exit={{.ExitCode}} output={{.Output}}{{println}}{{end}}' \
      | tail -5
    fail "engine container became unhealthy"
  fi

  sleep 2
done

HEALTH_STATUS="$(
  docker inspect "$EXPECTED_CONTAINER" \
    --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}'
)"

[[ "$HEALTH_STATUS" == "healthy" ]] \
  || fail "engine container did not become healthy"

echo "Verifying /healthz inside container..."
docker exec "$EXPECTED_CONTAINER" \
  python -c 'import urllib.request; r=urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=3); assert r.status == 200; print(r.read().decode())'

docker inspect "$EXPECTED_CONTAINER" \
  --format 'Container={{.Name}} Status={{.State.Status}} Health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
  | grep -q 'Status=running Health=healthy' \
  || fail "engine container is not healthy"

echo "Alembic state (read-only verification):"
docker exec "$EXPECTED_CONTAINER" sh -lc 'alembic current && alembic heads'

echo "Deployment complete: $LOCAL_SHA"
