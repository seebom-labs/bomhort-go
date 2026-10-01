#!/usr/bin/env bash
# End-to-end test: bomhort-go ⇄ a real BOMHort stack (docker compose).
#
# 1. Optionally builds BOMHort's api-gateway / ingestion-watcher /
#    parsing-worker images from $BOMHORT_SRC (BOMHORT_BUILD=1).
# 2. Starts an isolated stack from hack/docker-compose.e2e.yml (auth on,
#    writable SBOM dir, high ports) and waits for /readyz.
# 3. Runs the integration tests (test/integration, -tags integration) with
#    strict decoding: they upload testdata/bomhort-0.6.1.spdx.json through
#    the client, wait for ingestion + OSV scan, exercise every endpoint,
#    upload a scoped OpenVEX statement and assert BOMHort applied it.
#
# Usage:
#   BOMHORT_SRC=~/src/bomhort BOMHORT_BUILD=1 hack/e2e-bomhort.sh [--keep] [-run Regex]
#
# Env:
#   BOMHORT_SRC           path to a BOMHort checkout (db/ migrations and
#                         sboms/ policy files are mounted from it) [required]
#   BOMHORT_BUILD         "1" builds the images from $BOMHORT_SRC/backend first
#   BOMHORT_IMAGE_PREFIX  image prefix (default "bomhort-go-e2e/"; use
#                         "ghcr.io/seebom-labs/bomhort/" for published images)
#   BOMHORT_IMAGE_TAG     image tag (default "latest"; e.g. "0.7.1" for ghcr)
#   E2E_API_PORT          host port of the api-gateway (default 18080)
#   E2E_WORK              work dir for SBOMs, logs, test output (default .e2e)
#   BOMHORT_IT_TIMEOUT    per-wait timeout passed to the tests (default 5m)
#   GO                    go binary (default "go")
#
# Exit codes: 0 ok, 1 stack/test failure, 2 usage. Compose logs are written
# to $E2E_WORK/logs/ on failure (uploaded as CI artifacts).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

: "${BOMHORT_SRC:?set BOMHORT_SRC to a BOMHort checkout}"
BOMHORT_SRC="$(cd "$BOMHORT_SRC" && pwd)"
export BOMHORT_SRC
export BOMHORT_IMAGE_PREFIX="${BOMHORT_IMAGE_PREFIX:-bomhort-go-e2e/}"
export BOMHORT_IMAGE_TAG="${BOMHORT_IMAGE_TAG:-latest}"
export E2E_API_PORT="${E2E_API_PORT:-18080}"
export E2E_CH_PORT="${E2E_CH_PORT:-18123}"
export E2E_API_KEY="${E2E_API_KEY:-bomhort-go-e2e-key}"
export E2E_SERVICE_TOKEN="${E2E_SERVICE_TOKEN:-bomhort-go-e2e-service-token}"
PROJECT="${E2E_PROJECT:-bomhort-go-e2e}"
COMPOSE=(docker compose -p "$PROJECT" -f hack/docker-compose.e2e.yml)
GO="${GO:-go}"
KEEP=0
RUN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1 ;;
    -run) shift; RUN="$1" ;;
    -run=*) RUN="${1#-run=}" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

WORK="${E2E_WORK:-$ROOT/.e2e}"
export E2E_SBOM_DIR="$WORK/sboms"
rm -rf "$WORK"
mkdir -p "$E2E_SBOM_DIR/pushed"
# api-gateway runs as nobody and must create files under SBOM_DIR/pushed.
chmod -R 0777 "$E2E_SBOM_DIR"
# SELinux: label the bind mount so the containers may read/write it.
if command -v chcon >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null || echo Disabled)" = "Enforcing" ]; then
  chcon -Rt container_file_t "$E2E_SBOM_DIR" 2>/dev/null || true
fi

dump_logs() {
  mkdir -p "$WORK/logs"
  for svc in api-gateway ingestion-watcher parsing-worker clickhouse; do
    "${COMPOSE[@]}" logs --no-color --tail 500 "$svc" > "$WORK/logs/$svc.log" 2>&1 || true
  done
  echo "    compose logs in $WORK/logs/"
}

cleanup() {
  status=$?
  [ "$status" = "0" ] || dump_logs
  if [ "$KEEP" = "1" ]; then
    echo "--keep: stack '$PROJECT' left running"
    echo "    BOMHORT_URL=http://localhost:$E2E_API_PORT BOMHORT_API_KEY=$E2E_API_KEY make test-integration"
    return
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

API="http://localhost:$E2E_API_PORT"
BOMHORT_REV="$(git -C "$BOMHORT_SRC" describe --tags --always 2>/dev/null || echo unknown)"
if [ "${BOMHORT_BUILD:-0}" = "1" ]; then
  echo "==> building BOMHort images from $BOMHORT_SRC/backend ($BOMHORT_REV)"
  for svc in api-gateway ingestion-watcher parsing-worker; do
    docker build -q --target "$svc" -t "${BOMHORT_IMAGE_PREFIX}${svc}:${BOMHORT_IMAGE_TAG}" "$BOMHORT_SRC/backend" >/dev/null
  done
fi
echo "==> starting BOMHort stack '$PROJECT' (${BOMHORT_IMAGE_PREFIX}*:${BOMHORT_IMAGE_TAG}, source $BOMHORT_REV)"
"${COMPOSE[@]}" up -d --quiet-pull

echo "==> waiting for $API/readyz"
for i in $(seq 1 90); do
  if curl -fsS "$API/readyz" >/dev/null 2>&1; then break; fi
  sleep 2
  [ "$i" = 90 ] && { echo "api-gateway did not become ready"; exit 1; }
done

echo "==> running integration tests"
args=(-tags integration -count=1 -v -timeout 20m)
[ -n "$RUN" ] && args+=(-run "$RUN")
set +e
BOMHORT_URL="$API" BOMHORT_API_KEY="$E2E_API_KEY" \
  "$GO" test "${args[@]}" ./test/integration/ 2>&1 | tee "$WORK/integration.log"
status=${PIPESTATUS[0]}
set -e
if [ "$status" != "0" ]; then
  echo "integration tests failed against BOMHort $BOMHORT_REV"
  exit 1
fi
SKIPS=$(grep -c -- "--- SKIP" "$WORK/integration.log" || true)
echo "E2E OK against BOMHort $BOMHORT_REV ($SKIPS skipped)"
