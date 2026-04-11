#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_PID=""
cleanup_enabled="false"

ensure_oid4vc_dev() {
  if command -v oid4vc-dev >/dev/null 2>&1; then
    return 0
  fi
  if ! command -v go >/dev/null 2>&1; then
    echo "Missing required command: go" >&2
    exit 1
  fi

  local gobin
  gobin="$(go env GOBIN)"
  if [[ -z "${gobin}" ]]; then
    gobin="$(go env GOPATH)/bin"
  fi
  mkdir -p "${gobin}"

  echo "oid4vc-dev not found. Installing latest with Go..."
  GOBIN="${gobin}" go install github.com/dominikschlosser/oid4vc-dev@latest
  export PATH="${gobin}:${PATH}"
}

usage() {
  cat <<'EOF'
Usage: ./start.sh [--setup-only|--smoke]

  default      Start Keycloak on http://localhost:8081, bootstrap the HAIP verifier setup, and run the demo app
  --smoke      Run the headless issuance + verification smoke flow after setup
  --setup-only Download/build dependencies, start Keycloak, and bootstrap the realm only
EOF
}

cleanup() {
  if [[ -n "${APP_PID}" ]]; then
    kill "${APP_PID}" >/dev/null 2>&1 || true
    wait "${APP_PID}" >/dev/null 2>&1 || true
  fi
  if [[ "${cleanup_enabled}" == "true" ]]; then
    docker compose down --remove-orphans >/dev/null 2>&1 || true
  fi
}

wait_for_app() {
  local app_base_url="${APP_BASE_URL:-http://127.0.0.1:8091}"
  local health_url="${app_base_url}/healthz"
  for _ in $(seq 1 60); do
    if curl -fsS "${health_url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Demo app did not become ready at ${health_url}" >&2
  exit 1
}

mode="app"
if [[ $# -gt 1 ]]; then
  usage >&2
  exit 1
fi
if [[ $# -eq 1 ]]; then
  case "$1" in
    --setup-only) mode="setup-only" ;;
    --smoke) mode="smoke" ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
fi

cd "${SCRIPT_DIR}"

ensure_oid4vc_dev
./scripts/download-extension.sh
./scripts/build-link-provider.sh

export KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8081}"
export KEYCLOAK_TRUST_LIST_PATH="${KEYCLOAK_TRUST_LIST_PATH:-${SCRIPT_DIR}/keycloak-trustlist.jwt}"

docker compose up -d --force-recreate
./scripts/bootstrap.sh

if [[ "${mode}" != "smoke" ]]; then
  oid4vc-dev wallet register
fi

case "${mode}" in
  app)
    cleanup_enabled="true"
    trap cleanup EXIT INT TERM
    ./scripts/start-app.sh &
    APP_PID=$!
    wait "${APP_PID}"
    ;;
  smoke)
    cleanup_enabled="true"
    trap cleanup EXIT
    oid4vc-dev wallet remove --all >/dev/null
    ./scripts/start-app.sh &
    APP_PID=$!
    wait_for_app
    ./scripts/smoke.py
    ;;
  setup-only)
    echo
    echo "HAIP example is ready."
    ;;
esac
