#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_PID=""
compose_args=(-f docker-compose.yml)
transport="http"
trust_mode="trustlist"

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
Usage: ./start.sh [--http|--https] [--setup-only|--smoke]

  default      Same as --http: start Keycloak on http://localhost:8080, bootstrap the realm, and start the demo app
  --http       Use http://localhost:8080 and a custom trust list for verifier trust
  --https      Use https://localhost:8443 and issuer metadata for verifier trust
  --smoke      Run the full headless smoke flow after setup
  --setup-only Download/build dependencies, start Keycloak, and bootstrap the realm only
EOF
}

cleanup() {
  if [[ -n "${APP_PID}" ]]; then
    kill "${APP_PID}" >/dev/null 2>&1 || true
    wait "${APP_PID}" >/dev/null 2>&1 || true
  fi
}

wait_for_app() {
  local app_base_url="${APP_BASE_URL:-http://127.0.0.1:8090}"
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
while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup-only) mode="setup-only" ;;
    --smoke) mode="smoke" ;;
    --http)
      transport="http"
      trust_mode="trustlist"
      ;;
    --https)
      transport="https"
      trust_mode="metadata"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
  shift
done

cd "${SCRIPT_DIR}"

ensure_oid4vc_dev
./scripts/download-extension.sh
./scripts/build-link-provider.sh

case "${transport}" in
  http)
    export KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
    compose_args=(-f docker-compose.yml)
    ;;
  https)
    export KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-https://localhost:8443}"
    export KEYCLOAK_CA_CERT="${KEYCLOAK_CA_CERT:-${SCRIPT_DIR}/keycloak-ca-cert.pem}"
    ./scripts/generate-keycloak-cert.sh
    compose_args=(-f docker-compose.yml -f docker-compose.https.yml)
    ;;
esac

export OID4VP_TRUST_MODE="${OID4VP_TRUST_MODE:-${trust_mode}}"
export KEYCLOAK_TRUST_LIST_PATH="${KEYCLOAK_TRUST_LIST_PATH:-${SCRIPT_DIR}/keycloak-trustlist.jwt}"

docker compose "${compose_args[@]}" up -d --force-recreate
./scripts/bootstrap.sh

if [[ "${mode}" != "smoke" ]]; then
  oid4vc-dev wallet register
fi

case "${mode}" in
  app)
    exec ./scripts/start-app.sh
    ;;
  smoke)
    trap cleanup EXIT
    ./scripts/start-app.sh &
    APP_PID=$!
    wait_for_app
    ./scripts/smoke.py
    ;;
  setup-only)
    echo
    echo "Combined example is ready."
    ;;
esac
