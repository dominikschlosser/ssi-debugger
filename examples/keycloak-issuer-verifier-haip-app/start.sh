#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${REPO_ROOT}/examples/lib/public-ngrok.sh"
example_load_env_files "${REPO_ROOT}/.env" "${SCRIPT_DIR}/.env"
APP_PID=""
PROXY_PID=""
cleanup_enabled="false"
public_mode="false"
keycloak_ngrok_domain="${KEYCLOAK_NGROK_DOMAIN:-${NGROK_DOMAIN:-}}"
compose_args=(-f docker-compose.yml)
public_proxy_port="${PUBLIC_PROXY_PORT:-18091}"
ngrok_override=""

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
Usage: ./start.sh [--setup-only|--smoke] [--public] [--keycloak-domain <name>]

  default      Start Keycloak on http://localhost:8081, bootstrap the HAIP verifier setup, and run the demo app
  --smoke      Run the headless issuance + verification smoke flow after setup
  --setup-only Download/build dependencies, start Keycloak, and bootstrap the realm only
  --public     Publish both Keycloak and the demo app through one ngrok HTTPS hostname
  --keycloak-domain  Fixed ngrok hostname (otherwise detect from sandbox cert SAN when available)
EOF
}

cleanup() {
  if [[ -n "${APP_PID}" ]]; then
    kill "${APP_PID}" >/dev/null 2>&1 || true
    wait "${APP_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${PROXY_PID}" ]]; then
    kill "${PROXY_PID}" >/dev/null 2>&1 || true
    wait "${PROXY_PID}" >/dev/null 2>&1 || true
  fi
  if [[ "${cleanup_enabled}" == "true" ]]; then
    docker compose "${compose_args[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ -n "${ngrok_override}" ]]; then
    rm -f "${ngrok_override}" >/dev/null 2>&1 || true
  fi
  example_stop_ngrok
}

wait_for_app() {
  local app_base_url="http://${APP_HOST:-127.0.0.1}:${APP_PORT:-8091}"
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

wait_for_proxy() {
  local proxy_url="http://127.0.0.1:${public_proxy_port}/"
  local status=""

  for _ in $(seq 1 40); do
    if [[ -n "${PROXY_PID}" ]] && ! kill -0 "${PROXY_PID}" 2>/dev/null; then
      echo "Public reverse proxy exited before becoming ready." >&2
      exit 1
    fi
    status="$(curl -s -o /dev/null -w '%{http_code}' "${proxy_url}" || true)"
    if [[ "${status}" =~ ^(200|302|400|401|403|404|502)$ ]]; then
      return 0
    fi
    sleep 0.25
  done

  echo "Public reverse proxy did not become ready at ${proxy_url}" >&2
  exit 1
}

mode="app"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup-only) mode="setup-only" ;;
    --smoke) mode="smoke" ;;
    --public) public_mode="true" ;;
    --keycloak-domain)
      keycloak_ngrok_domain="$2"
      shift
      ;;
    --domain)
      keycloak_ngrok_domain="$2"
      shift
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

if [[ "${public_mode}" == "true" ]]; then
  public_proxy_port="$(example_resolve_free_port "${public_proxy_port}" "public proxy")"
  export OID4VP_PUBLIC_WALLET="true"
  export OID4VP_SANDBOX_PEM_PATH="${OID4VP_SANDBOX_PEM_PATH:-$(example_find_sandbox_pem "${REPO_ROOT}" "${SCRIPT_DIR}" || true)}"
  export OID4VP_SANDBOX_VERIFIER_INFO_PATH="${OID4VP_SANDBOX_VERIFIER_INFO_PATH:-$(example_find_sandbox_verifier_info "${REPO_ROOT}" "${SCRIPT_DIR}" || true)}"
  if [[ -z "${keycloak_ngrok_domain}" ]]; then
    keycloak_ngrok_domain="$(example_env_keycloak_ngrok_domain || true)"
  fi
  detected_domain="$(example_default_ngrok_domain "${REPO_ROOT}" "${SCRIPT_DIR}" "" || true)"
  if [[ -n "${detected_domain}" ]] && [[ "${detected_domain}" != "${keycloak_ngrok_domain}" ]]; then
    echo "Using ngrok hostname from sandbox certificate SAN: ${detected_domain}"
    keycloak_ngrok_domain="${detected_domain}"
  fi
  (
    cd "${REPO_ROOT}"
    exec go run ./examples/lib/single-host-proxy \
      --listen "127.0.0.1:${public_proxy_port}" \
      --app "http://127.0.0.1:8091" \
      --keycloak "http://127.0.0.1:8081"
  ) &
  PROXY_PID=$!
  wait_for_proxy
  public_base_url="$(example_start_ngrok_tunnel "keycloak-issuer-verifier-haip-public" "${public_proxy_port}" "${keycloak_ngrok_domain}")"
  export KEYCLOAK_BASE_URL="${public_base_url}"
  export APP_BASE_URL="${public_base_url}"
  export APP_REDIRECT_URI="${public_base_url%/}/callback"
  export OID4VP_TRUST_LIST_URL="${public_base_url%/}/keycloak-trustlist.jwt"
  export ALLOWED_ISSUER="${public_base_url%/}/realms/${KEYCLOAK_REALM:-wallet-haip-demo}"
  ngrok_override="${SCRIPT_DIR}/docker-compose.ngrok.override.yml"
  example_write_keycloak_public_override "${ngrok_override}" "${KEYCLOAK_BASE_URL}"
  compose_args+=(-f "${ngrok_override}")
  echo "Public URL: ${public_base_url}"
else
  export OID4VP_PUBLIC_WALLET="false"
  export KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8081}"
fi
export KEYCLOAK_TRUST_LIST_PATH="${KEYCLOAK_TRUST_LIST_PATH:-${SCRIPT_DIR}/keycloak-trustlist.jwt}"

docker compose "${compose_args[@]}" up -d --force-recreate
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
