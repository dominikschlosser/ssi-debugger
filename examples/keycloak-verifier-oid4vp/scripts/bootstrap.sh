#!/usr/bin/env bash
set -euo pipefail

KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-wallet-demo}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-wallet-mock}"
OIDC_REDIRECT_URI="${OIDC_REDIRECT_URI:-http://127.0.0.1:18080/callback}"
OID4VP_TRUST_LIST_URL="${OID4VP_TRUST_LIST_URL:-http://host.docker.internal:8085/api/trustlist}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need curl
need jq

wait_for_endpoint() {
  local url="$1"
  for _ in $(seq 1 60); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "Keycloak did not become ready at ${url}" >&2
  exit 1
}

discovery_url="${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/.well-known/openid-configuration"

echo "Waiting for Keycloak realm import at ${discovery_url}..."
wait_for_endpoint "${discovery_url}"

jq -er '.authorization_endpoint' < <(curl -fsS "${discovery_url}") >/dev/null

echo
echo "Ready:"
echo "  realm=${KEYCLOAK_REALM}"
echo "  client=${OIDC_CLIENT_ID}"
echo "  authorize=${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth"
echo "  redirect_uri=${OIDC_REDIRECT_URI}"
echo "  trust_list_url=${OID4VP_TRUST_LIST_URL}"
