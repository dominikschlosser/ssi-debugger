#!/usr/bin/env bash
set -euo pipefail

KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-oid4vc-demo}"
OID4VCI_CLIENT_ID="${OID4VCI_CLIENT_ID:-oid4vc-demo-client}"
OID4VCI_CREDENTIAL_SCOPE="${OID4VCI_CREDENTIAL_SCOPE:-membership-credential}"
OID4VCI_USER="${OID4VCI_USER:-alice}"

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

issuer_metadata_url="${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/.well-known/openid-credential-issuer"

echo "Waiting for Keycloak realm import at ${issuer_metadata_url}..."
wait_for_endpoint "${issuer_metadata_url}"

jq -er '.credential_issuer' < <(curl -fsS "${issuer_metadata_url}") >/dev/null

echo
echo "Issuer metadata:"
echo "  ${issuer_metadata_url}"
echo
echo "Offer endpoint:"
echo "  ${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/oid4vc/create-credential-offer"
echo
echo "Ready:"
echo "  realm=${KEYCLOAK_REALM}"
echo "  user=${OID4VCI_USER}"
echo "  client=${OID4VCI_CLIENT_ID}"
echo "  credential_configuration_id=${OID4VCI_CREDENTIAL_SCOPE}"
