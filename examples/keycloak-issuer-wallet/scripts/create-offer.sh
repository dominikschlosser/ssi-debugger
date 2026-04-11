#!/usr/bin/env bash
set -euo pipefail

KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-oid4vc-demo}"
OID4VCI_CLIENT_ID="${OID4VCI_CLIENT_ID:-oid4vc-demo-client}"
OID4VCI_CREDENTIAL_SCOPE="${OID4VCI_CREDENTIAL_SCOPE:-membership-credential}"
OID4VCI_USER="${OID4VCI_USER:-alice}"
OID4VCI_USER_PASSWORD="${OID4VCI_USER_PASSWORD:-alice}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need curl
need jq

USER_TOKEN="$(
  curl -fsS \
    -X POST "${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=${OID4VCI_CLIENT_ID}" \
    -d "username=${OID4VCI_USER}" \
    -d "password=${OID4VCI_USER_PASSWORD}" \
    | jq -er '.access_token'
)"

OFFER_JSON="$(
  curl -fsS \
    -H "Authorization: Bearer ${USER_TOKEN}" \
    "${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/oid4vc/create-credential-offer?credential_configuration_id=${OID4VCI_CREDENTIAL_SCOPE}&pre_authorized=true&type=uri"
)"

ISSUER="$(printf '%s' "$OFFER_JSON" | jq -er '.issuer')"
NONCE="$(printf '%s' "$OFFER_JSON" | jq -er '.nonce')"
RAW_OFFER_URI="${ISSUER%/}/${NONCE#/}"
ENCODED_OFFER_URI="$(jq -rn --arg uri "$RAW_OFFER_URI" '$uri|@uri')"

printf 'openid-credential-offer://?credential_offer_uri=%s\n' "$ENCODED_OFFER_URI"
