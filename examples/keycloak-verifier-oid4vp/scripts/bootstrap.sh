#!/usr/bin/env bash
set -euo pipefail

KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-wallet-demo}"
OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-wallet-mock}"
OIDC_REDIRECT_URI="${OIDC_REDIRECT_URI:-http://127.0.0.1:18080/callback}"
OID4VP_TRUST_LIST_URL="${OID4VP_TRUST_LIST_URL:-http://host.docker.internal:8085/api/trustlist}"
OID4VP_TRUST_LIST_LOTE_TYPE="${OID4VP_TRUST_LIST_LOTE_TYPE:-http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need curl
need jq

wait_for_keycloak() {
  local ready_url="${KEYCLOAK_BASE_URL}/realms/master"
  for _ in $(seq 1 60); do
    if curl -fsS "$ready_url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "Keycloak did not become ready at ${ready_url}" >&2
  exit 1
}

admin_token() {
  curl -fsS \
    -X POST "${KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "X-Forwarded-Proto: https" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    -d "username=${KEYCLOAK_ADMIN}" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
    | jq -er '.access_token'
}

api() {
  local method="$1"
  local path="$2"
  shift 2
  curl -fsS -X "$method" \
    "${KEYCLOAK_BASE_URL}${path}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "X-Forwarded-Proto: https" \
    "$@"
}

api_json() {
  local method="$1"
  local path="$2"
  local payload="$3"
  curl -fsS -X "$method" \
    "${KEYCLOAK_BASE_URL}${path}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "X-Forwarded-Proto: https" \
    -H "Content-Type: application/json" \
    --data-binary @- <<<"$payload"
}

json_payload() {
  jq -c -n "$@"
}

DCQL_QUERY="$(jq -c -n '{
  credentials: [
    {
      id: "pid_sd_jwt",
      format: "dc+sd-jwt",
      meta: {vct_values: ["urn:eudi:pid:de:1"]},
      claims: [
        {path: ["family_name"]},
        {path: ["given_name"]},
        {path: ["birthdate"]}
      ]
    }
  ]
}')"

echo "Waiting for Keycloak at ${KEYCLOAK_BASE_URL}..."
wait_for_keycloak
ADMIN_TOKEN="$(admin_token)"

if curl -fsS -o /dev/null -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "X-Forwarded-Proto: https" \
  "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}" 2>/dev/null; then
  echo "Deleting existing realm ${KEYCLOAK_REALM}..."
  api DELETE "/admin/realms/${KEYCLOAK_REALM}"
fi

echo "Creating realm ${KEYCLOAK_REALM}..."
api_json POST "/admin/realms" \
  "$(json_payload --arg realm "$KEYCLOAK_REALM" '{realm: $realm, enabled: true, sslRequired: "NONE"}')"

echo "Creating public client ${OIDC_CLIENT_ID}..."
api_json POST "/admin/realms/${KEYCLOAK_REALM}/clients" \
  "$(json_payload \
    --arg client_id "$OIDC_CLIENT_ID" \
    --arg redirect_uri "$OIDC_REDIRECT_URI" \
    '{
      clientId: $client_id,
      enabled: true,
      publicClient: true,
      directAccessGrantsEnabled: false,
      standardFlowEnabled: true,
      redirectUris: [
        "http://127.0.0.1/*",
        "http://localhost/*"
      ],
      webOrigins: ["*"],
      protocol: "openid-connect",
      attributes: {
        "pkce.code.challenge.method": "S256"
      }
    }')"

echo "Configuring OID4VP identity provider..."
api_json POST "/admin/realms/${KEYCLOAK_REALM}/identity-provider/instances" \
  "$(json_payload \
    --arg trust_list_url "$OID4VP_TRUST_LIST_URL" \
    --arg trust_list_lote_type "$OID4VP_TRUST_LIST_LOTE_TYPE" \
    --arg dcql_query "$DCQL_QUERY" \
    '{
      alias: "oid4vp",
      displayName: "Sign in with Wallet",
      providerId: "oid4vp",
      enabled: true,
      trustEmail: false,
      storeToken: false,
      addReadTokenRoleOnCreate: false,
      authenticateByDefault: false,
      linkOnly: false,
      firstBrokerLoginFlowAlias: "first broker login",
      config: {
        clientId: "not-used",
        clientSecret: "not-used",
        sameDeviceEnabled: "true",
        crossDeviceEnabled: "false",
        walletScheme: "openid4vp://",
        responseMode: "direct_post",
        enforceHaip: "false",
        clientIdScheme: "plain",
        x509CertificatePem: "",
        x509SigningKeyJwk: "",
        trustListUrl: $trust_list_url,
        trustListLoTEType: $trust_list_lote_type,
        trustedAuthoritiesMode: "none",
        statusListMaxCacheTtlSeconds: "0",
        userMappingClaim: "family_name",
        userMappingClaimMdoc: "family_name",
        dcqlQuery: $dcql_query
      }
    }')"

echo
echo "Ready:"
echo "  realm=${KEYCLOAK_REALM}"
echo "  client=${OIDC_CLIENT_ID}"
echo "  authorize=${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth"
echo "  redirect_uri=${OIDC_REDIRECT_URI}"
echo "  trust_list_url=${OID4VP_TRUST_LIST_URL}"
