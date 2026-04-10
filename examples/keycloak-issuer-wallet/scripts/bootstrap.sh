#!/usr/bin/env bash
set -euo pipefail

KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
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

lookup_id_by_name() {
  local path="$1"
  local name="$2"
  api GET "$path" | jq -er --arg name "$name" '.[] | select(.name == $name) | .id' | head -n 1
}

lookup_client_id() {
  local client_id="$1"
  api GET "/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${client_id}" \
    | jq -er '.[0].id'
}

lookup_user_id() {
  local username="$1"
  api GET "/admin/realms/${KEYCLOAK_REALM}/users?username=${username}&exact=true" \
    | jq -er '.[0].id'
}

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
  "$(json_payload --arg realm "$KEYCLOAK_REALM" '{realm: $realm, enabled: true, sslRequired: "NONE", verifiableCredentialsEnabled: true}')"

echo "Creating user ${OID4VCI_USER}..."
api_json POST "/admin/realms/${KEYCLOAK_REALM}/users" \
  "$(json_payload \
    --arg username "$OID4VCI_USER" \
    --arg email "${OID4VCI_USER}@example.com" \
    '{
      username: $username,
      enabled: true,
      emailVerified: true,
      firstName: "Alice",
      lastName: "Issuer",
      email: $email
    }')"

USER_ID="$(lookup_user_id "$OID4VCI_USER")"

echo "Setting password for ${OID4VCI_USER}..."
api_json PUT "/admin/realms/${KEYCLOAK_REALM}/users/${USER_ID}/reset-password" \
  "$(json_payload --arg password "$OID4VCI_USER_PASSWORD" '{
    type: "password",
    temporary: false,
    value: $password
  }')"

echo "Creating OID4VCI client scope ${OID4VCI_CREDENTIAL_SCOPE}..."
api_json POST "/admin/realms/${KEYCLOAK_REALM}/client-scopes" \
  "$(json_payload \
    --arg name "$OID4VCI_CREDENTIAL_SCOPE" \
    --arg vct "https://credentials.example.com/membership" \
    '{
      name: $name,
      protocol: "oid4vc",
      attributes: {
        "include.in.token.scope": "true",
        "vc.credential_configuration_id": $name,
        "vc.credential_identifier": "membership-credential-id",
        "vc.format": "dc+sd-jwt",
        "vc.verifiable_credential_type": $vct,
        "vc.credential_signing_alg": "ES256",
        "vc.credential_build_config.token_jws_type": "dc+sd-jwt",
        "vc.binding_required": "true",
        "vc.binding_required_proof_types": "jwt",
        "vc.cryptographic_binding_methods_supported": "jwk"
      },
      protocolMappers: [
        {
          "name": "given-name-mapper",
          "protocol": "oid4vc",
          "protocolMapper": "oid4vc-user-attribute-mapper",
          "config": {
            "claim.name": "given_name",
            "userAttribute": "firstName"
          }
        },
        {
          "name": "family-name-mapper",
          "protocol": "oid4vc",
          "protocolMapper": "oid4vc-user-attribute-mapper",
          "config": {
            "claim.name": "family_name",
            "userAttribute": "lastName"
          }
        },
        {
          "name": "email-mapper",
          "protocol": "oid4vc",
          "protocolMapper": "oid4vc-user-attribute-mapper",
          "config": {
            "claim.name": "email",
            "userAttribute": "email"
          }
        },
        {
          "name": "jti-mapper",
          "protocol": "oid4vc",
          "protocolMapper": "oid4vc-generated-id-mapper",
          "config": {
            "claim.name": "jti"
          }
        },
        {
          "name": "iat-mapper",
          "protocol": "oid4vc",
          "protocolMapper": "oid4vc-issued-at-time-claim-mapper",
          "config": {
            "claim.name": "iat"
          }
        }
      ]
    }')"

SCOPE_ID="$(lookup_id_by_name "/admin/realms/${KEYCLOAK_REALM}/client-scopes" "$OID4VCI_CREDENTIAL_SCOPE")"

echo "Creating public client ${OID4VCI_CLIENT_ID}..."
api_json POST "/admin/realms/${KEYCLOAK_REALM}/clients" \
  "$(json_payload \
    --arg client_id "$OID4VCI_CLIENT_ID" \
    '{
      clientId: $client_id,
      enabled: true,
      publicClient: true,
      directAccessGrantsEnabled: true,
      standardFlowEnabled: true,
      redirectUris: ["http://127.0.0.1/*"],
      webOrigins: ["*"],
      attributes: {
        "oid4vci.enabled": "true",
        "pkce.code.challenge.method": "S256"
      }
    }')"

CLIENT_UUID="$(lookup_client_id "$OID4VCI_CLIENT_ID")"

echo "Assigning optional client scope ${OID4VCI_CREDENTIAL_SCOPE}..."
api PUT "/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_UUID}/optional-client-scopes/${SCOPE_ID}"

echo "Assigning credential-offer-create role to ${OID4VCI_USER}..."
ROLE_JSON="$(api GET "/admin/realms/${KEYCLOAK_REALM}/roles/credential-offer-create")"
api_json POST "/admin/realms/${KEYCLOAK_REALM}/users/${USER_ID}/role-mappings/realm" "[${ROLE_JSON}]"

echo
echo "Issuer metadata:"
echo "  ${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/.well-known/openid-credential-issuer"
echo
echo "Offer endpoint:"
echo "  ${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/oid4vc/create-credential-offer"
echo
echo "Ready:"
echo "  realm=${KEYCLOAK_REALM}"
echo "  user=${OID4VCI_USER}"
echo "  client=${OID4VCI_CLIENT_ID}"
echo "  credential_configuration_id=${OID4VCI_CREDENTIAL_SCOPE}"
