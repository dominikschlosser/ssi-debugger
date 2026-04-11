#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-wallet-app-demo}"
KEYCLOAK_SIGNING_KEY_PATH="${KEYCLOAK_SIGNING_KEY_PATH:-${SCENARIO_DIR}/keycloak-signing-key.pem}"
KEYCLOAK_SIGNING_CERT_PATH="${KEYCLOAK_SIGNING_CERT_PATH:-${SCENARIO_DIR}/keycloak-signing-cert.pem}"

OID4VCI_CLIENT_ID="${OID4VCI_CLIENT_ID:-oid4vc-demo-client}"
OID4VCI_CREDENTIAL_SCOPE="${OID4VCI_CREDENTIAL_SCOPE:-membership-credential}"
OID4VCI_USER="${OID4VCI_USER:-alice}"
OID4VCI_USER_PASSWORD="${OID4VCI_USER_PASSWORD:-alice}"
OID4VP_FIRST_BROKER_FLOW_ALIAS="${OID4VP_FIRST_BROKER_FLOW_ALIAS:-oid4vp-user-id-auto-link}"
OID4VP_LINK_PROVIDER_ID="${OID4VP_LINK_PROVIDER_ID:-oid4vp-detect-user-by-id}"

APP_CLIENT_ID="${APP_CLIENT_ID:-wallet-app}"
APP_REDIRECT_URI="${APP_REDIRECT_URI:-http://127.0.0.1:8090/callback}"
ALLOWED_ISSUER="${ALLOWED_ISSUER:-${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}}"
OID4VP_TRUST_LIST_URL="${OID4VP_TRUST_LIST_URL:-http://host.docker.internal:8090/keycloak-trustlist.jwt}"
OID4VP_TRUST_LIST_LOTE_TYPE="${OID4VP_TRUST_LIST_LOTE_TYPE:-http://uri.etsi.org/19602/LoTEType/local}"
KEYCLOAK_TRUST_LIST_PATH="${KEYCLOAK_TRUST_LIST_PATH:-${SCENARIO_DIR}/keycloak-trustlist.jwt}"
OID4VP_TRUST_MODE="${OID4VP_TRUST_MODE:-trustlist}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need curl
need jq
need openssl
if [[ "${OID4VP_TRUST_MODE}" == "trustlist" ]]; then
  need go
fi

curl_common() {
  if [[ "${KEYCLOAK_BASE_URL}" == https://* ]] && [[ -n "${KEYCLOAK_CA_CERT:-}" ]] && [[ -f "${KEYCLOAK_CA_CERT}" ]]; then
    curl --cacert "${KEYCLOAK_CA_CERT}" "$@"
    return 0
  fi
  curl "$@"
}

wait_for_keycloak() {
  local ready_url="${KEYCLOAK_BASE_URL}/realms/master"
  for _ in $(seq 1 60); do
    if curl_common -fsS "$ready_url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "Keycloak did not become ready at ${ready_url}" >&2
  exit 1
}

admin_token() {
  curl_common -fsS \
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
  curl_common -fsS -X "$method" \
    "${KEYCLOAK_BASE_URL}${path}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "X-Forwarded-Proto: https" \
    "$@"
}

api_json() {
  local method="$1"
  local path="$2"
  local payload="$3"
  curl_common -fsS -X "$method" \
    "${KEYCLOAK_BASE_URL}${path}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "X-Forwarded-Proto: https" \
    -H "Content-Type: application/json" \
    --data-binary @- <<<"$payload"
}

json_payload() {
  jq -c -n "$@"
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "Required file not found: $path" >&2
    exit 1
  fi
}

realm_id() {
  api GET "/admin/realms/${KEYCLOAK_REALM}" | jq -er '.id'
}

configure_static_realm_signing_key() {
  local realm_id_value="$1"
  local cert_b64 existing_id
  cert_b64="$(openssl x509 -outform DER -in "${KEYCLOAK_SIGNING_CERT_PATH}" | base64 | tr -d '\n')"
  existing_id="$(
    api GET "/admin/realms/${KEYCLOAK_REALM}/components?type=org.keycloak.keys.KeyProvider" \
      | jq -er --arg cert_b64 "$cert_b64" '
          map(select(.providerId == "rsa"))[]
          | select((.config.certificate[0] // "") | gsub("-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|[\\n\\r ]"; "") == $cert_b64)
          | .id
        ' 2>/dev/null | head -n 1 || true
  )"
  if [[ -n "${existing_id}" ]]; then
    return 0
  fi

  api_json POST "/admin/realms/${KEYCLOAK_REALM}/components" \
    "$(jq -cn \
      --arg parent_id "${realm_id_value}" \
      --rawfile private_key "${KEYCLOAK_SIGNING_KEY_PATH}" \
      --rawfile certificate "${KEYCLOAK_SIGNING_CERT_PATH}" \
      '{
        name: "static-rsa-signing-key",
        providerId: "rsa",
        providerType: "org.keycloak.keys.KeyProvider",
        parentId: $parent_id,
        config: {
          priority: ["1000"],
          enabled: ["true"],
          active: ["true"],
          algorithm: ["RS256"],
          privateKey: [$private_key],
          certificate: [$certificate]
        }
      }')" >/dev/null

  while read -r generated_id; do
    if [[ -n "${generated_id}" ]]; then
      api DELETE "/admin/realms/${KEYCLOAK_REALM}/components/${generated_id}" >/dev/null
    fi
  done < <(
    api GET "/admin/realms/${KEYCLOAK_REALM}/components?type=org.keycloak.keys.KeyProvider" \
      | jq -r '.[] | select(.providerId == "rsa-generated") | .id'
  )
}

assert_static_realm_signing_key_active() {
  local expected_cert active_cert
  expected_cert="$(openssl x509 -outform DER -in "${KEYCLOAK_SIGNING_CERT_PATH}" | base64 | tr -d '\n')"
  active_cert="$(
    api GET "/admin/realms/${KEYCLOAK_REALM}/keys" \
      | jq -er '.keys[] | select(.algorithm == "RS256" and .status == "ACTIVE") | .certificate' \
      | head -n 1
  )"
  if [[ "${active_cert}" != "${expected_cert}" ]]; then
    echo "Expected static Keycloak RS256 signing certificate to be active, but a different certificate is active." >&2
    exit 1
  fi
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

create_basic_flow() {
  local alias="$1"
  api_json POST "/admin/realms/${KEYCLOAK_REALM}/authentication/flows" \
    "$(json_payload \
      --arg alias "$alias" \
      '{
        alias: $alias,
        description: "Automatically link OID4VP wallet logins to existing Keycloak users via keycloak_user_id",
        providerId: "basic-flow",
        topLevel: true,
        builtIn: false
      }')"
}

add_flow_execution() {
  local flow_alias="$1"
  local provider_id="$2"
  api_json POST "/admin/realms/${KEYCLOAK_REALM}/authentication/flows/${flow_alias}/executions/execution" \
    "$(json_payload --arg provider "$provider_id" '{provider: $provider}')"
}

set_flow_requirement() {
  local flow_alias="$1"
  local provider_id="$2"
  local requirement="$3"
  local execution_json
  execution_json="$(
    api GET "/admin/realms/${KEYCLOAK_REALM}/authentication/flows/${flow_alias}/executions" \
      | jq -cer --arg provider_id "$provider_id" --arg requirement "$requirement" \
        '.[] | select(.providerId == $provider_id) | .requirement = $requirement' \
      | head -n 1
  )"
  api_json PUT "/admin/realms/${KEYCLOAK_REALM}/authentication/flows/${flow_alias}/executions" "$execution_json"
}

ensure_user_profile_attribute() {
  local attribute_name="$1"
  local profile_json
  local updated_profile_json

  profile_json="$(api GET "/admin/realms/${KEYCLOAK_REALM}/users/profile")"
  updated_profile_json="$(
    printf '%s' "$profile_json" | jq -c --arg attribute_name "$attribute_name" '
      if any(.attributes[]?; .name == $attribute_name) then
        .
      else
        .attributes += [{
          name: $attribute_name,
          displayName: "Keycloak user id",
          permissions: {
            view: ["admin"],
            edit: ["admin"]
          },
          multivalued: false
        }]
      end
    '
  )"
  api_json PUT "/admin/realms/${KEYCLOAK_REALM}/users/profile" "$updated_profile_json"
}

require_file "${SCENARIO_DIR}/providers/keycloak-extension-oid4vp.jar"
require_file "${SCENARIO_DIR}/providers/oid4vp-user-id-link-provider.jar"
"${SCENARIO_DIR}/scripts/generate-keycloak-signing-cert.sh"
require_file "${KEYCLOAK_SIGNING_KEY_PATH}"
require_file "${KEYCLOAK_SIGNING_CERT_PATH}"

DCQL_QUERY="$(jq -c -n '{
  credentials: [
    {
      id: "membership_sd_jwt",
      format: "dc+sd-jwt",
      meta: {vct_values: ["https://credentials.example.com/membership"]},
      claims: [
        {path: ["keycloak_user_id"]},
        {path: ["given_name"]},
        {path: ["family_name"]},
        {path: ["email"]}
      ]
    }
  ]
}')"

echo "Waiting for Keycloak at ${KEYCLOAK_BASE_URL}..."
wait_for_keycloak
ADMIN_TOKEN="$(admin_token)"

if curl_common -fsS -o /dev/null -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "X-Forwarded-Proto: https" \
  "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}" 2>/dev/null; then
  echo "Deleting existing realm ${KEYCLOAK_REALM}..."
  delete_status="$(
    curl_common -sS -o /dev/null -w '%{http_code}' \
      -X DELETE \
      "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -H "X-Forwarded-Proto: https"
  )"
  if [[ "${delete_status}" != "204" && "${delete_status}" != "404" ]]; then
    echo "Deleting realm ${KEYCLOAK_REALM} failed with HTTP ${delete_status}" >&2
    exit 1
  fi
fi

echo "Creating realm ${KEYCLOAK_REALM}..."
api_json POST "/admin/realms" \
  "$(json_payload --arg realm "$KEYCLOAK_REALM" '{realm: $realm, enabled: true, sslRequired: "NONE", verifiableCredentialsEnabled: true}')"

REALM_ID="$(realm_id)"

echo "Importing persistent RS256 realm signing key..."
configure_static_realm_signing_key "${REALM_ID}"
assert_static_realm_signing_key_active

echo "Registering keycloak_user_id in the realm user profile..."
ensure_user_profile_attribute "keycloak_user_id"

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

echo "Persisting the Keycloak user ID as keycloak_user_id..."
USER_REP="$(api GET "/admin/realms/${KEYCLOAK_REALM}/users/${USER_ID}")"
api_json PUT "/admin/realms/${KEYCLOAK_REALM}/users/${USER_ID}" \
  "$(printf '%s' "$USER_REP" | jq -c --arg user_id "$USER_ID" '.attributes.keycloak_user_id = [$user_id]')"

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
        "vc.credential_signing_alg": "RS256",
        "vc.credential_build_config.token_jws_type": "dc+sd-jwt",
        "vc.binding_required": "true",
        "vc.binding_required_proof_types": "jwt",
        "vc.cryptographic_binding_methods_supported": "jwk"
      },
      protocolMappers: [
        {
          "name": "keycloak-user-id-mapper",
          "protocol": "oid4vc",
          "protocolMapper": "oid4vc-user-attribute-mapper",
          "config": {
            "claim.name": "keycloak_user_id",
            "userAttribute": "keycloak_user_id"
          }
        },
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
          "name": "preferred-username-mapper",
          "protocol": "oid4vc",
          "protocolMapper": "oid4vc-user-attribute-mapper",
          "config": {
            "claim.name": "preferred_username",
            "userAttribute": "username"
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

echo "Creating OID4VCI public client ${OID4VCI_CLIENT_ID}..."
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

ISSUER_CLIENT_UUID="$(lookup_client_id "$OID4VCI_CLIENT_ID")"

echo "Assigning optional client scope ${OID4VCI_CREDENTIAL_SCOPE}..."
api PUT "/admin/realms/${KEYCLOAK_REALM}/clients/${ISSUER_CLIENT_UUID}/optional-client-scopes/${SCOPE_ID}"

echo "Assigning credential-offer-create role to ${OID4VCI_USER}..."
ROLE_JSON="$(api GET "/admin/realms/${KEYCLOAK_REALM}/roles/credential-offer-create")"
api_json POST "/admin/realms/${KEYCLOAK_REALM}/users/${USER_ID}/role-mappings/realm" "[${ROLE_JSON}]"

echo "Creating app client ${APP_CLIENT_ID}..."
api_json POST "/admin/realms/${KEYCLOAK_REALM}/clients" \
  "$(json_payload \
    --arg client_id "$APP_CLIENT_ID" \
    --arg redirect_uri "$APP_REDIRECT_URI" \
    '{
      clientId: $client_id,
      enabled: true,
      publicClient: true,
      directAccessGrantsEnabled: false,
      standardFlowEnabled: true,
      redirectUris: [
        $redirect_uri,
        "http://127.0.0.1:8090/*",
        "http://localhost:8090/*"
      ],
      webOrigins: ["*"],
      protocol: "openid-connect",
      attributes: {
        "pkce.code.challenge.method": "S256",
        "oid4vci.enabled": "true"
      }
    }')"

APP_CLIENT_UUID="$(lookup_client_id "$APP_CLIENT_ID")"

echo "Assigning optional client scope ${OID4VCI_CREDENTIAL_SCOPE} to ${APP_CLIENT_ID}..."
api PUT "/admin/realms/${KEYCLOAK_REALM}/clients/${APP_CLIENT_UUID}/optional-client-scopes/${SCOPE_ID}"

if [[ "${OID4VP_TRUST_MODE}" == "trustlist" ]]; then
  echo "Generating trust list for the Keycloak signing certificate..."
  (
    cd "${SCENARIO_DIR}/../.."
    KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL}" \
    KEYCLOAK_REALM="${KEYCLOAK_REALM}" \
    KEYCLOAK_TRUST_LIST_PATH="${KEYCLOAK_TRUST_LIST_PATH}" \
    go run ./examples/keycloak-issuer-verifier-app/scripts/generate-keycloak-trustlist.go
  )
else
  rm -f "${KEYCLOAK_TRUST_LIST_PATH}"
fi

echo "Creating custom first broker login flow ${OID4VP_FIRST_BROKER_FLOW_ALIAS}..."
create_basic_flow "${OID4VP_FIRST_BROKER_FLOW_ALIAS}"
add_flow_execution "${OID4VP_FIRST_BROKER_FLOW_ALIAS}" "${OID4VP_LINK_PROVIDER_ID}"
add_flow_execution "${OID4VP_FIRST_BROKER_FLOW_ALIAS}" "idp-auto-link"
set_flow_requirement "${OID4VP_FIRST_BROKER_FLOW_ALIAS}" "${OID4VP_LINK_PROVIDER_ID}" "REQUIRED"
set_flow_requirement "${OID4VP_FIRST_BROKER_FLOW_ALIAS}" "idp-auto-link" "REQUIRED"

echo "Configuring OID4VP identity provider..."
api_json POST "/admin/realms/${KEYCLOAK_REALM}/identity-provider/instances" \
  "$(json_payload \
    --arg allowed_issuer "$ALLOWED_ISSUER" \
    --arg trust_list_url "$OID4VP_TRUST_LIST_URL" \
    --arg trust_list_lote_type "$OID4VP_TRUST_LIST_LOTE_TYPE" \
    --arg trust_mode "$OID4VP_TRUST_MODE" \
    --arg dcql_query "$DCQL_QUERY" \
    --arg first_broker_flow_alias "$OID4VP_FIRST_BROKER_FLOW_ALIAS" \
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
      firstBrokerLoginFlowAlias: $first_broker_flow_alias,
      config: ({
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
        trustedAuthoritiesMode: "none",
        allowedIssuers: $allowed_issuer,
        trustListMaxCacheTtlSeconds: "0",
        trustListMaxStaleAgeSeconds: "0",
        statusListMaxCacheTtlSeconds: "0",
        userMappingClaim: "keycloak_user_id",
        userMappingClaimMdoc: "keycloak_user_id",
        dcqlQuery: $dcql_query
      } + (if $trust_mode == "trustlist" then {trustListUrl: $trust_list_url, trustListLoTEType: $trust_list_lote_type} else {} end))
    }')"

echo
echo "Ready:"
echo "  realm=${KEYCLOAK_REALM}"
echo "  issuer_client=${OID4VCI_CLIENT_ID}"
echo "  app_client=${APP_CLIENT_ID}"
echo "  allowed_issuer=${ALLOWED_ISSUER}"
if [[ "${OID4VP_TRUST_MODE}" == "trustlist" ]]; then
  echo "  trust_list_url=${OID4VP_TRUST_LIST_URL}"
  echo "  trust_list_lote_type=${OID4VP_TRUST_LIST_LOTE_TYPE}"
else
  echo "  trust_mode=metadata"
fi
echo "  credential_configuration_id=${OID4VCI_CREDENTIAL_SCOPE}"
echo "  first_broker_flow=${OID4VP_FIRST_BROKER_FLOW_ALIAS}"
echo "  app_redirect_uri=${APP_REDIRECT_URI}"
