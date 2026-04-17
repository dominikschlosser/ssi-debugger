#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SCENARIO_DIR}/../.." && pwd)"
source "${REPO_ROOT}/examples/lib/public-ngrok.sh"
example_load_env_files "${REPO_ROOT}/.env" "${SCENARIO_DIR}/.env"

KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8081}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-wallet-haip-demo}"
KEYCLOAK_SIGNING_KEY_PATH="${KEYCLOAK_SIGNING_KEY_PATH:-${SCENARIO_DIR}/keycloak-signing-key.pem}"
KEYCLOAK_SIGNING_CERT_PATH="${KEYCLOAK_SIGNING_CERT_PATH:-${SCENARIO_DIR}/keycloak-signing-cert.pem}"

OID4VCI_USER="${OID4VCI_USER:-alice}"
OID4VCI_USER_PASSWORD="${OID4VCI_USER_PASSWORD:-alice}"
OID4VCI_CREDENTIAL_SCOPE="${OID4VCI_CREDENTIAL_SCOPE:-membership-credential}"
APP_CLIENT_ID="${APP_CLIENT_ID:-wallet-haip-app}"
APP_BASE_URL="${APP_BASE_URL:-http://127.0.0.1:8091}"
APP_REDIRECT_URI="${APP_REDIRECT_URI:-${APP_BASE_URL%/}/callback}"
OID4VP_FIRST_BROKER_FLOW_ALIAS="${OID4VP_FIRST_BROKER_FLOW_ALIAS:-oid4vp-user-id-auto-link}"
ALLOWED_ISSUER="${ALLOWED_ISSUER:-${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}}"
OID4VP_TRUST_LIST_LOTE_TYPE="${OID4VP_TRUST_LIST_LOTE_TYPE:-http://uri.etsi.org/19602/LoTEType/local}"
KEYCLOAK_TRUST_LIST_PATH="${KEYCLOAK_TRUST_LIST_PATH:-${SCENARIO_DIR}/keycloak-trustlist.jwt}"
VERIFIER_CERT_CHAIN_PATH="${VERIFIER_CERT_CHAIN_PATH:-${SCENARIO_DIR}/verifier-cert-chain.pem}"
VERIFIER_CA_CERT_PATH="${VERIFIER_CA_CERT_PATH:-${SCENARIO_DIR}/verifier-ca-cert.pem}"
VERIFIER_SIGNING_KEY_JWK_PATH="${VERIFIER_SIGNING_KEY_JWK_PATH:-${SCENARIO_DIR}/verifier-signing-key.jwk}"
OID4VP_PUBLIC_WALLET="${OID4VP_PUBLIC_WALLET:-false}"
OID4VP_SANDBOX_PEM_PATH="${OID4VP_SANDBOX_PEM_PATH:-}"
OID4VP_SANDBOX_VERIFIER_INFO_PATH="${OID4VP_SANDBOX_VERIFIER_INFO_PATH:-}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need curl
need jq
need openssl
need go

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

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "Required file not found: $path" >&2
    exit 1
  fi
}

optional_file() {
  local path="$1"
  if [[ -n "${path}" ]] && [[ -f "${path}" ]]; then
    printf '%s\n' "${path}"
  fi
}

realm_id() {
  api GET "/admin/realms/${KEYCLOAK_REALM}" | jq -er '.id'
}

lookup_user_id() {
  local username="$1"
  api GET "/admin/realms/${KEYCLOAK_REALM}/users?username=${username}&exact=true" \
    | jq -er '.[0].id'
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

set_user_password() {
  local user_id="$1"
  api_json PUT "/admin/realms/${KEYCLOAK_REALM}/users/${user_id}/reset-password" \
    "$(json_payload --arg password "$OID4VCI_USER_PASSWORD" '{
      type: "password",
      temporary: false,
      value: $password
    }')" >/dev/null
}

update_identity_provider() {
  local instance_json
  local verifier_cert_path="${VERIFIER_CERT_CHAIN_PATH}"
  local verifier_signing_key_path="${VERIFIER_SIGNING_KEY_JWK_PATH}"
  local sandbox_verifier_info_path=""
  local public_wallet_flag="false"

  if [[ "${OID4VP_PUBLIC_WALLET}" == "true" ]]; then
    public_wallet_flag="true"
    verifier_cert_path="$(
      optional_file "${OID4VP_SANDBOX_PEM_PATH}" \
        || example_find_sandbox_pem "${REPO_ROOT}" "${SCENARIO_DIR}" \
        || printf '%s\n' "${VERIFIER_CERT_CHAIN_PATH}"
    )"
    sandbox_verifier_info_path="$(
      optional_file "${OID4VP_SANDBOX_VERIFIER_INFO_PATH}" \
        || example_find_sandbox_verifier_info "${REPO_ROOT}" "${SCENARIO_DIR}" \
        || true
    )"
    if [[ "${verifier_cert_path}" != "${VERIFIER_CERT_CHAIN_PATH}" ]]; then
      verifier_signing_key_path=""
    fi
  fi

  instance_json="$(
    api GET "/admin/realms/${KEYCLOAK_REALM}/identity-provider/instances/oid4vp" \
      | jq -c \
        --arg allowed_issuer "$ALLOWED_ISSUER" \
        --arg trust_list_url "$OID4VP_TRUST_LIST_URL" \
        --arg trust_list_lote_type "$OID4VP_TRUST_LIST_LOTE_TYPE" \
        --arg dcql_query "$DCQL_QUERY" \
        --arg first_broker_flow_alias "$OID4VP_FIRST_BROKER_FLOW_ALIAS" \
        --arg public_wallet_flag "$public_wallet_flag" \
        --rawfile verifier_cert_chain "${verifier_cert_path}" \
        --rawfile verifier_signing_key_jwk "${verifier_signing_key_path}" \
        --rawfile verifier_info "${sandbox_verifier_info_path}" '
          .firstBrokerLoginFlowAlias = $first_broker_flow_alias
          | .config.allowedIssuers = $allowed_issuer
          | .config.trustListUrl = $trust_list_url
          | .config.trustListLoTEType = $trust_list_lote_type
          | .config.sameDeviceEnabled = "true"
          | .config.crossDeviceEnabled = (if $public_wallet_flag == "true" then "true" else (.config.crossDeviceEnabled // "false") end)
          | .config.walletScheme = "haip-vp://"
          | .config.responseMode = "direct_post.jwt"
          | .config.enforceHaip = "true"
          | .config.clientIdScheme = "x509_hash"
          | .config.x509CertificatePem = $verifier_cert_chain
          | if ($verifier_signing_key_jwk | length) > 0 then
              .config.x509SigningKeyJwk = $verifier_signing_key_jwk
            else
              .config |= del(.x509SigningKeyJwk)
            end
          | if $public_wallet_flag == "true" and ($verifier_info | length) > 0 then
              .config.verifierInfo = $verifier_info
            else
              .
            end
          | .config.userMappingClaim = "keycloak_user_id"
          | .config.userMappingClaimMdoc = "keycloak_user_id"
          | .config.dcqlQuery = $dcql_query
        '
  )"
  api_json PUT "/admin/realms/${KEYCLOAK_REALM}/identity-provider/instances/oid4vp" "${instance_json}" >/dev/null
}

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

require_file "${SCENARIO_DIR}/providers/keycloak-extension-oid4vp.jar"
require_file "${SCENARIO_DIR}/providers/oid4vp-user-id-link-provider.jar"
"${SCENARIO_DIR}/scripts/generate-keycloak-signing-cert.sh"
(
  cd "${SCENARIO_DIR}/../.."
  VERIFIER_CERT_CHAIN_PATH="${VERIFIER_CERT_CHAIN_PATH}" \
  VERIFIER_CA_CERT_PATH="${VERIFIER_CA_CERT_PATH}" \
  VERIFIER_SIGNING_KEY_JWK_PATH="${VERIFIER_SIGNING_KEY_JWK_PATH}" \
  go run ./examples/keycloak-issuer-verifier-haip-app/scripts/generate-verifier-material
)
require_file "${KEYCLOAK_SIGNING_KEY_PATH}"
require_file "${KEYCLOAK_SIGNING_CERT_PATH}"
require_file "${VERIFIER_CERT_CHAIN_PATH}"
require_file "${VERIFIER_CA_CERT_PATH}"
require_file "${VERIFIER_SIGNING_KEY_JWK_PATH}"

if [[ -z "${OID4VP_TRUST_LIST_URL:-}" ]]; then
  app_port="$(printf '%s' "${APP_REDIRECT_URI}" | sed -nE 's#^[a-z]+://[^/:]+:([0-9]+)(/.*)?$#\1#p')"
  if [[ -z "${app_port}" ]]; then
    echo "Could not derive trust list URL from APP_REDIRECT_URI=${APP_REDIRECT_URI}" >&2
    exit 1
  fi
  OID4VP_TRUST_LIST_URL="http://host.docker.internal:${app_port}/keycloak-trustlist.jwt"
fi

echo "Waiting for Keycloak at ${KEYCLOAK_BASE_URL}..."
wait_for_endpoint "${KEYCLOAK_BASE_URL}/realms/master"
wait_for_endpoint "${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/.well-known/openid-configuration"
ADMIN_TOKEN="$(admin_token)"

REALM_ID="$(realm_id)"

echo "Importing persistent RS256 realm signing key..."
configure_static_realm_signing_key "${REALM_ID}"
assert_static_realm_signing_key_active

USER_ID="$(lookup_user_id "${OID4VCI_USER}")"

echo "Setting password for ${OID4VCI_USER}..."
set_user_password "${USER_ID}"

echo "Generating trust list for the Keycloak signing certificate..."
(
  cd "${SCENARIO_DIR}/../.."
  KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL}" \
  KEYCLOAK_REALM="${KEYCLOAK_REALM}" \
  KEYCLOAK_TRUST_LIST_PATH="${KEYCLOAK_TRUST_LIST_PATH}" \
  go run ./examples/keycloak-issuer-verifier-haip-app/scripts/generate-keycloak-trustlist
)

echo "Updating OID4VP identity provider for HAIP verifier mode..."
update_identity_provider

echo
echo "Ready:"
echo "  realm=${KEYCLOAK_REALM}"
echo "  app_client=${APP_CLIENT_ID}"
echo "  allowed_issuer=${ALLOWED_ISSUER}"
echo "  trust_list_url=${OID4VP_TRUST_LIST_URL}"
echo "  trust_list_lote_type=${OID4VP_TRUST_LIST_LOTE_TYPE}"
echo "  client_id_scheme=x509_hash"
echo "  wallet_scheme=haip-vp://"
echo "  response_mode=direct_post.jwt"
echo "  credential_configuration_id=${OID4VCI_CREDENTIAL_SCOPE}"
echo "  first_broker_flow=${OID4VP_FIRST_BROKER_FLOW_ALIAS}"
echo "  app_redirect_uri=${APP_REDIRECT_URI}"
if [[ "${OID4VP_PUBLIC_WALLET}" == "true" ]]; then
  echo "  cross_device_enabled=true"
  if [[ -n "$(optional_file "${OID4VP_SANDBOX_PEM_PATH}" || example_find_sandbox_pem "${REPO_ROOT}" "${SCENARIO_DIR}" || true)" ]]; then
    echo "  verifier_cert=sandbox"
  fi
  if [[ -n "$(optional_file "${OID4VP_SANDBOX_VERIFIER_INFO_PATH}" || example_find_sandbox_verifier_info "${REPO_ROOT}" "${SCENARIO_DIR}" || true)" ]]; then
    echo "  verifier_info=sandbox"
  fi
fi
