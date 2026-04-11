#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

CA_KEY="${SCENARIO_DIR}/keycloak-ca-key.pem"
CA_CERT="${SCENARIO_DIR}/keycloak-ca-cert.pem"
SERVER_KEY="${SCENARIO_DIR}/keycloak-key.pem"
SERVER_CSR="${SCENARIO_DIR}/keycloak-cert.csr"
SERVER_CERT="${SCENARIO_DIR}/keycloak-cert.pem"
SERVER_EXT="${SCENARIO_DIR}/keycloak-cert.ext"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need openssl

rm -f "${SERVER_CSR}" "${SERVER_EXT}"

openssl genrsa -out "${CA_KEY}" 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days 3650 \
  -subj "/CN=oid4vc-dev Keycloak Local CA" \
  -out "${CA_CERT}" >/dev/null 2>&1

openssl genrsa -out "${SERVER_KEY}" 2048 >/dev/null 2>&1
openssl req -new -key "${SERVER_KEY}" \
  -subj "/CN=localhost" \
  -out "${SERVER_CSR}" >/dev/null 2>&1

cat > "${SERVER_EXT}" <<'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
EOF

openssl x509 -req -in "${SERVER_CSR}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -CAcreateserial \
  -out "${SERVER_CERT}" -days 3650 -sha256 -extfile "${SERVER_EXT}" >/dev/null 2>&1

rm -f "${SERVER_CSR}" "${SERVER_EXT}" "${SCENARIO_DIR}/keycloak-ca-cert.srl"

echo "Generated:"
echo "  ${CA_CERT}"
echo "  ${SERVER_CERT}"
echo "  ${SERVER_KEY}"
