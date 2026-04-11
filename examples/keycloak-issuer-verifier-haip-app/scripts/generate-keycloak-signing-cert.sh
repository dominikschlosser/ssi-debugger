#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KEY_PATH="${KEYCLOAK_SIGNING_KEY_PATH:-${SCENARIO_DIR}/keycloak-signing-key.pem}"
CERT_PATH="${KEYCLOAK_SIGNING_CERT_PATH:-${SCENARIO_DIR}/keycloak-signing-cert.pem}"
SUBJECT="${KEYCLOAK_SIGNING_CERT_SUBJECT:-/CN=wallet-haip-demo}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need openssl

if [[ -f "${KEY_PATH}" && -f "${CERT_PATH}" ]]; then
  echo "Using existing Keycloak signing key material:"
  echo "  ${KEY_PATH}"
  echo "  ${CERT_PATH}"
  exit 0
fi

mkdir -p "$(dirname "${KEY_PATH}")"

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -keyout "${KEY_PATH}" \
  -out "${CERT_PATH}" \
  -sha256 \
  -days 3650 \
  -nodes \
  -subj "${SUBJECT}" >/dev/null 2>&1

echo "Generated persistent Keycloak signing key material:"
echo "  ${KEY_PATH}"
echo "  ${CERT_PATH}"
