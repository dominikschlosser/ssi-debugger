#!/usr/bin/env bash
set -euo pipefail

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MODULE_DIR="${SCENARIO_DIR}/link-provider"
PROVIDERS_DIR="${SCENARIO_DIR}/providers"
TARGET_JAR="${MODULE_DIR}/target/oid4vp-user-id-link-provider.jar"
OUTPUT_JAR="${PROVIDERS_DIR}/oid4vp-user-id-link-provider.jar"

need mvn

mkdir -p "${PROVIDERS_DIR}"

echo "Building custom Keycloak broker authenticator..."
mvn -q -f "${MODULE_DIR}/pom.xml" -DskipTests package

cp "${TARGET_JAR}" "${OUTPUT_JAR}"

echo "Saved:"
echo "  ${OUTPUT_JAR}"
