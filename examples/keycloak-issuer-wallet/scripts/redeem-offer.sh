#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SCENARIO_DIR}/../.." && pwd)"

OID4VC_WALLET_DIR="${OID4VC_WALLET_DIR:-${SCENARIO_DIR}/.wallet}"

resolve_oid4vc_dev_bin() {
  if [[ -n "${OID4VC_DEV_BIN:-}" ]]; then
    printf '%s\n' "${OID4VC_DEV_BIN}"
    return 0
  fi
  if [[ -x "${REPO_ROOT}/oid4vc-dev" ]]; then
    printf '%s\n' "${REPO_ROOT}/oid4vc-dev"
    return 0
  fi
  if command -v oid4vc-dev >/dev/null 2>&1; then
    command -v oid4vc-dev
    return 0
  fi
  printf '%s\n' "go run ${REPO_ROOT}"
}

run_oid4vc_dev() {
  local bin
  bin="$(resolve_oid4vc_dev_bin)"
  if [[ "$bin" == go\ run* ]]; then
    (cd "$REPO_ROOT" && go run . "$@")
    return 0
  fi
  "$bin" "$@"
}

mkdir -p "${OID4VC_WALLET_DIR}"
OFFER_URI="$("${SCRIPT_DIR}/create-offer.sh")"

echo "Redeeming offer:"
echo "  ${OFFER_URI}"

run_oid4vc_dev wallet --wallet-dir "${OID4VC_WALLET_DIR}" accept "${OFFER_URI}"

echo
echo "Stored credentials:"
run_oid4vc_dev wallet --wallet-dir "${OID4VC_WALLET_DIR}" list
