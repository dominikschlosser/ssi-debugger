#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ensure_oid4vc_dev() {
  if [[ -n "${OID4VC_DEV_BIN:-}" ]]; then
    export PATH="$(dirname "${OID4VC_DEV_BIN}"):${PATH}"
    return 0
  fi
  if command -v oid4vc-dev >/dev/null 2>&1; then
    export OID4VC_DEV_BIN="$(command -v oid4vc-dev)"
    export PATH="$(dirname "${OID4VC_DEV_BIN}"):${PATH}"
    return 0
  fi
  if ! command -v go >/dev/null 2>&1; then
    echo "Missing required command: go" >&2
    exit 1
  fi

  local gobin
  gobin="$(go env GOBIN)"
  if [[ -z "${gobin}" ]]; then
    gobin="$(go env GOPATH)/bin"
  fi
  mkdir -p "${gobin}"

  echo "oid4vc-dev not found. Installing latest with Go..."
  GOBIN="${gobin}" go install github.com/dominikschlosser/oid4vc-dev@latest
  export OID4VC_DEV_BIN="${gobin}/oid4vc-dev"
  export PATH="${gobin}:${PATH}"
}

usage() {
  cat <<'EOF'
Usage: ./start.sh [--setup-only|--browser]

  default      Download the provider, generate the wallet, start Keycloak, bootstrap the verifier, and run the headless login flow
  --browser    Run the browser-driven flow after setup
  --setup-only Download the provider, generate the wallet, start Keycloak, and bootstrap the verifier only
EOF
}

mode="headless"
if [[ $# -gt 1 ]]; then
  usage >&2
  exit 1
fi
if [[ $# -eq 1 ]]; then
  case "$1" in
    --setup-only) mode="setup-only" ;;
    --browser) mode="browser" ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
fi

cd "${SCRIPT_DIR}"

ensure_oid4vc_dev
./scripts/download-extension.sh
./scripts/generate-wallet.sh
docker compose up -d
./scripts/bootstrap.sh

case "${mode}" in
  headless)
    ./scripts/login.py
    ;;
  browser)
    "${OID4VC_DEV_BIN}" wallet register
    ./scripts/test-oidc-flow.sh
    ;;
  setup-only)
    echo
    echo "Verifier is ready."
    ;;
esac
