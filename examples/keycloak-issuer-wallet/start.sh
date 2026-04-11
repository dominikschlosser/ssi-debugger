#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ensure_oid4vc_dev() {
  if command -v oid4vc-dev >/dev/null 2>&1; then
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
  export PATH="${gobin}:${PATH}"
}

usage() {
  cat <<'EOF'
Usage: ./start.sh [--setup-only]

  default      Start Keycloak, bootstrap the issuer, and redeem a credential
  --setup-only Start Keycloak and bootstrap the issuer only
EOF
}

mode="full"
if [[ $# -gt 1 ]]; then
  usage >&2
  exit 1
fi
if [[ $# -eq 1 ]]; then
  case "$1" in
    --setup-only) mode="setup-only" ;;
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
docker compose up -d --force-recreate
./scripts/bootstrap.sh

if [[ "${mode}" == "full" ]]; then
  ./scripts/redeem-offer.sh
else
  echo
  echo "Issuer is ready."
fi
