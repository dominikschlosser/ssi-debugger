#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OID4VC_WALLET_PORT="${OID4VC_WALLET_PORT:-8085}"

require_oid4vc_dev() {
  if command -v oid4vc-dev >/dev/null 2>&1; then
    return 0
  fi
  echo "oid4vc-dev not found in PATH. Install it first or run ./start.sh." >&2
  exit 1
}

require_oid4vc_dev
oid4vc-dev wallet generate-pid \
  --docker \
  --base-url "http://host.docker.internal:${OID4VC_WALLET_PORT}"

echo
echo "Stored credentials:"
oid4vc-dev wallet list
