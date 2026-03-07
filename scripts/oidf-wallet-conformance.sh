#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PORT=${PORT:-8085}
RUN_DIR=${OIDF_RUN_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/oidf-wallet-conformance.XXXXXX")}
SUITE_URL=${OIDF_SUITE_URL:-https://github.com/openid-certification/conformance-suite/archive/refs/heads/master.tar.gz}
WALLET_DIR=${OIDF_WALLET_DIR:-"$RUN_DIR/wallet"}
WALLET_URL=${OIDF_WALLET_URL:-"http://127.0.0.1:${PORT}"}
CONFORMANCE_SERVER=${CONFORMANCE_SERVER:-https://demo.certification.openid.net/}

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  . "$ROOT_DIR/.env"
  set +a
fi

if [ -z "${CONFORMANCE_TOKEN:-}" ]; then
  CONFORMANCE_TOKEN=${OIDF_TOKEN:-}
fi

if [ -z "${CONFORMANCE_TOKEN:-}" ]; then
  echo "error: set OIDF_TOKEN in .env or export CONFORMANCE_TOKEN" >&2
  exit 1
fi

SUITE_DIR="$RUN_DIR/conformance-suite-master"
VENV_DIR="$RUN_DIR/venv"
RESULTS_DIR="$RUN_DIR/results"
RUNNER_LOG="$RUN_DIR/runner.log"
WALLET_LOG="$RUN_DIR/wallet.log"

mkdir -p "$RESULTS_DIR" "$WALLET_DIR"

cleanup() {
  if [ -n "${WALLET_PID:-}" ] && kill -0 "$WALLET_PID" 2>/dev/null; then
    kill "$WALLET_PID" 2>/dev/null || true
    wait "$WALLET_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "Using run directory: $RUN_DIR"
echo "Fetching latest official OIDF runner..."
curl -fsSL "$SUITE_URL" | tar -xz -C "$RUN_DIR"

echo "Installing runner dependencies..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet -r "$SUITE_DIR/scripts/requirements.txt"

echo "Starting strict wallet on $WALLET_URL"
(
  cd "$ROOT_DIR"
  exec go run . wallet serve \
    --mode strict \
    --auto-accept \
    --pid \
    --preferred-format dc+sd-jwt \
    --wallet-dir "$WALLET_DIR" \
    --port "$PORT"
) >"$WALLET_LOG" 2>&1 &
WALLET_PID=$!

attempt=0
until curl -fsS "$WALLET_URL/api/credentials" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    echo "error: wallet did not become ready" >&2
    exit 1
  fi
  sleep 1
done

echo "Running official OIDF wallet plan via demo.certification.openid.net"
CONFORMANCE_SERVER="$CONFORMANCE_SERVER" \
CONFORMANCE_TOKEN="$CONFORMANCE_TOKEN" \
"$VENV_DIR/bin/python" "$ROOT_DIR/scripts/oidf_wallet_conformance.py" \
  --suite-dir "$SUITE_DIR" \
  --wallet-url "$WALLET_URL" \
  --results-dir "$RESULTS_DIR" \
  --runner-log "$RUNNER_LOG"

echo "Wallet log:   $WALLET_LOG"
echo "Runner log:   $RUNNER_LOG"
echo "Results dir:  $RESULTS_DIR"
