#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

pick_port_pair() {
  python3 - <<'PY'
import socket

def port_free(port: int) -> bool:
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True

for _ in range(128):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    if port < 1024 or port >= 65534:
        continue
    if port_free(port) and port_free(port + 1):
        print(port)
        raise SystemExit(0)

raise SystemExit("failed to find a free local port pair")
PY
}

PORT=${PORT:-$(pick_port_pair)}
RUN_DIR=${OIDF_RUN_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/oidf-wallet-conformance.XXXXXX")}
SUITE_URL=${OIDF_SUITE_URL:-https://github.com/openid-certification/conformance-suite/archive/refs/heads/master.tar.gz}
WALLET_DIR=${OIDF_WALLET_DIR:-"$RUN_DIR/wallet"}
WALLET_URL=${OIDF_WALLET_URL:-"http://127.0.0.1:${PORT}"}
WALLET_ISSUER_URL=${OIDF_WALLET_ISSUER_URL:-"https://localhost:$((PORT + 1))"}
WALLET_CA_CERT=${OIDF_WALLET_CA_CERT:-"$RUN_DIR/wallet-ca-cert.pem"}
CONFORMANCE_SERVER=${CONFORMANCE_SERVER:-https://demo.certification.openid.net/}
CONFORMANCE_SERVER_LOCAL=${CONFORMANCE_SERVER_LOCAL:-$CONFORMANCE_SERVER}
CONFORMANCE_SERVER_MTLS=${CONFORMANCE_SERVER_MTLS:-$CONFORMANCE_SERVER}
OIDF_INCLUDE_HAIP=${OIDF_INCLUDE_HAIP:-0}
OIDF_VCI_CLIENT_ID=${OIDF_VCI_CLIENT_ID:-52480754053}
OIDF_VCI_ALIAS=${OIDF_VCI_ALIAS:-"oid4vc-dev-vci-${PORT}"}

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

OIDF_VCI_REDIRECT_URI=${OIDF_VCI_REDIRECT_URI:-"${CONFORMANCE_SERVER_LOCAL%/}/test/a/${OIDF_VCI_ALIAS}/callback"}

SUITE_DIR="$RUN_DIR/conformance-suite-master"
VENV_DIR="$RUN_DIR/venv"
RESULTS_DIR="$RUN_DIR/results"
RUNNER_LOG="$RUN_DIR/runner.log"
WALLET_LOG="$RUN_DIR/wallet.log"
EXTRA_ARGS=""

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

echo "Starting wallet on $WALLET_URL"
(
  cd "$ROOT_DIR"
  exec go run . wallet serve \
    --mode strict \
    --auto-accept \
    --pid \
    --preferred-format dc+sd-jwt \
    --wallet-dir "$WALLET_DIR" \
    --port "$PORT" \
    --vci-client-id "$OIDF_VCI_CLIENT_ID" \
    --vci-redirect-uri "$OIDF_VCI_REDIRECT_URI"
) >"$WALLET_LOG" 2>&1 &
WALLET_PID=$!

attempt=0
until curl -fsS "$WALLET_URL/api/credentials" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if ! kill -0 "$WALLET_PID" 2>/dev/null; then
    echo "error: wallet exited before becoming ready" >&2
    cat "$WALLET_LOG" >&2
    exit 1
  fi
  if [ "$attempt" -ge 60 ]; then
    echo "error: wallet did not become ready" >&2
    exit 1
  fi
  sleep 1
done

if [ "$OIDF_INCLUDE_HAIP" = "1" ]; then
  EXTRA_ARGS="$EXTRA_ARGS --include-haip"
fi

echo "Running OIDF Final wallet plans via demo.certification.openid.net"
CONFORMANCE_SERVER="$CONFORMANCE_SERVER" \
CONFORMANCE_SERVER_LOCAL="$CONFORMANCE_SERVER_LOCAL" \
CONFORMANCE_SERVER_MTLS="$CONFORMANCE_SERVER_MTLS" \
CONFORMANCE_TOKEN="$CONFORMANCE_TOKEN" \
"$VENV_DIR/bin/python" "$ROOT_DIR/scripts/oidf_wallet_conformance.py" \
  --suite-dir "$SUITE_DIR" \
  --wallet-url "$WALLET_URL" \
  --wallet-issuer-url "$WALLET_ISSUER_URL" \
  --wallet-ca-cert "$WALLET_CA_CERT" \
  --vci-client-id "$OIDF_VCI_CLIENT_ID" \
  --vci-redirect-uri "$OIDF_VCI_REDIRECT_URI" \
  --results-dir "$RESULTS_DIR" \
  --runner-log "$RUNNER_LOG" \
  $EXTRA_ARGS

echo "Wallet log:   $WALLET_LOG"
echo "Runner log:   $RUNNER_LOG"
echo "Results dir:  $RESULTS_DIR"
