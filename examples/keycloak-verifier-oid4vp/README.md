# Keycloak Verifier + `keycloak-extension-oid4vp`

This scenario uses:

- Keycloak `26.6.0` as the OpenID4VP verifier
- `keycloak-extension-oid4vp` `0.6.1` from Maven Central
- `oid4vc-dev` as the wallet presenting a locally generated PID

The example pins a plain-client-ID, non-HAIP same-device flow so it can run locally without extra verifier X.509 material. The verifier requests the SD-JWT PID branch and uses the wallet's HTTPS issuer metadata endpoint as a fallback verification path, so Keycloak is started with the generated wallet CA certificate in its truststore. The login script drives the full browser-style OIDC login, hands the `openid4vp://` request to `oid4vc-dev`, completes Keycloak's first-broker-login step if needed, and exchanges the resulting authorization code for tokens.

## Files

- `docker-compose.yml` starts Keycloak `26.6.0` and loads provider jars from `providers/`
- `scripts/download-extension.sh` downloads `keycloak-extension-oid4vp` `0.6.1` from Maven Central
- `scripts/bootstrap.sh` recreates a demo realm and configures the OID4VP identity provider
- `scripts/generate-wallet.sh` creates a local PID wallet store that Keycloak can verify from Docker
- `scripts/login.py` runs the same-device verifier flow end to end and exchanges the auth code
- `scripts/test-oidc-flow.sh` opens a browser-driven OIDC flow like `../eudi-wallet-connector` and expects a registered `oid4vc-dev` wallet handler

## Prerequisites

- Docker
- `curl`
- `jq`
- `python3`
- a local `oid4vc-dev` binary or `go` toolchain

## Quick Start

Download the verifier extension jar:

```bash
cd examples/keycloak-verifier-oid4vp
./scripts/download-extension.sh
```

Generate a wallet with local PID credentials and Docker-reachable status/trust-list URLs:

```bash
./scripts/generate-wallet.sh
```

Start Keycloak:

```bash
docker compose up -d
```

Bootstrap the demo verifier realm:

```bash
./scripts/bootstrap.sh
```

Run the same-device login flow and exchange the resulting authorization code:

```bash
./scripts/login.py
```

Or drive the browser flow from the command line and let the registered `oid4vc-dev` wallet handle the `openid4vp://` redirect:

```bash
../../oid4vc-dev wallet register
./scripts/test-oidc-flow.sh
```

## Demo Setup

The bootstrap script recreates a realm named `wallet-demo` with:

- public client `wallet-mock`
- redirect URI pattern `http://127.0.0.1/*`
- OID4VP identity provider alias `oid4vp`
- same-device flow enabled, cross-device flow disabled
- `direct_post` response mode
- `plain` `client_id` scheme with `enforceHaip=false`
- PID trust-list LoTE filter `http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList`
- a DCQL query requesting SD-JWT PID `urn:eudi:pid:de:1`

The generated wallet still contains both the SD-JWT PID and mDoc PID credentials, but this verifier scenario asks for the SD-JWT PID branch so Keycloak can use the wallet issuer-metadata fallback in local mode.

The scripts prefer `go run` from the current `oid4vc-dev` checkout when Go is available, which avoids accidentally picking up a stale previously built binary. Set `OID4VC_DEV_BIN` if you want to force a specific binary path.

The verifier trusts the wallet's PID trust list at `http://host.docker.internal:8085/api/trustlist`, which is served temporarily by `oid4vc-dev wallet accept` during the presentation flow.

## Useful Overrides

All scripts accept environment overrides:

```bash
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=wallet-demo
OIDC_CLIENT_ID=wallet-mock
OIDC_REDIRECT_URI=http://127.0.0.1:18080/callback
OID4VP_TRUST_LIST_URL=http://host.docker.internal:8085/api/trustlist
OID4VC_DEV_BIN=../../oid4vc-dev
OID4VC_WALLET_DIR=$(pwd)/.wallet
OID4VC_WALLET_PORT=8085
BROKER_USERNAME_PREFIX=wallet-user
```

## Cleanup

```bash
docker compose down -v
rm -rf .wallet
rm -f wallet-ca-cert.pem wallet-ca-key.pem
```
