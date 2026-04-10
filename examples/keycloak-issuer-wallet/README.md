# Keycloak Issuer + oid4vc-dev Wallet

This scenario uses:

- Keycloak `26.6.0` as the OpenID4VCI credential issuer
- `oid4vc-dev` as the wallet redeeming the credential offer
- a pre-authorized code offer so the flow is easy to run locally

The example bootstraps a demo realm, creates an SD-JWT credential configuration, creates a demo user, and creates a pre-authorized credential offer that `oid4vc-dev` can redeem directly.

It uses Keycloak's current `create-credential-offer` endpoint from 26.6.0.

## Files

- `docker-compose.yml` starts Keycloak with the `oid4vc-vci:v1` feature enabled
- `scripts/bootstrap.sh` recreates the demo realm and configures the issuer
- `scripts/create-offer.sh` creates a fresh pre-authorized Keycloak offer and wraps it as an `openid-credential-offer://` URI for `oid4vc-dev`
- `scripts/redeem-offer.sh` creates an offer and passes it to `oid4vc-dev wallet accept`

## Prerequisites

- Docker
- `curl`
- `jq`
- a local `oid4vc-dev` binary or `go` toolchain

## Quick Start

Start Keycloak:

```bash
cd examples/keycloak-issuer-wallet
docker compose up -d
```

Bootstrap the demo issuer:

```bash
./scripts/bootstrap.sh
```

Redeem an offer with a dedicated local wallet store:

```bash
./scripts/redeem-offer.sh
```

Inspect the imported credential:

```bash
../../oid4vc-dev wallet --wallet-dir "$(pwd)/.wallet" list
```

Or show the raw offer and redeem it manually:

```bash
OFFER_URI=$(./scripts/create-offer.sh)
../../oid4vc-dev wallet --wallet-dir "$(pwd)/.wallet" accept "$OFFER_URI"
```

## Demo Setup

The bootstrap script recreates a realm named `oid4vc-demo` with:

- user `alice` / password `alice`
- public client `oid4vc-demo-client`
- credential configuration ID `membership-credential`
- SD-JWT claims mapped from `alice`'s profile: `given_name`, `family_name`, and `email`

The issued credential uses the `dc+sd-jwt` format and a `vct` of `https://credentials.example.com/membership`.

## Useful Overrides

All scripts accept environment overrides:

```bash
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=oid4vc-demo
OID4VCI_CLIENT_ID=oid4vc-demo-client
OID4VCI_USER=alice
OID4VCI_USER_PASSWORD=alice
OID4VC_DEV_BIN=../../oid4vc-dev
OID4VC_WALLET_DIR=$(pwd)/.wallet
```

## Cleanup

```bash
docker compose down -v
rm -rf .wallet
```
