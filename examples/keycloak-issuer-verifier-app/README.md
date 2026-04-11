# Keycloak Issuer + Verifier Demo App

This example combines OpenID4VCI issuance and OpenID4VP verification around one Keycloak realm and one small sample application.

Compared with the smaller examples in this directory, this scenario still needs a small dynamic bootstrap for runtime-generated trust material and the persistent signing key. The static realm import already contains the fixed app client, credential scope, custom first-broker flow, OID4VP identity provider, and the wallet-login session-note mapper. The UI itself is kept separate from the Go handlers in `app/templates/` and `app/static/`.

The example supports two verifier-trust setups:

- `--http`: Keycloak runs on `http://localhost:8080` and the OID4VP extension validates the credential through a generated trust list served by the demo app.
- `--https`: Keycloak runs on `https://localhost:8443` and the OID4VP extension resolves the issuer signing key from the VC metadata / issuer metadata endpoints.

The issuance flow is the same in both modes. The only difference is how wallet-login trust is resolved.

## How It Works

The static realm import provides the stable parts of the example. `bootstrap.sh` fills in the runtime parts: the persistent RS256 signing key, the generated trust list in HTTP mode, and the real `keycloak_user_id` value for `alice`.

### Trust Modes

- HTTP mode uses `http://host.docker.internal:8090/keycloak-trustlist.jwt` and `trustListLoTEType=http://uri.etsi.org/19602/LoTEType/local`.
- HTTPS mode uses `allowedIssuers=https://localhost:8443/realms/wallet-app-demo` and fetches issuer metadata / JWKS over HTTPS.

## High-Level Flow

```mermaid
sequenceDiagram
    participant U as User
    participant APP as Demo App
    participant KC as Keycloak
    participant EXT as keycloak-extension-oid4vp
    participant BROKER as Custom Broker Authenticator
    participant W as oid4vc-dev wallet

    U->>APP: Sign in with password
    APP->>KC: standard login
    KC-->>APP: app session for alice
    U->>APP: Issue membership credential
    APP->>KC: create-credential-offer
    KC-->>APP: issuer + nonce
    APP->>W: openid-credential-offer://...?credential_offer_uri=...
    W->>KC: redeem credential
    KC-->>W: sd-jwt credential with keycloak_user_id

    U->>APP: Log out, then sign in again
    APP->>KC: standard login
    KC->>EXT: brokered wallet login
    EXT-->>W: openid4vp://authorize?request_uri=...
    W->>EXT: present wallet credential
    EXT->>KC: verified user with keycloak_user_id
    KC->>BROKER: auto-link existing user
    KC-->>APP: app session for the same user
```

## Detailed Flows

### Issuance

```mermaid
sequenceDiagram
    participant U as User
    participant APP as Demo App
    participant KC as Keycloak
    participant W as oid4vc-dev

    U->>APP: POST /issue
    APP->>KC: GET /realms/wallet-app-demo/protocol/oid4vc/create-credential-offer?credential_configuration_id=membership-credential&pre_authorized=true&type=uri
    Note over APP,KC: Authorization: Bearer <wallet-app access_token>
    KC-->>APP: {issuer, nonce}
    APP-->>U: HTML page with openid-credential-offer://?credential_offer_uri=...

    U->>W: wallet accept 'openid-credential-offer://...?credential_offer_uri=...'
    W->>KC: GET /realms/wallet-app-demo/protocol/oid4vc/credential-offer/{nonce}
    W->>KC: GET /realms/wallet-app-demo/.well-known/openid-credential-issuer
    W->>KC: POST /realms/wallet-app-demo/protocol/oid4vc/credential
    Note over W,KC: pre-authorized flow<br/>proof.jwt=...
    KC-->>W: dc+sd-jwt credential
```

### Verification

```mermaid
sequenceDiagram
    participant U as User
    participant APP as Demo App
    participant KC as Keycloak
    participant EXT as keycloak-extension-oid4vp
    participant W as oid4vc-dev

    U->>APP: Open Keycloak sign-in again
    APP->>KC: GET /realms/wallet-app-demo/protocol/openid-connect/auth?client_id=wallet-app&redirect_uri=http://127.0.0.1:8090/callback&response_type=code&scope=openid&kc_idp_hint=oid4vp
    KC->>EXT: start brokered login for alias oid4vp
    EXT-->>W: openid4vp://authorize?request_uri=...
    Note over EXT,W: request object fields that matter:<br/>response_mode=direct_post<br/>walletScheme=openid4vp://<br/>dcqlQuery.credentials[0].id=membership_sd_jwt<br/>dcqlQuery.credentials[0].format=dc+sd-jwt<br/>dcqlQuery.credentials[0].meta.vct_values[0]=https://credentials.example.com/membership<br/>dcqlQuery.credentials[0].claims=[keycloak_user_id, given_name, family_name, email]

    W->>EXT: GET request_uri
    W->>EXT: POST response_uri
    Note over W,EXT: vp_token=...<br/>presentation_submission=...

    EXT->>KC: verified brokered identity with keycloak_user_id
    KC->>BROKER: firstBrokerLoginFlow = oid4vp-user-id-auto-link
    KC-->>APP: 302 /callback?code=...&state=...
    APP->>KC: POST /realms/wallet-app-demo/protocol/openid-connect/token
    KC-->>APP: access_token, id_token, refresh_token
```

## Files

- `start.sh`: runs the full setup; default is HTTP plus the custom trust list, `--https` switches to issuer metadata
- `docker-compose.yml`: starts the HTTP Keycloak setup and imports the base realm from `realm/`
- `docker-compose.https.yml`: overrides the base compose file for HTTPS mode
- `realm/wallet-app-demo-realm.json`: source-of-truth base realm with the static user, app client, and credential scope
- `scripts/download-extension.sh`: downloads `keycloak-extension-oid4vp` `0.6.1`
- `scripts/build-link-provider.sh`: builds the custom Keycloak first-broker authenticator
- `scripts/generate-keycloak-cert.sh`: generates the local HTTPS certificate for Keycloak in `--https` mode
- `scripts/generate-keycloak-signing-cert.sh`: creates and reuses the persistent Keycloak RS256 signing keypair used in both HTTP and HTTPS mode
- `scripts/generate-keycloak-trustlist.go`: generates `keycloak-trustlist.jwt` from the persistent Keycloak signing certificate in `--http` mode
- `scripts/bootstrap.sh`: configures issuance, verification, user profile, and first-broker flow
- `scripts/start-app.sh`: starts the Go sample app
- `scripts/smoke.py`: runs the complete password-login, issuance, redemption, and wallet-login flow
- `app/main.go`: sample application routes and OIDC flow handling
- `app/templates/`: external HTML templates for the demo UI
- `app/static/`: CSS for the demo UI

## Quick Start

```bash
cd examples/keycloak-issuer-verifier-app
./start.sh
```

If `oid4vc-dev` is not already installed, `start.sh` installs the latest release with `go install github.com/dominikschlosser/oid4vc-dev@latest`.

HTTP / HTTPS setup:

```bash
./start.sh --http
./start.sh --https
```

Then open `http://127.0.0.1:8090/` and:

1. log in as `alice` / `alice`
2. issue the membership credential
3. open the offer in `oid4vc-dev`
4. log out, sign in again, and choose the wallet option in Keycloak
5. present the credential back to Keycloak

`./start.sh` runs `oid4vc-dev wallet register` automatically. On macOS that installs the custom scheme handlers so `openid-credential-offer://` and `openid4vp://` links hand the URI to `oid4vc-dev` and open the wallet UI in interactive mode. On Linux and Windows the command is a no-op.

If your system does not handle the custom scheme directly:

- issuance: use the offer page in the demo app and run the printed `oid4vc-dev wallet accept '<openid-credential-offer://...>'` command
- verification: when Keycloak shows the wallet login page, copy the `openid4vp://...` link target and run `oid4vc-dev wallet accept '<openid4vp://...>'`

Manual registration is still available if you want to run it yourself:

```bash
oid4vc-dev wallet register
```

Headless verification:

```bash
./start.sh --http --smoke
./start.sh --https --smoke
```

Setup only:

```bash
./start.sh --http --setup-only
./start.sh --https --setup-only
```

## Parameters

### Keycloak

| Parameter | HTTP mode | HTTPS mode |
|---|---|
| Image | `quay.io/keycloak/keycloak:26.6.0` | `quay.io/keycloak/keycloak:26.6.0` |
| Base URL | `http://localhost:8080` | `https://localhost:8443` |
| Startup flags | `start-dev`, `--features=oid4vc-vci:v1,oid4vc-vci-preauth-code:v1`, `--http-port=8080`, `--proxy-headers=xforwarded` | `start-dev`, `--features=oid4vc-vci:v1,oid4vc-vci-preauth-code:v1`, `--https-port=8443`, `--proxy-headers=xforwarded`, `--truststore-paths=/opt/keycloak/conf/keycloak-ca-cert.pem`, `--tls-hostname-verifier=ANY`, `--https-certificate-file=/opt/keycloak/conf/keycloak-cert.pem`, `--https-certificate-key-file=/opt/keycloak/conf/keycloak-key.pem` |
| Realm | `wallet-app-demo` | `wallet-app-demo` |
| Admin user | `admin` / `admin` | `admin` / `admin` |
| Demo user | `alice` / `alice` | `alice` / `alice` |
| User-profile attribute | `keycloak_user_id` | `keycloak_user_id` |
| App client | `wallet-app` | `wallet-app` |
| App redirect URI | `http://127.0.0.1:8090/callback` | `http://127.0.0.1:8090/callback` |
| App client attributes | `pkce.code.challenge.method=S256`, `oid4vci.enabled=true` | `pkce.code.challenge.method=S256`, `oid4vci.enabled=true` |
| App client redirect URIs | `*` | `*` |
| Credential configuration ID | `membership-credential` | `membership-credential` |
| Credential format | `dc+sd-jwt` | `dc+sd-jwt` |
| `vct` | `https://credentials.example.com/membership` | `https://credentials.example.com/membership` |
| Signing algorithm | `RS256` | `RS256` |
| Binding requirement | `vc.binding_required=true` | `vc.binding_required=true` |
| Proof types | `vc.binding_required_proof_types=jwt` | `vc.binding_required_proof_types=jwt` |
| Binding methods | `vc.cryptographic_binding_methods_supported=jwk` | `vc.cryptographic_binding_methods_supported=jwk` |
| Credential identifier | `membership-credential-id` | `membership-credential-id` |
| Credential claims | `keycloak_user_id`, `given_name`, `family_name`, `email`, `preferred_username`, `jti`, `iat` | `keycloak_user_id`, `given_name`, `family_name`, `email`, `preferred_username`, `jti`, `iat` |
| Custom first-broker flow | `oid4vp-user-id-auto-link` | `oid4vp-user-id-auto-link` |
| Custom flow executions | `oid4vp-detect-user-by-id`, `idp-auto-link` | `oid4vp-detect-user-by-id`, `idp-auto-link` |

### `keycloak-extension-oid4vp`

| Parameter | HTTP mode | HTTPS mode |
|---|---|
| Version | `0.6.1` | `0.6.1` |
| Provider alias | `oid4vp` | `oid4vp` |
| `firstBrokerLoginFlowAlias` | `oid4vp-user-id-auto-link` | `oid4vp-user-id-auto-link` |
| `sameDeviceEnabled` | `true` | `true` |
| `crossDeviceEnabled` | `false` | `false` |
| `walletScheme` | `openid4vp://` | `openid4vp://` |
| `responseMode` | `direct_post` | `direct_post` |
| `clientIdScheme` | `plain` | `plain` |
| `enforceHaip` | `false` | `false` |
| `trustedAuthoritiesMode` | `none` | `none` |
| `allowedIssuers` | `http://localhost:8080/realms/wallet-app-demo` | `https://localhost:8443/realms/wallet-app-demo` |
| `trustListUrl` | `http://host.docker.internal:8090/keycloak-trustlist.jwt` | not set |
| Issuer metadata trust | not used | used |
| `userMappingClaim` | `keycloak_user_id` | `keycloak_user_id` |
| `userMappingClaimMdoc` | `keycloak_user_id` | `keycloak_user_id` |
| DCQL credential id | `membership_sd_jwt` | `membership_sd_jwt` |
| DCQL format | `dc+sd-jwt` | `dc+sd-jwt` |
| DCQL `vct` | `https://credentials.example.com/membership` | `https://credentials.example.com/membership` |
| DCQL requested claims | `keycloak_user_id`, `given_name`, `family_name`, `email` | `keycloak_user_id`, `given_name`, `family_name`, `email` |

### oid4vc-dev

| Parameter | Value |
|---|---|
| Wallet store | `~/.oid4vc-dev/wallet` |
| Local wallet port in smoke flow | `8085` |

## Useful Overrides

```bash
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_CA_CERT=$(pwd)/keycloak-ca-cert.pem
KEYCLOAK_REALM=wallet-app-demo
APP_CLIENT_ID=wallet-app
APP_REDIRECT_URI=http://127.0.0.1:8090/callback
APP_BASE_URL=http://127.0.0.1:8090
OID4VCI_CREDENTIAL_SCOPE=membership-credential
OID4VP_TRUST_MODE=trustlist
OID4VP_TRUST_LIST_URL=http://host.docker.internal:8090/keycloak-trustlist.jwt
KEYCLOAK_TRUST_LIST_PATH=$(pwd)/keycloak-trustlist.jwt
OID4VC_WALLET_PORT=8085
```

## Cleanup

```bash
docker compose down -v
oid4vc-dev wallet remove --all
rm -f keycloak-trustlist.jwt
rm -f keycloak-ca-cert.pem keycloak-ca-key.pem keycloak-cert.pem keycloak-key.pem
```
