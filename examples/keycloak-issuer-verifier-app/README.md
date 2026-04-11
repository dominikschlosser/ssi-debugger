# Keycloak Issuer + Verifier Demo App

This example combines OpenID4VCI issuance and OpenID4VP verification around one Keycloak realm and one small sample application.

Compared with the smaller examples in this directory, this scenario still needs a small dynamic bootstrap for runtime-generated trust material and the persistent signing key. The static realm import now already contains the fixed app client, credential scope, custom first-broker flow, OID4VP identity provider, and the wallet-login session-note mapper. The UI itself is kept separate from the Go handlers in `app/templates/` and `app/static/`.

It supports two verifier-trust setups:

- `--http`: Keycloak runs on `http://localhost:8080` and the OID4VP extension validates the credential through a generated trust list served by the demo app. This is the default.
- `--https`: Keycloak runs on `https://localhost:8443` and the OID4VP extension resolves the issuer signing key from the VC metadata / issuer metadata endpoints.

VC metadata based trust is the standards-aligned setup and must be served via HTTPS.

## How It Works

### HTTP + Custom Trust List

1. `./start.sh` or `./start.sh --http` downloads `keycloak-extension-oid4vp` `0.6.1`, builds the custom first-broker authenticator, and starts Keycloak on `http://localhost:8080`.
2. `./scripts/bootstrap.sh` waits for the imported base realm, imports a persistent RS256 realm signing key from `keycloak-signing-key.pem` / `keycloak-signing-cert.pem`, then runs `./scripts/generate-keycloak-trustlist.go` to write `keycloak-trustlist.jwt` for that same signing certificate and updates the imported OID4VP identity provider for HTTP trust-list mode.
3. `./scripts/start-app.sh` runs the local Go app on `http://127.0.0.1:8090` and serves `http://127.0.0.1:8090/keycloak-trustlist.jwt`.
4. The OID4VP identity provider is configured with `trustListUrl=http://host.docker.internal:8090/keycloak-trustlist.jwt` and `trustListLoTEType=http://uri.etsi.org/19602/LoTEType/local`.
5. The login, issuance, and wallet-login steps are the same as in the HTTPS setup.
6. During wallet login, `keycloak-extension-oid4vp` validates the SD-JWT `x5c` chain against the custom trust list instead of using issuer metadata.

### HTTPS + VC Metadata

1. `./start.sh --https` downloads `keycloak-extension-oid4vp` `0.6.1`, builds the custom first-broker authenticator, generates a local HTTPS certificate for Keycloak, and starts Keycloak on `https://localhost:8443`.
2. `./scripts/bootstrap.sh` waits for the imported base realm `wallet-app-demo`, registers `keycloak_user_id` in the realm user profile, persists the runtime user id into that attribute for `alice`, and updates the imported `oid4vp` identity provider with `allowedIssuers=https://localhost:8443/realms/wallet-app-demo` for metadata-based trust.
3. `./scripts/start-app.sh` runs the local Go app on `http://127.0.0.1:8090`.
4. A browser login with username/password creates a normal Keycloak app session.
5. The app client itself is OID4VCI-enabled and uses its signed-in access token to call Keycloak's `create-credential-offer` endpoint, then hands the offer to `oid4vc-dev`.
6. The wallet stores the issued credential, including `keycloak_user_id`.
7. After logout, a second login goes through the normal Keycloak login page and can select the wallet option there. `keycloak-extension-oid4vp` verifies the credential by resolving the issuer signing key from the issuer metadata / VC metadata endpoints over HTTPS, and the custom first-broker flow links it back to the existing Keycloak user.

## Request Flow

### Issuance

```mermaid
sequenceDiagram
    participant U as User
    participant APP as Demo App
    participant KC as Keycloak
    participant W as oid4vc-dev

    U->>APP: GET /
    U->>APP: GET /login
    APP->>KC: 302 GET /realms/wallet-app-demo/protocol/openid-connect/auth
    Note over APP,KC: client_id=wallet-app<br/>redirect_uri=http://127.0.0.1:8090/callback<br/>response_type=code<br/>scope=openid<br/>code_challenge=S256
    KC-->>APP: 302 /callback?code=...&state=...
    APP->>KC: POST /realms/wallet-app-demo/protocol/openid-connect/token
    Note over APP,KC: grant_type=authorization_code<br/>client_id=wallet-app<br/>code_verifier=...
    KC-->>APP: access_token, id_token, refresh_token

    U->>APP: POST /issue
    APP->>KC: GET /realms/wallet-app-demo/protocol/oid4vc/create-credential-offer
    Note over APP,KC: Authorization: Bearer <wallet-app access_token><br/>credential_configuration_id=membership-credential<br/>pre_authorized=true&type=uri
    KC-->>APP: {issuer, nonce}
    APP-->>U: HTML page with openid-credential-offer://?credential_offer_uri=...

    U->>W: wallet accept 'openid-credential-offer://...?credential_offer_uri=...'
    W->>KC: GET /realms/wallet-app-demo/protocol/oid4vc/credential-offer/{nonce}
    W->>KC: GET /realms/wallet-app-demo/.well-known/openid-credential-issuer
    W->>KC: POST /realms/wallet-app-demo/protocol/oid4vc/credential
    Note over W,KC: proof.jwt=...<br/>pre-authorized flow
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

    U->>APP: GET /logout
    APP->>KC: 302 GET /realms/wallet-app-demo/protocol/openid-connect/logout
    Note over APP,KC: post_logout_redirect_uri=http://127.0.0.1:8090<br/>client_id=wallet-app<br/>id_token_hint=...

    U->>APP: GET /login
    APP->>KC: 302 GET /realms/wallet-app-demo/protocol/openid-connect/auth
    Note over APP,KC: client_id=wallet-app<br/>redirect_uri=http://127.0.0.1:8090/callback<br/>response_type=code<br/>scope=openid
    U->>KC: select "Sign in with Wallet"
    KC->>EXT: start brokered login via IdP alias oid4vp
    EXT-->>U: same-device page with openid4vp://authorize?request_uri=...

    U->>W: wallet accept 'openid4vp://authorize?...'
    W->>EXT: GET request object / request_uri
    W->>EXT: POST response_uri
    Note over W,EXT: response_mode=direct_post<br/>vp_token=...<br/>presentation_submission=...

    EXT->>KC: verified brokered user with keycloak_user_id
    KC->>KC: firstBrokerLoginFlow = oid4vp-user-id-auto-link
    Note over KC: oid4vp-detect-user-by-id<br/>idp-auto-link
    KC-->>APP: 302 /callback?code=...&state=...
    APP->>KC: POST /realms/wallet-app-demo/protocol/openid-connect/token
    KC-->>APP: access_token, id_token, refresh_token
```

## High-Level Flow

```mermaid
sequenceDiagram
    participant U as User
    participant APP as Demo App
    participant KC as Keycloak 26.6.0
    participant EXT as keycloak-extension-oid4vp 0.6.1
    participant LINK as Custom Broker Authenticator
    participant W as oid4vc-dev wallet

    U->>APP: Login With Password
    APP->>KC: OIDC authorization code flow
    KC-->>APP: app session for alice
    U->>APP: Issue Membership Credential
    APP->>KC: create-credential-offer with app access token
    KC-->>APP: issuer + nonce
    APP->>W: openid-credential-offer://...
    W->>KC: OID4VCI credential request
    KC-->>W: dc+sd-jwt credential with keycloak_user_id
    U->>APP: Logout, then Sign In again
    APP->>KC: OIDC auth via standard login page
    KC->>EXT: start OID4VP broker login
    EXT-->>W: openid4vp:// request
    W->>EXT: direct_post VP token
    EXT->>KC: verified brokered identity with keycloak_user_id
    KC->>LINK: detect existing user by keycloak_user_id
    LINK-->>KC: existing user id
    KC-->>APP: authorization code and tokens for same user
```

## Trust Setup

### HTTP + Custom Trust List

```mermaid
sequenceDiagram
    participant APP as Demo App
    participant KC as Keycloak
    participant EXT as OID4VP Extension
    participant W as oid4vc-dev wallet

    APP->>KC: create-credential-offer
    W->>KC: OID4VCI credential request
    KC-->>W: SD-JWT VC with x5c chain
    APP->>KC: second login via standard login page
    W->>EXT: direct_post VP token
    EXT->>APP: fetch /keycloak-trustlist.jwt
    EXT->>EXT: verify SD-JWT x5c chain against trust list
```

### HTTPS + VC Metadata

```mermaid
sequenceDiagram
    participant APP as Demo App
    participant KC as Keycloak
    participant EXT as OID4VP Extension
    participant W as oid4vc-dev wallet

    APP->>KC: create-credential-offer
    W->>KC: OID4VCI credential request
    KC-->>W: SD-JWT VC with iss=https://localhost:8443/realms/wallet-app-demo
    APP->>KC: second login via standard login page
    W->>EXT: direct_post VP token
    EXT->>KC: fetch issuer metadata / JWKS over HTTPS
    EXT->>EXT: verify SD-JWT signature with issuer metadata key
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

HTTPS setup:

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
| App client attributes | `pkce.code.challenge.method=S256`, `oid4vci.enabled=true` |
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
