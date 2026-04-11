# Keycloak Issuer + Verifier HAIP Demo

This example mirrors [`keycloak-issuer-verifier-app`](../keycloak-issuer-verifier-app/README.md), but switches the verifier side to HAIP-style OID4VP:

- `haip-vp://`
- `response_mode=direct_post.jwt`
- `client_id_scheme=x509_hash`
- signed Request Objects with an X.509 certificate and ES256 key
- trust-list based issuer trust

The example intentionally stays on local HTTP. That keeps the setup small and focuses on the HAIP-specific verifier behavior. In a production-style deployment, the verifier `request_uri` endpoint would normally be HTTPS.

## Deviations

This is not full HAIP issuance yet.

- Issuance still uses a pre-authorized credential offer, not authorization-code issuance.
- The app hands the wallet a `haip-vci://` URI, but the underlying Keycloak offer still contains a pre-authorized grant.
- The verifier side is the HAIP part of this example. That is the supported end-to-end flow today.

## High-Level Flow

```mermaid
sequenceDiagram
    participant U as User
    participant APP as Demo App
    participant KC as Keycloak
    participant EXT as keycloak-extension-oid4vp
    participant W as oid4vc-dev

    U->>APP: Sign in with password
    APP->>KC: standard OIDC login
    KC-->>APP: app session

    U->>APP: Issue membership credential
    APP->>KC: create-credential-offer
    KC-->>APP: offer URI
    APP->>W: haip-vci://...?credential_offer_uri=...
    W->>KC: redeem offer
    KC-->>W: membership credential

    U->>APP: Log out and sign in again
    KC->>EXT: start OID4VP broker login
    EXT-->>W: haip-vp://authorize?request_uri=...
    W->>EXT: direct_post.jwt response
    EXT->>KC: verified user with keycloak_user_id
    KC-->>APP: app session
```

## Issuance

```mermaid
sequenceDiagram
    participant U as User
    participant APP as Demo App
    participant KC as Keycloak
    participant W as oid4vc-dev

    U->>APP: POST /issue
    APP->>KC: GET /realms/wallet-haip-demo/protocol/oid4vc/create-credential-offer?credential_configuration_id=membership-credential&pre_authorized=true&type=uri
    Note over APP,KC: Authorization: Bearer <wallet-haip-app access_token>
    KC-->>APP: {issuer, nonce}
    APP-->>U: issue page with haip-vci://?credential_offer_uri=http://localhost:8081/realms/wallet-haip-demo/protocol/oid4vc/credential-offer/{nonce}

    U->>W: open haip-vci://... or run wallet accept
    W->>KC: GET /realms/wallet-haip-demo/protocol/oid4vc/credential-offer/{nonce}
    W->>KC: GET /realms/wallet-haip-demo/.well-known/openid-credential-issuer
    W->>KC: POST /realms/wallet-haip-demo/protocol/oid4vc/credential
    Note over W,KC: proof.jwt=...<br/>pre-authorized flow
    KC-->>W: dc+sd-jwt credential
```

## Verification

```mermaid
sequenceDiagram
    participant U as User
    participant APP as Demo App
    participant KC as Keycloak
    participant EXT as keycloak-extension-oid4vp
    participant W as oid4vc-dev

    U->>APP: Sign in again and choose wallet login in Keycloak
    APP->>KC: GET /realms/wallet-haip-demo/protocol/openid-connect/auth?client_id=wallet-haip-app&redirect_uri=http://127.0.0.1:8091/callback&response_type=code&scope=openid
    KC->>EXT: start brokered login for alias oid4vp
    EXT-->>W: haip-vp://authorize?request_uri=http://localhost:8081/realms/wallet-haip-demo/broker/oid4vp/endpoint/request-uri/{id}

    W->>EXT: GET /realms/wallet-haip-demo/broker/oid4vp/endpoint/request-uri/{id}
    Note over W,EXT: Request Object includes:<br/>client_id=x509_hash:...<br/>response_mode=direct_post.jwt<br/>dcql_query.credentials[0].meta.vct_values[0]=https://credentials.example.com/membership<br/>claims=[keycloak_user_id,given_name,family_name,email]
    W->>EXT: POST /realms/wallet-haip-demo/broker/oid4vp/endpoint/auth-response
    Note over W,EXT: encrypted direct_post.jwt response
    EXT-->>W: 302 /realms/wallet-haip-demo/broker/oid4vp/endpoint/complete-auth?code=...
    EXT->>KC: verified identity with keycloak_user_id
    KC-->>APP: /callback?code=...
```

## What Bootstrap Does

The imported realm already contains the static pieces:

- demo user `alice`
- public app client `wallet-haip-app`
- credential scope `membership-credential`
- custom first-broker flow
- OID4VP identity provider stub

`scripts/bootstrap.sh` only fills in the runtime-dependent pieces:

- imports the persistent Keycloak signing key
- sets `alice.attributes.keycloak_user_id`
- generates the Keycloak trust list JWT
- generates a verifier certificate chain and ES256 JWK for `x509_hash` request objects
- patches the imported `oid4vp` identity provider with the HAIP verifier settings

## Quick Start

```bash
cd examples/keycloak-issuer-verifier-haip-app
./start.sh
```

Then open `http://127.0.0.1:8091/` and:

1. sign in as `alice` / `alice`
2. issue the membership credential
3. import it into `oid4vc-dev`
4. log out
5. sign in again and choose the wallet option in Keycloak

`./start.sh` runs `oid4vc-dev wallet register` automatically. On macOS that installs the custom scheme handlers. On Linux and Windows it is accepted but does nothing, so use the printed CLI commands instead.

Smoke test:

```bash
./start.sh --smoke
```

Setup only:

```bash
./start.sh --setup-only
```

## Files

- `realm/wallet-haip-demo-realm.json`: static base realm
- `scripts/bootstrap.sh`: runtime wiring for signing key, trust list, and HAIP verifier material
- `scripts/generate-verifier-material/`: generates the verifier certificate chain and signing JWK
- `scripts/generate-keycloak-trustlist/`: generates the trust list JWT from Keycloak's issuer certificate
- `scripts/smoke.py`: headless end-to-end check
- `app/`: small Go demo app with external templates and CSS
