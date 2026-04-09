# Flow Diagrams

GitHub renders the diagrams in this section directly from Mermaid source, so the pages stay reviewable in plain text and do not depend on generated image assets.

These diagrams intentionally treat `oid4vc-dev` as a single actor. They show the external interaction pattern and the request parameters or wallet flags that change behavior, not the internal package structure.

## Pages

| Page | Scope |
|------|-------|
| [OID4VP Flows](./oid4vp.md) | Presentation request variants, response modes, Browser API, and request-object handling |
| [OID4VCI Flows](./oid4vci.md) | Credential offer variants, grant flows, and the credential request branches |

## Whole Interaction

```mermaid
sequenceDiagram
    actor User as User or calling app
    participant Issuer as Issuer / authorization server
    participant Wallet as oid4vc-dev
    participant Verifier as Verifier / relying party

    Issuer-->>User: credential_offer or credential_offer_uri
    User->>Wallet: openid-credential-offer:// or haip-vci://
    Wallet->>Issuer: token and credential requests
    Issuer-->>Wallet: credential

    Verifier-->>User: authorization request or Browser API request
    User->>Wallet: openid4vp:// / haip-vp:// / eudi-openid4vp:// or dc_api*
    Wallet->>Verifier: presentation response
```

## Supported Flow Map

```mermaid
sequenceDiagram
    actor User
    participant Wallet as oid4vc-dev
    participant Issuer as Issuer / AS
    participant Verifier

    Note over User,Issuer: OID4VCI branch
    User->>Wallet: receive and open credential offer
    alt pre-authorized code
        Wallet->>Issuer: token request with pre-authorized_code
    else authorization code
        Wallet->>Issuer: PAR, authorization, token request
    end
    Wallet->>Issuer: credential request with proofs.jwt
    opt transaction_id returned
        Wallet->>Issuer: deferred credential request
    end
    Issuer-->>Wallet: credential

    Note over User,Verifier: OID4VP branch
    User->>Wallet: open URI request or trigger Browser API request
    opt request or request_uri present
        Wallet->>Verifier: fetch inline request or request_uri
    end
    Wallet->>Wallet: evaluate dcql_query against stored credentials
    alt direct_post
        Wallet->>Verifier: direct_post response
    else direct_post.jwt
        Wallet->>Verifier: encrypted direct_post.jwt response
    else fragment
        Wallet-->>User: redirect URI with fragment response
    else dc_api / dc_api.jwt
        Wallet-->>Verifier: Browser API response
    end
```

## Reading Guide

- Start with [OID4VCI Flows](./oid4vci.md) if you want to understand how credentials get into the wallet.
- Start with [OID4VP Flows](./oid4vp.md) if you want to understand how the wallet selects and returns stored credentials.
- Use the parameter tables on each page as the practical checklist for building issuer or verifier requests against `oid4vc-dev`.
