# Examples

Runnable integration scenarios live under [`examples/`](../examples/README.md).

These examples are meant to show complete local setups around `oid4vc-dev`, including any Docker compose files, bootstrap scripts, wallet preparation steps, and the exact versions they were tested against.

## Scenarios

### Keycloak Issuer + oid4vc-dev Wallet

Folder: [`examples/keycloak-issuer-wallet`](../examples/keycloak-issuer-wallet/README.md)

Use this when you want to run Keycloak `26.6.0` as an OpenID4VCI issuer and redeem the resulting offer with an `oid4vc-dev` wallet.

It includes:

- a Keycloak compose setup
- issuer bootstrap scripts
- a helper to create a pre-authorized credential offer
- a wallet redemption helper

### Keycloak Verifier + keycloak-extension-oid4vp

Folder: [`examples/keycloak-verifier-oid4vp`](../examples/keycloak-verifier-oid4vp/README.md)

Use this when you want to run Keycloak `26.6.0` as an OpenID4VP verifier with `keycloak-extension-oid4vp` and use `oid4vc-dev` as the wallet.

It includes:

- a provider download script for the published extension jar
- wallet generation helpers
- verifier bootstrap scripts
- a headless same-device login test
- a browser-driven command-line flow that works with a registered `oid4vc-dev` wallet

## Notes

- The examples are intentionally self-contained and version-pinned.
- Each scenario README documents its own prerequisites, quick start, and cleanup.
- If you want to browse only the example folders, start from [`examples/README.md`](../examples/README.md).
