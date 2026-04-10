# Examples

Runnable integration scenarios live in this directory.

For a documentation-style overview, see [docs/examples.md](../docs/examples.md).

Each example should be self-contained in its own subfolder and include:

- a short `README.md`
- any compose files, scripts, or fixtures needed to run it
- the exact versions or assumptions the scenario was tested against

## Scenarios

| Folder | Purpose |
|--------|---------|
| `keycloak-issuer-wallet` | Use Keycloak 26.6.0 as an OpenID4VCI credential issuer and `oid4vc-dev` as the wallet |
| `keycloak-verifier-oid4vp` | Use Keycloak 26.6.0 plus `keycloak-extension-oid4vp` as an OpenID4VP verifier and `oid4vc-dev` as the wallet |
