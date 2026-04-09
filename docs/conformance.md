# OIDF Conformance

This repository can run the current OpenID Foundation wallet plans for OID4VP 1.0 Final, OID4VCI 1.0 Final, and the current HAIP wallet variants against the local wallet implementation.

The wrapper uses the current Final wallet plans plus the current HAIP wallet plans:

- `oid4vp-1final-wallet-test-plan`
- `oid4vci-1_0-wallet-test-plan`
- `oid4vp-1final-wallet-haip-test-plan`
- `oid4vci-1_0-wallet-haip-test-plan`

It does not use the older ID3 wallet plan, and it does not add suite-specific behavior to the wallet. The runner adapts the OIDF config to the wallet's normal keys, CA, credentials, and HTTPS issuer metadata.

## What the wrapper does

[`scripts/oidf-wallet-conformance.sh`](/Users/dominik/projects/oid4vc-dev/scripts/oidf-wallet-conformance.sh):

- loads `OIDF_TOKEN` from `.env` or `CONFORMANCE_TOKEN` from the environment
- downloads the latest upstream conformance suite tarball from GitHub
- creates a Python virtualenv for the official runner
- starts `oid4vc-dev wallet serve` in strict mode with default PID credentials
- configures the wallet's normal OID4VCI authorization-code client settings
- runs the official `run-test-plan.py` against `https://demo.certification.openid.net/`

[`scripts/oidf_wallet_conformance.py`](/Users/dominik/projects/oid4vc-dev/scripts/oidf_wallet_conformance.py):

- verifies the extracted suite contains the current Final wallet plans and templates
- reads the wallet's holder binding key from `/api/credentials`
- reads the wallet's issuer signing JWK from `/.well-known/jwt-vc-issuer`
- uses the shared wallet CA as the attestation and trust anchor PEM
- generates per-scenario OIDF config files from the upstream templates
- keeps the VCI suite alias aligned with the configured `redirect_uri` / helper-page paths
- disables the suite's VCI browser helper page and drives the same offer URL directly through the wallet API
- drives Browser API `dc_api` / `dc_api.jwt` presentation requests through the wallet's `/api/dc-api` endpoint
- monitors waiting modules and automatically:
  - submits presentation requests to `/api/presentations`
  - executes Browser API presentation requests from `browser.browserApiRequests`
  - submits credential offers to `/api/offers`
  - follows returned verifier `redirect_uri` values
  - uploads placeholder screenshots for negative-review modules
- prints the created private OIDF `plan-detail.html?plan=...` URLs

## Default matrix

The default run covers the current Final and HAIP scenarios this wallet is expected to pass:

- VP Final: SD-JWT `direct_post`, signed `request_uri`, `x509_hash`
- VP Final: SD-JWT `direct_post.jwt`, signed `request_uri`, `x509_hash`
- VP Final: SD-JWT `direct_post`, unsigned `request_uri`, `redirect_uri`
- VP Final: mDoc `direct_post.jwt`, signed `request_uri`, `x509_hash`
- VP HAIP: SD-JWT `direct_post.jwt`
- VP HAIP: mDoc `direct_post.jwt`
- VP HAIP: SD-JWT `dc_api.jwt` plan, covering both unsigned `web-origin` and signed `x509_san_dns` Browser API modules
- VP HAIP: mDoc `dc_api.jwt` plan, covering both unsigned `web-origin` and signed `x509_san_dns` Browser API modules
- VCI Final: SD-JWT authorization-code issuer-initiated flow with client attestation + DPoP
- VCI Final: mDoc authorization-code issuer-initiated flow with client attestation + DPoP
- VCI HAIP: SD-JWT plan, covering immediate plain, deferred plain, and immediate encrypted responses
- VCI HAIP: mDoc plan, covering immediate plain, deferred plain, and immediate encrypted responses

Those runs are fixed in the wrapper. There is no plan selector and no ID3 fallback.

## Prerequisites

Create a local `.env` file with your OIDF bearer token:

```bash
OIDF_TOKEN=...
```

You also need:

- `python3`
- `curl`
- network access to `demo.certification.openid.net`

## Running it

```bash
scripts/oidf-wallet-conformance.sh
```

Useful environment overrides:

- `PORT`: wallet port; defaults to a free local port
- `OIDF_RUN_DIR`: keep all runner artifacts in a chosen directory instead of a temp dir
- `OIDF_WALLET_DIR`: reuse a specific wallet store
- `OIDF_WALLET_ISSUER_URL`: override the wallet HTTPS issuer URL if needed
- `OIDF_WALLET_CA_CERT`: override the shared wallet CA PEM path
- `OIDF_VCI_CLIENT_ID`: override the configured OID4VCI client ID
- `OIDF_VCI_REDIRECT_URI`: override the configured OID4VCI redirect URI
- `OIDF_VCI_ALIAS`: convenience alias used by the default `OIDF_VCI_REDIRECT_URI`
- `OIDF_SUITE_URL`: override the suite tarball URL; defaults to the upstream `master` archive
- `CONFORMANCE_SERVER`: override the OIDF base URL; defaults to `https://demo.certification.openid.net/`

The script prints the run directory and leaves behind:

- wallet log
- mirrored official runner log
- exported OIDF result archives
- generated OIDF config files

## OIDF Website Results

The wrapper creates private plans on the OIDF service. It does not:

- delete plans
- publish plans
- create certification packages

If you do not see runs on the public OIDF pages, that is expected. Use the printed `plan-detail.html?plan=...` URLs, and make sure you are signed into the same OIDF account that owns the bearer token.

## Design Rule

There is no conformance-only wallet mode in this flow.

The wallet uses:

- its normal holder key for DPoP and proof binding
- its normal issuer signing key and certificate chain for client attestation and key attestation
- its normal shared wallet CA as the trust anchor

That keeps the conformance run aligned with real wallet behavior instead of carrying suite-only signing paths.

## Known gaps

Current remaining gap in the hosted OIDF service:

- the OIDF site's plain `direct_post` alternate-happy-flow VP Final modules still fail before the wallet receives a request because the hosted suite currently tries to replace an encryption step that does not exist for unencrypted response modes

## References

- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- [OIDF Conformance Service](https://www.certification.openid.net/)
