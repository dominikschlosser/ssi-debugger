# OIDF Conformance

This repository can run the official OpenID Foundation wallet runner against the current wallet-focused OID4VP suite, with the local wallet acting as the wallet under test.

As of April 8, 2026, the latest upstream suite on `master` uses the ID3 wallet plan:

- `oid4vp-id3-wallet-test-plan`

The wrapper still auto-detects the older legacy layout, but the current live suite is ID3.

## What the wrapper does

[`scripts/oidf-wallet-conformance.sh`](/Users/dominik/projects/oid4vc-dev/scripts/oidf-wallet-conformance.sh):

- loads `OIDF_TOKEN` from the local `.env` file or `CONFORMANCE_TOKEN` from the environment
- downloads the latest upstream conformance suite tarball from GitHub
- creates a Python virtualenv for the official runner
- starts `oid4vc-dev wallet serve` in strict mode with ISO session transcripts enabled
- derives per-scenario config files from the upstream ID3 templates
- runs the official `run-test-plan.py` against `https://demo.certification.openid.net/`
- monitors waiting modules and automatically:
  - submits the generated verifier request URL into the local wallet
  - follows returned verifier `redirect_uri` values
  - uploads a placeholder screenshot for negative tests that require one

[`scripts/oidf_wallet_conformance.py`](/Users/dominik/projects/oid4vc-dev/scripts/oidf_wallet_conformance.py):

- detects the upstream suite layout automatically
- expands the current upstream placeholder JSON references from `scripts/certs-keys/*.json`
- customizes the DCQL queries to the local mock credentials:
  - SD-JWT VCT `urn:eudi:pid:de:1`
  - mDoc doctype `eu.europa.ec.eudi.pid.1`
- retries transient `request_uri` readiness failures before treating a module as failed

## Default matrix

By default the wrapper now runs all current passing scenarios:

- signed SD-JWT `direct_post`
- signed SD-JWT `direct_post.jwt`
- unsigned SD-JWT `direct_post`
- unsigned SD-JWT `direct_post.jwt`
- signed mDoc `direct_post.jwt`

These map to the current ID3 variants:

- `credential_format=sd_jwt_vc`, `client_id_scheme=x509_san_dns`, `request_method=request_uri_signed`, `response_mode=direct_post`
- `credential_format=sd_jwt_vc`, `client_id_scheme=x509_san_dns`, `request_method=request_uri_signed`, `response_mode=direct_post.jwt`
- `credential_format=sd_jwt_vc`, `client_id_scheme=redirect_uri`, `request_method=request_uri_unsigned`, `response_mode=direct_post`
- `credential_format=sd_jwt_vc`, `client_id_scheme=redirect_uri`, `request_method=request_uri_unsigned`, `response_mode=direct_post.jwt`
- `credential_format=iso_mdl`, `client_id_scheme=x509_san_dns`, `request_method=request_uri_signed`, `response_mode=direct_post.jwt`

The negative modules in these plans finish as `REVIEW`, which is expected for the current suite. The wrapper treats unexpected condition failures as actual failures.

## Prerequisites

Create a local `.env` file with your OIDF bearer token:

```bash
OIDF_TOKEN=...
```

`.env` is gitignored in this repository.

You also need:

- `python3`
- `curl`
- network access to `demo.certification.openid.net`

## Running it

```bash
scripts/oidf-wallet-conformance.sh
```

Useful environment overrides:

- `PORT`: wallet port; defaults to a free local port discovered by the wrapper
- `OIDF_RUN_DIR`: keep all runner artifacts in a chosen directory instead of a temp dir
- `OIDF_WALLET_DIR`: reuse a specific wallet store
- `OIDF_INCLUDE_UNSIGNED=0`: skip the unsigned `redirect_uri` client ID scenarios
- `OIDF_INCLUDE_MDOC=0`: skip the mDoc scenario
- `OIDF_SUITE_URL`: override the suite tarball URL; defaults to the upstream `master` archive
- `CONFORMANCE_SERVER`: override the OIDF base URL; defaults to `https://demo.certification.openid.net/`

The script prints the run directory and leaves behind:

- wallet log
- mirrored official runner log
- exported OIDF result archives

## Verifier Note

The wallet’s mDoc `deviceSignature` is now emitted as a detached COSE_Sign1, which matches the current upstream suite and Multipaz parser behavior.

If your verifier already reconstructs `DeviceAuthentication` from the document and verifies the detached signature, nothing changes. If it was relying on the wallet’s previous nonstandard inline-payload `deviceSignature`, update it.

## Current status

Verified live on April 8, 2026 against the upstream suite on `master`:

- all five default scenarios ran to completion
- all happy-path modules passed
- no unexpected condition failures remained

Latest clean run artifacts from this workspace:

- run directory: `/tmp/oidf-live-full-clean.BeEP12`
- wallet log: `/tmp/oidf-live-full-clean.BeEP12/wallet.log`
- runner log: `/tmp/oidf-live-full-clean.BeEP12/runner.log`

## Scope

The strict-mode wallet is currently suitable for this OID4VP subset:

- `openid4vp://`, `haip-vp://`, `eudi-openid4vp://`
- `direct_post` and `direct_post.jwt`
- signed and unsigned `request_uri`
- `request_uri_method=post`
- DCQL-based matching
- SD-JWT and mDoc presentation

## Known gaps

Remaining gaps outside the currently passing wallet matrix:

- no `dc_api` / `dc_api.jwt` response modes
- no full verifier trust-anchor validation beyond the supplied `x5c`
- HAIP support is an OID4VP subset, not full HAIP issuance/profile coverage

## References

- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- [OIDF Conformance Service](https://www.certification.openid.net/)
