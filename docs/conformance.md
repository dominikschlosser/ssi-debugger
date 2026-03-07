# OIDF Conformance

This repository can run the official OpenID Foundation wallet runner in **strict** mode against the OID4VP early-version wallet plan, with the local wallet acting as the wallet under test.

## What the script does

`scripts/oidf-wallet-conformance.sh` now:

- loads `OIDF_TOKEN` from the local `.env` file or `CONFORMANCE_TOKEN` from the environment
- downloads the latest official OIDF conformance suite
- creates a Python virtualenv with the runner dependencies
- starts `oid4vc-dev wallet serve --mode strict --auto-accept --pid`
- derives a local DCQL config from the official `vp-wallet-test-config-dcql.json`
- runs the official `run-test-plan.py` against `https://demo.certification.openid.net/`
- monitors waiting modules and automatically:
  - submits the generated verifier request URL into the local wallet
  - follows returned verifier `redirect_uri` values
  - uploads a placeholder screenshot for negative tests that require one

The script currently targets the official wallet plan:

- `oid4vp-1final-wallet-test-plan`
- display name: `OpenID for Verifiable Presentations 1.0 Final: Test a wallet - alpha tests (not currently part of certification program)`

## Default scenario

By default the wrapper runs only the stable strict-mode scenario:

- signed `request_uri` with `x509_hash` client IDs

This run covers:

- `happy-flow-no-state`
- `happy-flow-with-state-and-redirect`
- `invalid-request-object-signature`

The scenario uses:

- `vp_profile=plain_vp`
- `response_mode=direct_post`
- `credential_format=sd_jwt_vc`

## Optional alpha scenario

You can opt into the current unsigned alpha path with:

```bash
OIDF_INCLUDE_ALPHA_UNSIGNED=1 scripts/oidf-wallet-conformance.sh
```

That adds:

- unsigned `request_uri` with `redirect_uri` client IDs

This is kept behind an explicit flag because the current OIDF alpha suite omits the required `typ: oauth-authz-req+jwt` header for that path, so a spec-strict wallet rejects it.

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

- `PORT`: wallet port, default `8085`
- `OIDF_RUN_DIR`: keep all runner artifacts in a chosen directory instead of a temp dir
- `OIDF_WALLET_DIR`: reuse a specific wallet store
- `OIDF_INCLUDE_ALPHA_UNSIGNED=1`: also run the current unsigned alpha scenario
- `CONFORMANCE_SERVER`: override the OIDF base URL; defaults to `https://demo.certification.openid.net/`

The script prints the run directory and leaves behind:

- wallet log
- mirrored official runner log
- exported OIDF result archives

## Current scope

The strict-mode wallet is currently suitable for this OID4VP subset:

- `openid4vp://`, `haip-vp://`, `eudi-openid4vp://`
- `direct_post` and `direct_post.jwt`
- signed and unsigned `request_uri`
- `request_uri_method=post`
- DCQL-based matching
- SD-JWT and mDoc presentation

## Known gaps

These are the remaining blockers for broad OID4VP wallet-suite coverage:

- no `dc_api` / `dc_api.jwt` response modes
- no full verifier trust-anchor validation beyond the supplied `x5c`
- HAIP support is an **OID4VP subset**, not full HAIP 1.0 issuance/profile coverage
- the current OIDF **alpha** unsigned `request_uri` path omits the required `typ: oauth-authz-req+jwt` header, so a spec-strict wallet rejects that opt-in scenario until the suite is updated

## References

- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- [OIDF Conformance Service](https://www.certification.openid.net/)
