# Validate

Validate a credential by checking signatures, expiry, and revocation status. Unlike `decode` (which only parses and displays), `validate` actively checks correctness.

If neither `--key` nor `--trust-list` is provided, signature verification is skipped and only expiry and status checks are performed. This is useful for quick revocation checks without needing the issuer's key.

```bash
# Full validation with signature verification
oid4vc-dev validate --key issuer-key.pem credential.txt
oid4vc-dev validate --trust-list trust-list.jwt credential.txt
oid4vc-dev validate --key key.pem --status-list credential.txt
oid4vc-dev validate --key key.pem --allow-expired credential.txt

# Expiry + revocation check without signature verification
oid4vc-dev validate --status-list credential.txt
oid4vc-dev validate credential.txt
```

## Flags

| Flag              | Description                                       |
|-------------------|---------------------------------------------------|
| `--key`           | Public key file (PEM or JWK) — optional            |
| `--trust-list`    | ETSI trust list JWT (file path or URL) — optional   |
| `--status-list`   | Check revocation via status list (network call)    |
| `--allow-expired` | Don't fail on expired credentials                  |

## Certificate chain validation

When a trust list is provided and the credential contains an x5c (SD-JWT/JWT) or x5chain (mDOC) certificate chain, the chain is validated against the trust list before verifying the signature. The validation follows the real-world EUDI flow:

1. The trust list contains **CA certificates** (trust anchors)
2. The credential's x5c/x5chain contains `[leaf, ...intermediates]`
3. The leaf certificate is verified to chain up to a trust list CA via any intermediates
4. The leaf certificate's public key is used to verify the credential signature

This matches the Bundesdruckerei PID provider setup where the trust list contains CA certificates like "PIDP Preprod CA" and credentials carry a leaf certificate signed by that CA.

Wallet-generated SD-JWT credentials follow the same model: the SD-JWT header carries a deterministic `kid` plus the leaf signing certificate in `x5c`, while the wallet trust list exposes the CA trust anchor separately. The wallet also publishes HTTPS JWT VC issuer metadata at `/.well-known/jwt-vc-issuer` for ecosystems that resolve issuer keys via metadata/JWKS.

```bash
# Validate a wallet-issued credential against the wallet's trust list
oid4vc-dev validate --trust-list http://localhost:8085/api/trustlist credential.txt

# Validate against the German PID provider trust list
oid4vc-dev validate --trust-list https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt credential.txt
```
