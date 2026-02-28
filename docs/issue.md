# Issue

Generate test SD-JWT, JWT, or mDOC credentials for development and testing. Produces valid, signed credentials using an ephemeral P-256 key by default (prints the public JWK to stderr).

```bash
oid4vc-dev issue sdjwt
oid4vc-dev issue sdjwt --pid
oid4vc-dev issue sdjwt --pid --omit resident_address,birth_place,administrative_number
oid4vc-dev issue sdjwt --claims '{"name":"Test","age":30}'
oid4vc-dev issue sdjwt --iss https://my-issuer.example --vct my-type --exp 48h
oid4vc-dev issue sdjwt --key signing-key.pem
oid4vc-dev issue sdjwt --wallet                # Issue and import into wallet
oid4vc-dev issue jwt                           # Plain JWT VC (no selective disclosure)
oid4vc-dev issue jwt --pid
oid4vc-dev issue jwt --claims '{"name":"Test","age":30}'
oid4vc-dev issue mdoc
oid4vc-dev issue mdoc --pid
oid4vc-dev issue mdoc --claims '{"name":"Test"}' --doc-type com.example.test
oid4vc-dev issue mdoc --pid --wallet           # Issue mDoc and import into wallet
```

Round-trip with decode:

```bash
oid4vc-dev issue sdjwt | oid4vc-dev decode
oid4vc-dev issue jwt   | oid4vc-dev decode
oid4vc-dev issue mdoc  | oid4vc-dev decode
```

## Flags

### `issue sdjwt`

| Flag       | Default                   | Description                                    |
|------------|---------------------------|------------------------------------------------|
| `--claims` | —                         | Claims as JSON string or `@filepath`           |
| `--key`    | —                         | Private key file (PEM or JWK); ephemeral if omitted |
| `--iss`    | `https://issuer.example`  | Issuer URL                                     |
| `--vct`    | `urn:eudi:pid:de:1`       | Verifiable Credential Type                     |
| `--exp`    | `24h`                     | Expiration duration                            |
| `--pid`    | `false`                   | Use full EUDI PID Rulebook claims              |
| `--omit`   | —                         | Comma-separated claim names to exclude         |
| `--wallet` | `false`                   | Import the issued credential into the wallet   |

### `issue jwt`

| Flag       | Default                   | Description                                    |
|------------|---------------------------|------------------------------------------------|
| `--claims` | —                         | Claims as JSON string or `@filepath`           |
| `--key`    | —                         | Private key file (PEM or JWK); ephemeral if omitted |
| `--iss`    | `https://issuer.example`  | Issuer URL                                     |
| `--vct`    | `urn:eudi:pid:de:1`       | Verifiable Credential Type                     |
| `--exp`    | `24h`                     | Expiration duration                            |
| `--pid`    | `false`                   | Use full EUDI PID Rulebook claims              |
| `--omit`   | —                         | Comma-separated claim names to exclude         |
| `--wallet` | `false`                   | Import the issued credential into the wallet   |

Unlike SD-JWT, the JWT subcommand produces a standard JWT with all claims directly in the payload — no selective disclosure, no `_sd` or `_sd_alg` fields.

### `issue mdoc`

| Flag          | Default                        | Description                                    |
|---------------|--------------------------------|------------------------------------------------|
| `--claims`    | —                              | Claims as JSON string or `@filepath`           |
| `--key`       | —                              | Private key file (PEM or JWK); ephemeral if omitted |
| `--doc-type`  | `eu.europa.ec.eudi.pid.1`      | Document type                                  |
| `--namespace` | `eu.europa.ec.eudi.pid.1`      | Namespace                                      |
| `--pid`       | `false`                        | Use full EUDI PID Rulebook claims              |
| `--omit`      | —                              | Comma-separated claim names to exclude         |
| `--wallet`    | `false`                        | Import the issued credential into the wallet   |

When no `--claims` are provided, a minimal set of PID-like claims is used (given_name, family_name, birth_date). With `--pid`, the full EUDI PID Rulebook claim set is generated (27 claims including address, nationality, age attributes, document metadata, etc.).
