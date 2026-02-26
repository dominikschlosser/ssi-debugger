# ssi-debugger

A local-first CLI tool for decoding, validating, and inspecting SSI credentials — SD-JWT and mDOC (mso_mdoc).

No network calls by default. Decode and verify credentials entirely offline.

## Install

### From GitHub Releases

Download the latest binary for your platform from [Releases](https://github.com/dominikschlosser/ssi-debugger/releases).

### From source

```bash
go install github.com/dominikschlosser/ssi-debugger@latest
```

### Build locally

```bash
git clone https://github.com/dominikschlosser/ssi-debugger.git
cd ssi-debugger
go build -o ssi-debugger .
```

## Usage

```
ssi-debugger [--json] [--no-color] [-v] <command> [flags] [input]
```

Input can be a **file path**, **URL**, **raw credential string**, or piped via **stdin**.

### Commands

| Command    | Purpose                                                    |
|------------|------------------------------------------------------------|
| `decode`   | Auto-detect & decode SD-JWT or mDOC, show all claims       |
| `validate` | Decode + verify signatures, check status/trust              |
| `status`   | Check revocation via status list (network call)             |
| `trust`    | Inspect an ETSI TS 119 602 trust list JWT                   |
| `dcql`     | Generate a DCQL query from a credential's claims            |
| `version`  | Print version                                               |

### Decode

```bash
ssi-debugger decode credential.txt
ssi-debugger decode "eyJhbGci..."
ssi-debugger decode --json credential.txt
ssi-debugger decode -v credential.txt
cat credential.txt | ssi-debugger decode
```

### Validate

Requires `--key` or `--trust-list` (or both).

```bash
ssi-debugger validate --key issuer-key.pem credential.txt
ssi-debugger validate --trust-list trust-list.jwt credential.txt
ssi-debugger validate --key key.pem --status-list credential.txt
ssi-debugger validate --key key.pem --allow-expired credential.txt
```

| Flag              | Description                                       |
|-------------------|---------------------------------------------------|
| `--key`           | Public key file (PEM or JWK)                      |
| `--trust-list`    | ETSI trust list JWT (file path or URL)             |
| `--status-list`   | Check revocation via status list (network call)    |
| `--allow-expired` | Don't fail on expired credentials                  |

### Status

Check credential revocation via the status list endpoint embedded in the credential.

```bash
ssi-debugger status credential.txt
```

### Trust

Inspect an ETSI TS 119 602 trust list JWT. Accepts a file path or URL.

```bash
ssi-debugger trust trust-list.jwt
ssi-debugger trust https://example.com/trust-list.jwt
```

### DCQL

Generate a DCQL (Digital Credentials Query Language) query from a credential's claims. Always outputs JSON.

```bash
ssi-debugger dcql credential.txt
```

## Supported Formats

### SD-JWT (`dc+sd-jwt`)

- Decodes JWT header/payload and all disclosures
- Resolves `_sd` digest arrays
- Shows key binding JWT if present
- Signature verification: ES256, ES384, ES512, RS256, RS384, RS512, PS256

### mDOC (`mso_mdoc`)

- Decodes CBOR IssuerSigned and DeviceResponse (hex or base64url input)
- Parses COSE_Sign1 issuerAuth and MSO (Mobile Security Object)
- COSE signature verification via go-cose

## Global Flags

| Flag         | Description              |
|--------------|--------------------------|
| `--json`     | Output as JSON           |
| `--no-color` | Disable colored output   |
| `-v`         | Verbose output           |

## License

Apache-2.0
