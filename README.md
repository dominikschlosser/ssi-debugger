# ssi-debugger

[![CI](https://github.com/dominikschlosser/ssi-debugger/actions/workflows/ci.yml/badge.svg)](https://github.com/dominikschlosser/ssi-debugger/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dominikschlosser/ssi-debugger)](https://github.com/dominikschlosser/ssi-debugger/releases/latest)

A local-first CLI tool for decoding, validating, and inspecting SSI credentials and OpenID4VCI/VP requests.

No network calls by default. Decode and verify credentials entirely offline.

## Highlights

- **Testing Wallet** — stateful CLI wallet with file persistence, OID4VP/VCI flows, QR scanning, and OS URL scheme registration ([wallet](#wallet))
- **Reverse Proxy** — intercept, classify, and decode OID4VP/VCI wallet traffic in real time ([proxy](#proxy))
- **Web UI** — paste, decode, and validate credentials in a split-pane browser interface ([serve](#serve))
- **Unified Decode** — a single `decode` command handles SD-JWT, JWT, mDOC, OID4VCI offers, OID4VP requests, and ETSI trust lists
- **QR Screen Capture** — scan a QR code straight from your screen to decode credentials or OpenID requests ([decode --screen](#qr-code-scanning))
- **Offline Decode & Validate** — SD-JWT, mDOC, JWT with signature verification and trust list support
- **DCQL Generation** — generate Digital Credentials Query Language queries from existing credentials

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
| `wallet`   | Stateful testing wallet with CLI-driven OID4VP/VCI flows   |
| `issue`    | Generate test SD-JWT or mDOC credentials                   |
| `proxy`    | Debugging reverse proxy for OID4VP/VCI wallet traffic      |
| `serve`    | Web UI for decoding and validating credentials in the browser |
| `decode`   | Auto-detect & decode credentials, OpenID4VCI/VP, and trust lists (read-only, no verification) |
| `validate` | Verify signatures, check expiry, and check revocation status |
| `dcql`     | Generate a DCQL query from a credential's claims            |
| `version`  | Print version                                               |

---

### Wallet

A stateful testing wallet with file persistence, CLI-driven OID4VP/VCI flows, QR scanning, and OS URL scheme registration. Credentials and keys are stored in `~/.ssi-debugger/wallet/` (configurable via `--wallet-dir`) and persist across invocations.

#### Subcommands

| Subcommand     | Purpose                                                         |
|----------------|-----------------------------------------------------------------|
| `serve`        | Start wallet HTTP server with web UI, OID4VP endpoints, and optional URL scheme handling |
| `list`         | List stored credentials                                         |
| `import`       | Import a credential from file, stdin, or raw string             |
| `remove`       | Remove a credential by ID                                       |
| `generate-pid` | Generate default EUDI PID credentials (SD-JWT + mDoc)           |
| `accept`       | Accept an OID4VP presentation request or OID4VCI credential offer (auto-detects) |
| `scan`         | Scan a QR code and auto-dispatch to accept/import               |
| `trust-list`   | Print the trust list URL for a running wallet server            |
| `register`     | Register OS URL scheme handlers (macOS only)                    |
| `unregister`   | Remove OS URL scheme handlers                                   |

#### Quick start

```bash
# Generate PID credentials and list them (re-running replaces existing PIDs)
ssi-debugger wallet generate-pid
ssi-debugger wallet generate-pid --claims '{"given_name":"MAX","family_name":"POWER"}'
ssi-debugger wallet list

# Start the wallet web UI with stored credentials
ssi-debugger wallet serve

# Start the wallet and register URL scheme handlers
ssi-debugger wallet serve --register

# Process an OID4VP request from the CLI
ssi-debugger wallet accept 'openid4vp://authorize?client_id=...'

# Accept a credential offer (auto-detected from URI)
ssi-debugger wallet accept 'openid-credential-offer://...'

# Scan a QR code from screen and auto-detect the flow
ssi-debugger wallet scan --screen

# Import a credential from a file
ssi-debugger wallet import credential.txt

# Register URL scheme handlers so openid4vp:// links open the wallet
ssi-debugger wallet register
```

#### Storage

All wallet state is stored in `~/.ssi-debugger/wallet/` by default:

```
~/.ssi-debugger/wallet/
├── wallet.json       # Credentials + metadata
├── holder.pem        # Holder EC private key (auto-generated on first use)
└── issuer.pem        # Issuer EC private key (for self-issued credentials)
```

Keys are P-256 EC keys, auto-generated on first use and reused across invocations.

#### `wallet serve`

Starts a persistent wallet HTTP server with a web UI for managing credentials and handling OID4VP/OID4VCI flows. Loads credentials from disk and saves state on credential changes. Includes request logging with timestamps and a browser-based consent UI for incoming requests.

The server exposes:
- Web UI for credential management and consent
- OID4VP authorization endpoint (`/authorize`)
- ETSI trust list endpoint (`/api/trustlist`) — use this URL as `--trust-list` when validating credentials issued by the wallet

Use `--register` to also register OS URL scheme handlers so that `openid4vp://` and `openid-credential-offer://` links automatically open the wallet.

```bash
ssi-debugger wallet serve
ssi-debugger wallet serve --port 9000 --auto-accept
ssi-debugger wallet serve --pid --credential extra.txt
ssi-debugger wallet serve --register           # also register URL scheme handlers
ssi-debugger wallet serve --register --port 9000
```

| Flag                    | Default  | Description                                      |
|-------------------------|----------|--------------------------------------------------|
| `--port`                | `8085`   | Server port                                      |
| `--auto-accept`         | `false`  | Auto-approve all presentations (headless mode)   |
| `--credential`          | —        | Import credential from file (repeatable)         |
| `--pid`                 | `false`  | Generate default EUDI PID credentials on start   |
| `--key`                 | —        | Override holder key (PEM/JWK)                    |
| `--issuer-key`          | —        | Override issuer key (PEM/JWK)                    |
| `--session-transcript`  | `oid4vp` | mDoc session transcript mode: `oid4vp` or `iso`  |
| `--register`            | `false`  | Register OS URL scheme handlers                  |
| `--no-register`         | `false`  | Skip URL scheme registration (overrides --register) |

#### `wallet accept <uri>`

Auto-detects the URI type and dispatches to the appropriate flow:

- `openid4vp://`, `haip://`, `eudi-openid4vp://` → OID4VP presentation (evaluates DCQL, shows consent UI, submits VP token)
- `openid-credential-offer://` → OID4VCI credential issuance (fetches credential from issuer)

In interactive mode (default), OID4VP requests start a temporary consent UI server and auto-open it in the browser. With `--auto-accept`, auto-selects and submits the first matching credentials.

```bash
ssi-debugger wallet accept 'openid4vp://authorize?...' --auto-accept
ssi-debugger wallet accept 'openid-credential-offer://...'
```

#### `wallet scan`

Scans a QR code from an image file or screen capture and auto-detects the content:

- `openid4vp://` → delegates to `accept` (OID4VP presentation)
- `openid-credential-offer://` → delegates to `accept` (OID4VCI issuance)
- SD-JWT / mDoc raw credential → delegates to `import`

```bash
ssi-debugger wallet scan qr-image.png
ssi-debugger wallet scan --screen              # macOS interactive screen capture
ssi-debugger wallet scan --screen --auto-accept # auto-approve if it's a presentation
```

#### `wallet trust-list`

Generates and prints the ETSI trust list JWT containing the wallet's issuer certificate. The output can be piped to a file or used directly with `--trust-list` in the `validate` command. Use `--url` to print only the URL for a running wallet server instead.

```bash
ssi-debugger wallet trust-list                          # Print the trust list JWT
ssi-debugger wallet trust-list > trustlist.jwt          # Save to file
ssi-debugger wallet trust-list --url                    # http://localhost:8085/api/trustlist
ssi-debugger wallet trust-list --url --port 9000        # http://localhost:9000/api/trustlist
ssi-debugger wallet trust-list --url --docker           # http://host.docker.internal:8085/api/trustlist
```

| Flag       | Default | Description                                        |
|------------|---------|----------------------------------------------------|
| `--url`    | `false` | Print only the trust list URL (for a running server) |
| `--port`   | `8085`  | Wallet server port (used with --url)                |
| `--docker` | `false` | Use `host.docker.internal` instead of `localhost` (used with --url) |

#### `wallet register` / `wallet unregister`

Registers (or removes) OS-level URL scheme handlers so that `openid4vp://`, `eudi-openid4vp://`, `haip://`, and `openid-credential-offer://` links automatically open the wallet.

The handler script first tries to POST to a running `wallet serve` instance. If the server is not running, it falls back to invoking the CLI directly (`wallet accept`).

- **macOS**: Creates an AppleScript `.app` bundle in `~/Applications/` and registers via Launch Services
- **Other platforms**: Not supported — use `wallet accept <uri>` instead

```bash
ssi-debugger wallet register               # Register URL handlers (default listener port 8085)
ssi-debugger wallet register --port 9000   # Use custom listener port
ssi-debugger wallet unregister             # Remove URL handlers
```

| Flag     | Default | Description                                                    |
|----------|---------|----------------------------------------------------------------|
| `--port` | `8085`  | Listener port for handler script to try before falling back to CLI |

#### Shared flag

All wallet subcommands accept `--wallet-dir` to override the storage directory:

```bash
ssi-debugger wallet list --wallet-dir /tmp/test-wallet
```

---

### Issue

Generate test SD-JWT or mDOC credentials for development and testing. Produces valid, signed credentials using an ephemeral P-256 key by default (prints the public JWK to stderr).

```bash
ssi-debugger issue sdjwt
ssi-debugger issue sdjwt --pid
ssi-debugger issue sdjwt --pid --omit resident_address,birth_place,administrative_number
ssi-debugger issue sdjwt --claims '{"name":"Test","age":30}'
ssi-debugger issue sdjwt --iss https://my-issuer.example --vct my-type --exp 48h
ssi-debugger issue sdjwt --key signing-key.pem
ssi-debugger issue sdjwt --wallet                # Issue and import into wallet
ssi-debugger issue mdoc
ssi-debugger issue mdoc --pid
ssi-debugger issue mdoc --claims '{"name":"Test"}' --doc-type com.example.test
ssi-debugger issue mdoc --pid --wallet           # Issue mDoc and import into wallet
```

Round-trip with decode:

```bash
ssi-debugger issue sdjwt | ssi-debugger decode
ssi-debugger issue mdoc  | ssi-debugger decode
```

#### Flags

**`issue sdjwt`:**

| Flag       | Default                   | Description                                    |
|------------|---------------------------|------------------------------------------------|
| `--claims` | —                         | Claims as JSON string or `@filepath`           |
| `--key`    | —                         | Private key file (PEM or JWK); ephemeral if omitted |
| `--iss`    | `https://issuer.example`  | Issuer URL                                     |
| `--vct`    | `urn:eudi:pid:1`          | Verifiable Credential Type                     |
| `--exp`    | `24h`                     | Expiration duration                            |
| `--pid`    | `false`                   | Use full EUDI PID Rulebook claims              |
| `--omit`   | —                         | Comma-separated claim names to exclude         |
| `--wallet` | `false`                   | Import the issued credential into the wallet   |

**`issue mdoc`:**

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

---

### Proxy

Intercept and debug OID4VP/VCI traffic between a wallet and a verifier/issuer. Point your wallet at the proxy instead of the real server — every request and response is captured, classified by protocol step, decoded, and displayed both in the terminal and a live web dashboard.

```bash
ssi-debugger proxy --target http://localhost:8080
ssi-debugger proxy --target http://localhost:8080 --port 9090 --dashboard 9091
ssi-debugger proxy --target http://localhost:8080 --no-dashboard
```

```
Wallet  <-->  Proxy (:9090)  <-->  Verifier/Issuer (:8080)
                  |
            Live dashboard (:9091)
```

Traffic is automatically classified into protocol steps:

| Badge               | Detected when                                                     |
|---------------------|-------------------------------------------------------------------|
| VP Auth Request     | `client_id` + `response_type=vp_token` in query                  |
| VP Request Object   | Response body is a JWT (request object fetch)                     |
| VP Auth Response    | POST body contains `vp_token`, `presentation_submission`, `id_token`, or `response` (JARM) |
| VCI Credential Offer| `credential_offer` / `credential_offer_uri` in query              |
| VCI Metadata        | Path contains `.well-known/openid-credential-issuer`              |
| VCI Token Request   | POST to path ending `/token`                                      |
| VCI Credential Req  | POST to path ending `/credential`                                 |

By default, only OID4VP/VCI traffic is shown. Non-matching requests (favicon, health checks, etc.) are still proxied but hidden from the output. Pass `--all-traffic` or toggle the "All traffic" checkbox in the dashboard to see everything.

#### NDJSON output

Use `--json` to get machine-readable output (one JSON object per line), suitable for piping to `jq` or logging:

```bash
ssi-debugger proxy --target http://localhost:8080 --json
ssi-debugger proxy --target http://localhost:8080 --json 2>/dev/null | jq .classLabel
ssi-debugger proxy --target http://localhost:8080 --json --all-traffic >> traffic.jsonl
```

#### Flow correlation

Related protocol steps (e.g., VP Auth Request → Request Object → Auth Response) are automatically grouped into flows using shared `state` or `nonce` values. Each entry includes a `flowId` field when correlated. In the dashboard, click **"Timeline"** to switch from a flat list to a grouped flow view with collapsible sections.

#### Smart decoding

Decoded payloads are shown inline — the proxy understands the structure of each protocol step:

- **VP Auth Request**: `client_id`, `response_mode`, `nonce`, `state`, `request_uri`, `response_uri`, plus `dcql_query` and `presentation_definition` parsed as JSON
- **VP Request Object**: JWT header and payload, including the verifier's `jwks` (ephemeral encryption key for JARM)
- **VP Auth Response**: `vp_token` decoded as SD-JWT/JWT/mDOC, `presentation_submission` as JSON, `state`
- **VCI flows**: credential offer JSON, issuer metadata, token request/response, credential request/response with inline credential decoding

#### Encrypted responses (direct_post.jwt / JARM)

When `response_mode=direct_post.jwt` is used, the wallet sends an encrypted JWE instead of plain form parameters. The proxy detects this and shows:

- The JWE protected header (`alg`, `enc`, `kid`, `epk`, `apu`, `apv`)
- A note that the payload is encrypted

The **verifier's ephemeral public key** (used by the wallet for encryption) is extracted from the request object's `jwks` claim and shown in the VP Request Object entry, so you can correlate the two sides of the flow.

> **Why can't the proxy decrypt JARM responses?** The verifier generates an **ephemeral key pair** for each authorization session. It sends the public key to the wallet (in the signed request object JWT), and the wallet encrypts the response to that key. The proxy can see the public key but never has access to the private key — it lives only inside the verifier. Modifying the request object to substitute the proxy's own key would break the verifier's signature, which the wallet verifies.
>
> **Workaround:** If your verifier has a debug mode that logs or exports ephemeral private keys, you can use those to decrypt the JWE offline. The proxy shows the `kid` to help you match the right key.

#### Web dashboard

The **web dashboard** at `http://localhost:9091` shows the same traffic with expandable cards, live SSE updates, and dark/light theme support. Open it alongside your terminal for full visibility.

When the proxy captures a credential (vp_token, id_token, or issued credential), the expanded entry shows a **"View in Decoder"** button that opens the credential in the full decoder web UI (served at `/decode/` on the dashboard port). This gives you the same decode experience as `ssi-debugger serve` without running a separate command.

#### HAR export

Click **"Export HAR"** in the dashboard header to download all captured traffic as a HAR 1.2 file. The file can be imported into Chrome DevTools, Firefox, or any HAR viewer for offline analysis.

#### cURL copy

Expand any entry in the dashboard and click **"Copy cURL"** to copy a `curl` command that reproduces the request. Paste it in a terminal to replay requests during debugging.

#### Flags

| Flag             | Default | Description                              |
|------------------|---------|------------------------------------------|
| `--target`       | —       | URL of the verifier/issuer (required)    |
| `--port`         | `9090`  | Proxy listen port                        |
| `--dashboard`    | `9091`  | Dashboard listen port                    |
| `--no-dashboard` | `false` | Disable web dashboard                    |
| `--all-traffic`  | `false` | Show all traffic, not just OID4VP/VCI    |
| `--json`         | `false` | NDJSON output to stdout (global flag)    |

#### Terminal output example

```
━━━ [14:32:05] GET /authorize?client_id=...  ← 200 (45ms)  [VP Auth Request]
    ┌ client_id: did:web:verifier.example
    ┌ response_mode: direct_post.jwt
    ┌ nonce: abc123
    ┌ dcql_query:
      {
        "credentials": [
          {
            "id": "cred1",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:1"] },
            "claims": [
              { "id": "claim1", "path": ["given_name"] },
              { "id": "claim2", "path": ["family_name"] }
            ]
          }
        ]
      }

━━━ [14:32:05] GET /request/abc123  ← 200 (12ms)  [VP Request Object]
    ┌ header: {"alg":"ES256","typ":"oauth-authz-req+jwt"}
    ┌ payload: { ... }
    ┌ encryption_jwks: {"keys":[{"kty":"EC","crv":"P-256","x":"...","y":"..."}]}

━━━ [14:32:06] POST /response  ← 200 (89ms)  [VP Auth Response]
    ┌ response_type: JWE (encrypted)
    ┌ encryption_alg: ECDH-ES
    ┌ encryption_enc: A256GCM
    ┌ encryption_epk: {"kty":"EC","crv":"P-256","x":"...","y":"..."}
```

---

### Serve

Start a local web UI for decoding and validating credentials in the browser.

```bash
ssi-debugger serve
ssi-debugger serve --port 3000
ssi-debugger serve credential.txt
ssi-debugger serve "eyJhbGci..."
```

Opens a split-pane interface at `http://localhost:8080` (default) where you can paste SD-JWT, JWT, or mDOC credentials and instantly see decoded output. Features include auto-decode on paste, format detection badges, collapsible sections, JSON syntax highlighting, cross-highlighting between raw and decoded views, signature verification, and dark/light theme toggle.

> **Warning:** Credentials are sent to the server for decoding. Only run `ssi-debugger serve` locally on your own machine — do not expose it on a network or use it with real production credentials on a shared server.

![Web UI screenshot](docs/web-ui.png)

Pass a credential as an argument (file path, URL, or raw string) to pre-fill the input on load. You can also use the `?credential=` query parameter on the URL, e.g. `http://localhost:8080/?credential=eyJhbGci...`.

---

### Decode

Auto-detect and decode credentials (SD-JWT, JWT, mDOC), OpenID4VCI/VP requests, and ETSI trust lists.

```bash
# Credentials
ssi-debugger decode credential.txt
ssi-debugger decode "eyJhbGci..."
ssi-debugger decode --json credential.txt
ssi-debugger decode -v credential.txt
cat credential.txt | ssi-debugger decode

# OpenID4VCI credential offers
ssi-debugger decode 'openid-credential-offer://?credential_offer_uri=...'
ssi-debugger decode 'https://issuer.example/offer?credential_offer=...'

# OpenID4VP authorization requests
ssi-debugger decode 'openid4vp://authorize?...'
ssi-debugger decode 'haip://authorize?...'
ssi-debugger decode 'eudi-openid4vp://authorize?...'
ssi-debugger decode request.jwt
cat offer.json | ssi-debugger decode

# ETSI trust lists
ssi-debugger decode trust-list.jwt
ssi-debugger decode -f trustlist https://example.com/trust-list.jwt
```

Auto-detection order:

1. **OpenID URI schemes** — `openid-credential-offer://` (VCI), `openid4vp://` / `haip://` / `eudi-openid4vp://` (VP)
2. **HTTP(S) URL with OID4 query params** — `credential_offer` / `credential_offer_uri` (VCI), `client_id` / `response_type` / `request_uri` (VP)
3. **SD-JWT** — contains `~` separator
4. **mDOC** — hex or base64url encoded CBOR
5. **JSON** — inspected for OID4 marker keys (`credential_issuer` → VCI, `client_id` → VP)
6. **JWT** — 3 dot-separated parts; payload inspected for OID4 markers and trust list markers (`TrustedEntitiesList`)

#### Format override

Use `--format` / `-f` to skip auto-detection when it gets it wrong (e.g. a credential JWT whose payload happens to contain `credential_issuer`):

```bash
ssi-debugger decode -f jwt "eyJhbGci..."
ssi-debugger decode -f sdjwt credential.txt
ssi-debugger decode -f mdoc credential.hex
ssi-debugger decode -f vci 'openid-credential-offer://...'
ssi-debugger decode -f vp request.jwt
```

Accepted values: `sdjwt` (or `sd-jwt`), `jwt`, `mdoc` (or `mso_mdoc`), `vci` (or `oid4vci`), `vp` (or `oid4vp`), `trustlist` (or `trust`).

#### QR Code Scanning

Scan a QR code directly from an image file or a screen capture:

```bash
ssi-debugger decode --qr screenshot.png
ssi-debugger decode --screen
```

`--screen` uses the native macOS `screencapture` tool in interactive selection mode — a crosshair appears to let you select the region containing the QR code. On other platforms, take a screenshot and use `--qr screenshot.png` instead.

> **Note:** Screen capture permission on macOS is granted to the **terminal app** (Terminal.app, iTerm2, etc.), not to `ssi-debugger` itself. If permission is missing, System Settings will be opened automatically to the Screen Recording pane — enable access for your terminal app there, then re-run the command.

#### Flags

| Flag             | Description                                                  |
|------------------|--------------------------------------------------------------|
| `-f`, `--format` | Pin format: `sdjwt`, `jwt`, `mdoc`, `vci`, `vp`, `trustlist` |
| `--qr`           | Decode QR from a PNG or JPEG image file                      |
| `--screen`       | Open interactive screen region selector and decode a QR code from the selection (macOS only) |

`--qr`, `--screen`, and positional input arguments are mutually exclusive.

#### SD-JWT example

```
SD-JWT Credential
──────────────────────────────────────────────────

┌ Header
  alg: ES256
  typ: dc+sd-jwt

┌ Payload (signed claims)
  _sd: ["77ofip...", "EyNwlR...", "X3X1zI..."]
  _sd_alg: sha-256
  exp: 1742592000
  iat: 1740000000
  iss: https://issuer.example
  vct: urn:eudi:pid:1

┌ Disclosed Claims (3)
  [1] given_name: Erika
  [2] family_name: Mustermann
  [3] birth_date: 1984-08-12
```

#### mDOC example

```
mDOC Credential
──────────────────────────────────────────────────
  (parsed from DeviceResponse)

┌ Document Info
  DocType: eu.europa.ec.eudi.pid.1
  MSO Version: 1.0
  Digest Algorithm: SHA-256
  Signed: 2026-02-25T00:00:00Z
  Valid From: 2026-02-25T00:00:00Z
  Valid Until: 2026-03-11T00:00:00Z (in 13 days)

┌ Namespace: eu.europa.ec.eudi.pid.1 (7 claims)
  birth_date: 1984-08-12
  family_name: MUSTERMANN
  given_name: ERIKA
  resident_city: KÖLN
  resident_country: DE
  resident_postal_code: 51147
  resident_street: HEIDESTRAẞE 17
```

With `-v`, each claim also shows its `digestID`, x5c certificate chains are displayed, and mDOC device key info is included. With `--json`, output is machine-readable:

```json
{
  "format": "dc+sd-jwt",
  "header": { "alg": "ES256", "typ": "dc+sd-jwt" },
  "payload": { "iss": "https://issuer.example", "vct": "urn:eudi:pid:1", "..." : "..." },
  "resolvedClaims": {
    "given_name": "Erika",
    "family_name": "Mustermann",
    "birth_date": "1984-08-12"
  },
  "disclosures": [
    { "name": "given_name", "value": "Erika", "salt": "...", "digest": "..." }
  ]
}
```

---

### Validate

Validate a credential by checking signatures, expiry, and revocation status. Unlike `decode` (which only parses and displays), `validate` actively checks correctness.

If neither `--key` nor `--trust-list` is provided, signature verification is skipped and only expiry and status checks are performed. This is useful for quick revocation checks without needing the issuer's key.

```bash
# Full validation with signature verification
ssi-debugger validate --key issuer-key.pem credential.txt
ssi-debugger validate --trust-list trust-list.jwt credential.txt
ssi-debugger validate --key key.pem --status-list credential.txt
ssi-debugger validate --key key.pem --allow-expired credential.txt

# Expiry + revocation check without signature verification
ssi-debugger validate --status-list credential.txt
ssi-debugger validate credential.txt
```

| Flag              | Description                                       |
|-------------------|---------------------------------------------------|
| `--key`           | Public key file (PEM or JWK) — optional            |
| `--trust-list`    | ETSI trust list JWT (file path or URL) — optional   |
| `--status-list`   | Check revocation via status list (network call)    |
| `--allow-expired` | Don't fail on expired credentials                  |

When a trust list is provided and the credential contains an x5c (SD-JWT) or x5chain (mDOC) certificate chain, the chain is validated against the trust list before verifying the signature.

---

### DCQL

Generate a DCQL (Digital Credentials Query Language) query from a credential's claims. Always outputs JSON.

```bash
ssi-debugger dcql credential.txt
```

**Example output (SD-JWT):**

```json
{
  "credentials": [
    {
      "id": "urn_eudi_pid_1",
      "format": "dc+sd-jwt",
      "meta": { "vct_values": ["urn:eudi:pid:1"] },
      "claims": [
        { "path": ["birth_date"] },
        { "path": ["family_name"] },
        { "path": ["given_name"] }
      ]
    }
  ]
}
```

---

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

### OpenID4VCI / OpenID4VP

- Decodes OID4VCI credential offers (inline JSON, `credential_offer_uri`)
- Decodes OID4VP authorization requests (query params, `request_uri`, JWT request objects)
- Supports URI schemes: `openid-credential-offer://`, `openid4vp://`, `haip://`, `eudi-openid4vp://`
- Auto-detects VCI vs VP based on content

### ETSI Trust Lists

- Decodes ETSI TS 119 602 trust list JWTs
- Displays trusted entities with names, identifiers, and service types
- Accepts file paths or URLs

## Global Flags

| Flag         | Description              |
|--------------|--------------------------|
| `--json`     | Output as JSON           |
| `--no-color` | Disable colored output   |
| `-v`         | Verbose output (x5c chain, device key, digest IDs) |

## License

Apache-2.0
