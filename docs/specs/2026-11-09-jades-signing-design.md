# JAdES Signing for Customs API Consumers — Design

Date: 2026-11-09
Status: Revised 2026-11-09. The deliverable is now **one demo HTML page** plus a local
smart-card helper (§1, §6, §7, §8, §9). The signature format (§3–§5) is unchanged.

## 1. Intent

Organizations that call the Customs API must sign the content they send. This project
explains to that community **how to sign**, using one mechanism that works in two
interchangeable ways:

- **File mode** — sign a payload into a self-contained signed JSON file.
- **REST mode** — sign an HTTP request body and send the signature in the
  `X-JAdES-Signature` header.

Both modes produce **the same signature over the same bytes**. That is the point: a
consumer's own client can sign a file in its own system, hand the file to the consumer
(the "provider"), and the provider can transmit it to Customs over its mTLS connection.
Customs verifies it exactly as if the original signer had called the API directly.

The signature proves **who authored the content**. mTLS proves **who delivered it**.
These are two different certificates and must never be mixed.

### Deliverable

**One self-contained demo HTML page** that shows the mechanism to a developer, plus a
small local helper for smart-card signing. *(Replaces the earlier Node/Python/.NET
reference implementations, cross-language vectors and mock Customs endpoint.)*

The page lets a developer:

1. **Sign** — type or paste JSON, choose a key (a `.pfx` + password, or a smart card
   through the local helper), and create a signed file in the §4.1 format. Every
   intermediate step is shown: protected header JSON, its B64URL, the signing input,
   the signature, the file.
2. **Verify** — load a signed file (or paste a REST header value + body) and see
   valid/invalid with the §4.4 reason code, next to the protected header and the
   payload rendered as JSON.
3. **Prepare curl** — from a signed file, enter the URL/path and HTTP method and get a
   ready `curl` command with a correct `X-JAdES-Signature` header and the exact body
   bytes. The point is that a developer understands what their own call must look like.

The page runs entirely in the browser (no server, works offline). Keys never leave the
browser / the smart card.

**A real Customs-side verifier already exists and is the authority.** The reference
Verify must accept and reject exactly what it does. Consequences:

- The positive and negative test vectors (§8) must be run against the real Customs
  verifier (by the Customs team, or via a test environment) before the spec is
  published. Any disagreement is resolved in favour of the real verifier and the
  spec updated.
- Open item: the real API's response to a failed signature (HTTP status, error body,
  whether reason codes are exposed) is not yet known. *(My call:)* until it is,
  mock-customs returns HTTP 401 with `{ "valid": false, "reason": "<code>" }` and
  this is marked in the spec as a placeholder to align with the real API.

## 2. Goals, non-goals, anti-goals

**Goals**
- One signing format, two transports (file, HTTP header), identical verification.
- A signed file can be relayed by a third party via `SendFromFile` and verify at Customs.
- Signing keys from `.pfx`/`.p12` files and from smart cards (via the local helper).
- A developer can see every byte that is signed and sent.

**Non-goals (for now)**
- Certificate trust: chain building, trusted CA lists, revocation (CRL/OCSP),
  certificate validity period.
- Full ETSI JAdES (TS 119 182-1) conformance. We use the basics of JAdES; extra JAdES
  fields may be present but are not checked.
- Timestamps, long-term validation, counter-signatures.
- Replay protection and endpoint binding. A signed file or captured header+body can be
  re-sent within the 24-hour window, to any endpoint. This is accepted for now. Future
  option: a required `jti` member so Customs can reject duplicates; the format leaves
  room for it because extra header members are already allowed.
- Batch / multi-file processing. One file at a time.
- Reference libraries, packages, a mock server, or sending the request from the page
  (the page prepares a `curl` command; it does not call the API).
- Generic PKCS#11 / HSM support. Smart cards are reached through the Windows certificate
  store only (§6.3).

**Anti-goals (failure even if it "works")**
- The page signs or shows bytes that differ from what `curl` sends, so a command copied
  from the page fails verification.
- The REST body is re-serialized (re-formatted JSON, changed whitespace, changed
  encoding) between signing and sending, breaking verification.
- The mTLS client certificate is used as, or confused with, the signing certificate.
- The page is so abstract that a developer can't see the mechanism.
  Clarity beats cleverness — the page is an explanation.

## 3. The signature format

### 3.1 Encoding

- **B64URL** = Base64URL (RFC 4648 §5) **without padding**.
- `x5c` entries use **standard Base64 with padding** (RFC 7515 §4.1.6), not Base64URL.

### 3.2 Protected header

A JSON object. Required members:

| Member | Type | Meaning |
|---|---|---|
| `alg` | string | `"PS256"` (RSA keys) or `"ES256"` (EC P-256 keys) |
| `iat` | integer | Signing time, seconds since Unix epoch (UTC) |
| `x5c` | array of strings | Contains the **leaf signing certificate only** (DER, standard Base64) |

Example:

```json
{
  "alg": "PS256",
  "iat": 1787255527,
  "x5c": ["MIIB3DCCAYagAwIBAgIQD6x..."]
}
```

- Signers emit exactly these three members. *(My call: the reference code doesn't add
  `typ`/`cty`.)*
- Consumers may add any other members (including other JAdES fields). Verify accepts
  them and ignores them. *(My call: this includes `crit` — it is ignored, not enforced.)*
- Signing time uses `iat` — **not** JAdES `sigT`.

### 3.3 Signing input

```
SigningInput = ASCII( B64URL(ProtectedHeaderJSON) + "." + B64URL(PayloadBytes) )
```

`B64URL(ProtectedHeaderJSON)` is computed **once** at signing and then carried verbatim;
verify never re-serializes the header.

### 3.4 Algorithms

| `alg` | Key | Algorithm | Signature bytes |
|---|---|---|---|
| `PS256` | RSA, ≥ 2048 bits | RSASSA-PSS, SHA-256, MGF1-SHA-256, salt length 32 | modulus-length bytes |
| `ES256` | EC P-256 | ECDSA with SHA-256 | **64 bytes raw `R‖S`** (not DER) |

The raw `R‖S` encoding for ES256 is a known cross-language trap (several crypto APIs and
most PKCS#11 tokens return or expect different forms; .NET and Node default differently).
Each implementation must convert explicitly and test vectors must cover it.

`alg` must match the key type in `x5c[0]`; a mismatch is rejected.

## 4. File mode

### 4.1 Signed file

UTF-8 JSON (flattened JWS JSON serialization), file extension `.json`:

```json
{
  "protected": "<B64URL(protected header JSON)>",
  "payload":   "<B64URL(payload bytes)>",
  "signature": "<B64URL(signature bytes)>"
}
```

### 4.2 `Sign(payload, signer, alg) → signedFile`

- `payload`: raw bytes (the samples use JSON, but any bytes are allowed — Verify does
  not require the payload to be JSON).
- `signer`: see §6.
- `alg`: enum `PS256 | ES256`.
- Sets `iat` to the current time and `x5c` to `[signer.certificate]`.

### 4.3 `Verify(signedFile, now?) → VerifyResult`

Checks, in order:

1. Input is JSON with string members `protected`, `payload`, `signature`, all valid B64URL.
2. `protected` decodes to a JSON object.
3. `alg`, `iat`, `x5c` are present with the right types; `alg` is `PS256` or `ES256`;
   `x5c` is a non-empty array. *(My call: only `x5c[0]` is used; further entries are
   ignored.)*
4. `x5c[0]` parses as an X.509 certificate; its public key type matches `alg`
   (`PS256` → RSA, `ES256` → EC P-256; any other curve is `ALG_KEY_MISMATCH`).
   *(My call:)* RSA keys under 2048 bits are rejected with `WEAK_KEY`.
5. The signature verifies over the signing input (§3.3) with that public key.
6. Time: `now - 24h ≤ iat ≤ now + 5min`. *(My call: 5 minutes of tolerance for clocks
   that run slightly ahead.)*

`now` is injectable (defaults to the system clock) so test vectors with fixed `iat`
values can be verified.

Not checked: certificate trust, certificate validity dates, revocation. *(My call:
certificate validity dates fall under "trust", so they are out of scope for now.)*

### 4.4 `VerifyResult`

```
{ valid: bool,
  reason: <code or null>,
  header: <decoded protected header>,
  certificate: <parsed x5c[0]>,
  payload: <decoded payload bytes> }
```

Reason codes (same strings in all three languages):

| Code | When |
|---|---|
| `MALFORMED_INPUT` | not JSON / missing parts / bad B64URL / bad header value format |
| `MALFORMED_HEADER` | protected header isn't a JSON object |
| `MISSING_ALG`, `MISSING_IAT`, `MISSING_X5C` | required member absent or wrong type |
| `UNSUPPORTED_ALG` | `alg` not `PS256`/`ES256` |
| `BAD_CERTIFICATE` | `x5c[0]` doesn't parse |
| `ALG_KEY_MISMATCH` | `alg` doesn't match key type / curve |
| `WEAK_KEY` | RSA key under 2048 bits |
| `BAD_SIGNATURE` | signature doesn't verify |
| `EXPIRED` | `iat` older than 24h |
| `NOT_YET_VALID` | `iat` more than 5 min in the future |

## 5. REST mode

### 5.1 Header

```
X-JAdES-Signature: <B64URL(protected header)>..<B64URL(signature)>
```

This is a detached JWS (compact form with the payload part empty). The payload is the
HTTP body.

### 5.2 Byte-exact body — critical

The signature covers the **exact bytes** of the HTTP body as sent on the wire. The
reference code must:

- Sign a byte buffer, and send **that same buffer** as the body (no re-serializing
  objects, no HTTP-library JSON helpers that re-encode).
- On verify, read the **raw** request body bytes before any framework parsing.

The spec must warn consumers about proxies / gateways / libraries that reformat bodies.

### 5.3 `SignRest(body, signer, alg) → headerValue`

Same as file `Sign`, but returns the header value instead of a file.

### 5.4 `Send(url, body, signer, alg, mtls, method="POST", headers?) → response`

Signs the body, sets `X-JAdES-Signature`, and sends over mTLS. This is the "direct"
path: the consumer signs and sends themselves.

### 5.5 `SendFromFile(signedFile, url, mtls, method="POST", headers?) → response`

The relay path:

1. Reads the signed file.
2. Body = `B64URL-decode(payload)` — the exact original bytes.
3. Header = `protected + ".." + signature`, taken verbatim from the file.
4. Sends over mTLS using the **provider's** mTLS certificate.

The provider never needs the original signer's key. *(My call: `SendFromFile` runs
`Verify` locally first and refuses to send an invalid or expired file, with an option to
skip this.)*

The 24-hour window is evaluated **when Customs receives the call**. A provider has 24
hours from signing to deliver; an older file must be re-signed by its original owner.

### 5.6 `VerifyRest(headerValue, rawBodyBytes, now?) → VerifyResult`

1. Header value must be exactly `<part1>..<part2>` (else `MALFORMED_INPUT`).
2. Rebuild `{ protected: part1, payload: B64URL(rawBodyBytes), signature: part2 }`.
3. Run file `Verify` (§4.3). Same logic, same result codes.

### 5.7 Content-Type and methods

*(My calls.)* Samples send `Content-Type: application/json`. Content-Type is not covered
by the signature. Any method with a body is allowed; an empty body signs/verifies as
empty payload.

## 6. Keys

> **Revised.** §6.1–§6.2 below describe the original multi-language design and are kept
> for reference only. The demo page uses §6.3.

### 6.3 Keys in the demo page

- **PFX:** the user picks a `.pfx`/`.p12` file and types its password. The page decrypts
  it in the browser (node-forge, inlined) and signs with WebCrypto. `alg` follows the key:
  RSA → `PS256`, EC P-256 → `ES256`; other keys are refused.
- **Smart card:** a browser cannot reach a smart card's private key. A small local helper
  (`demo/smartcard-helper.ps1`, Windows PowerShell 5.1, no install) listens on
  `http://127.0.0.1:8765` only. It lists the certificates with a private key in the
  Windows `CurrentUser\My` store (where smart-card certificates appear through the card's
  minidriver) and signs the signing input with the chosen one. Windows asks for the PIN;
  the key never leaves the card.
  - At startup the helper prints a random access token. The page must send it in every
    request, so another web page cannot use the helper.
  - The helper signs only the signing input it is given and returns the raw signature
    (PS256: RSASSA-PSS salt 32; ES256: raw `R‖S`). The page builds the file itself.

### 6.1 Signer abstraction

Every sign operation takes a **signer** with two capabilities:

- `certificate` — the leaf certificate (DER) to put in `x5c`.
- `sign(signingInputBytes, alg) → signatureBytes` (in the §3.4 format).

Two implementations per language:

| Signer | Inputs |
|---|---|
| `PfxSigner` | path to `.pfx`/`.p12`, password |
| `Pkcs11Signer` | path to vendor PKCS#11 module, token label or slot, PIN, key label or id |

HSMs and smart cards both go through **PKCS#11**. The private key never leaves the
device. The certificate is read from the token by default.

*(My calls:)*
- `Pkcs11Signer` accepts an optional certificate file (DER/PEM), for HSMs that hold
  only the key pair.
- Keys marked `CKA_ALWAYS_AUTHENTICATE` (common on smart cards) are supported by
  performing the per-signature context-specific login with the same PIN.
- PSS is done on-device with `CKM_SHA256_RSA_PKCS_PSS` (falling back to
  `CKM_RSA_PKCS_PSS` over a host-computed SHA-256 digest); ECDSA uses `CKM_ECDSA` over a
  host-computed digest, and the token's raw `R‖S` output is used as-is.
- CI tests against SoftHSM2 only. Real smart-card / HSM behaviour (including
  always-authenticate) is a documented testing gap until specific devices are named.

*(My call — suggested libraries:* Node `pkcs11js`, Python `python-pkcs11`,
.NET `Pkcs11Interop`. *The builder may substitute equivalents.)*

### 6.2 mTLS client certificate

Separate from the signer. *(My call: supplied as `.pfx`/`.p12` + password only;
HSM-backed mTLS is out of scope for the reference code.)*

## 7. Repository structure

```
demo/jades-demo.html        the demo page: one self-contained file (built)
demo/src/                   page source (HTML/CSS/JS), readable
demo/vendor/                node-forge bundle + licence (inlined by the build)
demo/build.mjs              node demo/build.mjs → demo/jades-demo.html
demo/smartcard-helper.ps1   local smart-card signing helper (§6.3)
test-vectors/certs/         test certificates (.pfx password test1234)
docs/specs/                 this design
```

### 7.1 The page

- **Sign tab.** The payload is the **exact UTF-8 bytes of the text box**. The page checks
  that it is valid JSON but never re-formats it, so what you see is what is signed.
  Output: each intermediate value (§3), the signed file, a download button.
- **Verify tab.** Two inputs: a signed file (load or paste), or a REST header value +
  body. Optional "verify at" time (`now`). Runs the §4.3 checks in order and shows the
  §4.4 result, the protected header as JSON, the payload as JSON (or text if it is not
  JSON), and the certificate subject.
- **curl tab.** Takes the current signed file. The user enters the URL/path and HTTP
  method. The page shows:
  - the body file (`body.json` = decoded payload bytes, downloadable, byte-exact);
  - the header value `protected..signature`;
  - a `curl` command that uses `--data-binary @body.json` (never `-d`, which strips
    newlines), `Content-Type: application/json`, and the `X-JAdES-Signature` header;
    with a bash / PowerShell (`curl.exe`) switch for line continuation;
  - placeholders for the provider's mTLS certificate (`--cert-type P12 --cert …`),
    labelled as the deliverer's certificate, separate from the signing certificate.
- Hebrew UI, right-to-left; code and values left-to-right.

## 8. Testing

- Sign → verify round trip in the page with `rsa2048.pfx` (PS256) and `ec256.pfx`
  (ES256).
- The page's output is cross-checked by an independent verifier (OpenSSL) once per alg.
- Negative checks in the page: tampered payload → `BAD_SIGNATURE`, old `iat` →
  `EXPIRED`, `rsa1024.pfx` refused for signing and → `WEAK_KEY` on verify, header with
  one dot → `MALFORMED_INPUT`, padded B64URL → `MALFORMED_INPUT`.
- The generated `curl` command is run against a local listener to confirm the body and
  header arrive byte-exact.
- The smart-card helper is tested with a software certificate in `CurrentUser\My`
  (imported from a test `.pfx`); real smart-card behaviour is a documented testing gap.

## 9. Left to the builder

- Page layout and styling.
- Helper port (default 8765) and token format.
