# JAdES Signing Reference Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reference code (Node.js, Python, .NET) plus a consumer spec showing Customs API consumers how to sign payloads as JAdES-style JWS, as a file or in the `X-JAdES-Signature` HTTP header, with identical verification everywhere.

**Architecture:** One shared contract (format, reason codes, test-vector manifest) implemented three times. Node is built first and also generates the shared negative test vectors. Python and .NET follow the same contract. Every language's test suite verifies every vector, including the positive vectors produced by the other two languages. A Node mock-Customs server runs `verifyRest` behind mTLS for end-to-end demos.

**Tech Stack:**
- Node 20+: plain ESM JavaScript, `node:crypto`, `node:test`, `pkcs11js`, `node:https`
- Python 3.10+: `cryptography`, `requests`, `requests-pkcs12`, `python-pkcs11`, `pytest`
- .NET 8: `System.Security.Cryptography`, `HttpClient`, `Pkcs11Interop`, xUnit
- Test tooling: OpenSSL (certificates), SoftHSM2 and OpenSC `pkcs11-tool` (PKCS#11 tests)

**Spec:** `docs/specs/2026-11-09-jades-signing-design.md`. Read it before starting any task. Section numbers below (§) refer to it.

## Global Constraints

### Encoding
- **B64URL:** RFC 4648 §5, **no padding**.
  - Decoders reject `=`, `+`, `/` and any other non-alphabet character with `MALFORMED_INPUT`.
- **`x5c[0]`:** DER certificate in **standard Base64 with padding**.

### Signing
- **Signing input:** `ASCII(protectedB64 + "." + payloadB64)`.
  - Use the protected B64 string exactly as received. Never re-serialize the header.
- **PS256:**
  - RSASSA-PSS with SHA-256, MGF1-SHA-256, salt length 32.
  - The key must be RSA with a modulus of at least 2048 bits.
- **ES256:**
  - ECDSA on P-256 with SHA-256.
  - Signature is **64 bytes raw `R‖S`**, never DER.
- **Signers** emit only `alg`, `iat` (integer seconds) and `x5c` (one entry).

### Verify
- **Checks:** order and reason codes exactly as §4.3–§4.4.
- **Reason code strings** (identical in every language):
  `MALFORMED_INPUT`, `MALFORMED_HEADER`, `MISSING_ALG`, `MISSING_IAT`, `MISSING_X5C`, `UNSUPPORTED_ALG`, `BAD_CERTIFICATE`, `ALG_KEY_MISMATCH`, `WEAK_KEY`, `BAD_SIGNATURE`, `EXPIRED`, `NOT_YET_VALID`.
- **Member types:**
  - `alg` must be a string. Any other type → `MISSING_ALG`.
  - `iat` must be a JSON integer. A string, a float or null → `MISSING_IAT`.
  - `x5c` must be a non-empty array of strings. Anything else → `MISSING_X5C`.
- **Time:**
  - `EXPIRED` iff `now - iat > 86400`.
  - `NOT_YET_VALID` iff `iat - now > 300`.
  - The boundaries themselves (exactly 86400 and exactly 300) are valid.
- **Ignored:** extra header members, including `crit`, are accepted and not checked. Entries in `x5c` after the first are ignored.
- **Not checked:** certificate trust, validity dates and revocation.

### REST
- **Header name:** `X-JAdES-Signature`, matched case-insensitively.
- **Header value:** `protectedB64 + ".." + signatureB64`.
  - Trim surrounding whitespace before parsing.
  - The value must split into exactly 3 parts on `.`, with the middle part empty. Otherwise → `MALFORMED_INPUT`.
- **Body:** the exact bytes that were signed. Never re-serialize it.
- **Content-Type:** samples send `application/json`.
- **`sendFromFile`:** runs Verify before sending by default and refuses to send an invalid file. An option disables this.

### Signers
- **mTLS client certificate:** `.pfx` plus password only. It is always a separate parameter from the signer.
- **Test PFX password:** `test1234`. This is test material only.

### Repo layout (§7)
`spec/`, `node/`, `python/`, `dotnet/`, `test-vectors/`, `mock-customs/`, `docs/`.

## Shared Test-Vector Contract

Every language's vector test reads **every** `test-vectors/**/manifest.json` file. Each manifest is a JSON array of entries:

```json
{
  "id": "neg-expired",
  "kind": "file",
  "file": "negative/neg-expired.json",
  "header": null,
  "body": null,
  "now": 1787255527,
  "expect": { "valid": false, "reason": "EXPIRED" },
  "producer": "node"
}
```

- **`kind`:** `"file"` or `"rest"`.
- **`file`:** the signed-file path, relative to `test-vectors/`. Used when `kind` is `"file"`.
- **`header` and `body`:** used when `kind` is `"rest"`.
  - `header` is the header value as a string.
  - `body` is a path to a raw body file.
- **`now`:** the verification time in Unix seconds.
- **`producer`:** `node`, `python` or `dotnet`.

A `"file"` vector is verified with `verify(fileText, now)`. A `"rest"` vector is verified with `verifyRest(header, bodyBytes, now)`. The assertion is that `valid` and `reason` equal `expect`.

Vectors are checked in byte-exact. `.gitattributes` marks `test-vectors/** -text` (see Review Focus 1).

## Review Focus

1. **Line-ending conversion.** Git `autocrlf`, which is active on this machine, or an editor turns `\n` into `\r\n` in a body file. Expected behaviour:
   - Signed **files** still verify, because only the string values matter, not whitespace.
   - A REST body with changed bytes fails with `BAD_SIGNATURE`.
   - `.gitattributes` stops this from silently breaking the committed vectors.
   - Pinned by: Task 1 (`.gitattributes`), and by vectors `pos-node-file-reformatted` and `neg-rest-crlf-body` (Task 5).
2. **A body re-serialized by an HTTP library.** For example, a caller passes an object instead of bytes. The `send` functions accept only bytes (`Buffer` / `bytes` / `byte[]`), so the code can never re-encode a body. Pinned by a test in each language's send task that the server receives exactly the bytes that were signed.
3. **Base64 variants from other tooling.** Padded B64URL, or standard Base64 using `+` and `/`, in `protected` or `signature` → `MALFORMED_INPUT`, the same in all three languages. Pinned by vectors `neg-padded-b64url` and `neg-std-b64` (Task 5).
4. **`iat` written as a string or float.** Some JSON tools emit `"1787255527"` or `1.787255527e9`. Both → `MISSING_IAT` everywhere. Pinned by vectors `neg-iat-string` and `neg-iat-float` (Task 5).
5. **The header value pasted with whitespace or a different-case header name.** The value is trimmed and the header name matched case-insensitively. Pinned by vector `pos-node-rest-whitespace` (Task 5) and the mock-Customs test (Task 13).

---

## Phase A — Foundation

### Task 1: Repo scaffold and test certificates

**Files:**
- Create: `.gitignore`, `.gitattributes`, `README.md`
- Create: `test-vectors/certs/gen-certs.sh`, `test-vectors/certs/README.md`
- Create: generated `test-vectors/certs/*.pfx`, `*.cer` (DER) and `*.pem` (committed)

**Interfaces:**
- Produces these certificate files in `test-vectors/certs/`. All are self-signed and use PFX password `test1234`.

| Name | Key | Purpose |
|---|---|---|
| `rsa2048.pfx` / `.cer` | RSA 2048 | PS256 signer |
| `ec256.pfx` / `.cer` | EC P-256 | ES256 signer |
| `rsa1024.pfx` / `.cer` | RSA 1024 | weak-key vectors |
| `ec384.pfx` / `.cer` | EC P-384 | curve-mismatch vectors |
| `mtls-client.pfx` | RSA 2048 | mTLS client certificate (CN=Provider) |
| `mock-server.pfx` | RSA 2048 | mock-Customs TLS server certificate (CN=localhost, SAN `localhost`, `127.0.0.1`) |

- The signer certificates use CN=`JAdES Test RSA`, `JAdES Test EC`, and so on.

- [ ] **Step 1:** Write `.gitattributes` containing `test-vectors/** -text` and `*.pfx binary`. Write `.gitignore` for `node_modules/`, `__pycache__/`, `.venv/`, `bin/`, `obj/`, `.pytest_cache/`.
- [ ] **Step 2:** Write `gen-certs.sh`. It uses `openssl req -x509` and `openssl pkcs12 -export -passout pass:test1234` to produce every file above. It must be idempotent: overwrite on every run.
- [ ] **Step 3:** Run `bash test-vectors/certs/gen-certs.sh`.
  - Expected: all files exist.
  - Check: `openssl pkcs12 -in test-vectors/certs/ec256.pfx -passin pass:test1234 -nokeys | openssl x509 -noout -text` shows `ASN1 OID: prime256v1`.
- [ ] **Step 4:** Write the root `README.md` (one paragraph plus the layout from §7) and `certs/README.md` (states the password and that this is test material only).
- [ ] **Step 5:** Commit: `chore: scaffold repo and test certificates`.

---

## Phase B — Node.js reference (`node/`)

The Node module layout is the template that the Python and .NET tasks mirror.

### Task 2: Node encoding, signer interface and PfxSigner

**Files:**
- Create: `node/package.json` (`"type": "module"`, `"engines": {"node": ">=20"}`, `test` script `node --test`)
- Create: `node/src/b64url.js`, `node/src/signers/pfx.js`, `node/src/algs.js`
- Test: `node/test/b64url.test.js`, `node/test/pfx.test.js`

**Interfaces:**
- **Produces, in `b64url.js`:**
  - `encode(buf: Buffer): string`
  - `decode(s: string): Buffer` — throws `JadesFormatError` on padding or a non-alphabet character
- **Produces, in `algs.js`:**
  - `ALGS = { PS256: 'PS256', ES256: 'ES256' }`
  - `rawSign(keyObject, input: Buffer, alg): Buffer`
  - `rawVerify(publicKey, input, sig, alg): boolean`
  - ES256 uses `dsaEncoding: 'ieee-p1363'`. PS256 uses `padding: RSA_PKCS1_PSS_PADDING, saltLength: 32`.
- **Produces the signer interface** (shared by every signer):
  ```
  { certificate: Buffer /*DER*/, keyType: 'RSA'|'EC', sign(input: Buffer, alg): Promise<Buffer> }
  ```
- **Produces, in `signers/pfx.js`:** `PfxSigner.fromFile(path: string, password: string): PfxSigner`
  - Load the PFX with `crypto.createPrivateKey({key, format:'der', type:'pkcs12'})`. If Node rejects that form, convert with `node-forge`. That fallback is the only allowed extra dependency.

- [ ] **Step 1: Write the failing tests.**
  - `b64url`: round-trip; `decode('YQ==')` throws; `decode('a+b/')` throws.
  - `pfx`: loading `rsa2048.pfx` gives `keyType === 'RSA'` and a `certificate` equal to the bytes of `rsa2048.cer`. A `sign()` → `rawVerify()` round-trip works for PS256 (RSA) and ES256 (EC). The ES256 signature length is exactly 64.
- [ ] **Step 2:** Run `cd node && npm test`. Expected: FAIL (modules missing).
- [ ] **Step 3:** Implement the three modules.
- [ ] **Step 4:** Run `npm test`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(node): base64url, algorithms, PfxSigner`.

### Task 3: Node file mode — `sign` and `verify`

**Files:**
- Create: `node/src/sign.js`, `node/src/verify.js`, `node/src/reasons.js`, `node/src/index.js`
- Test: `node/test/sign-verify.test.js`

**Interfaces:**
- **Consumes:** Task 2.
- **Produces:**
  - `sign(payload: Buffer, signer, alg, opts?: {iat?: number}): Promise<{protected, payload, signature}>`
    - `opts.iat` exists only so test vectors can be generated with fixed times. It is documented as test-only.
  - `signRaw(protectedB64: string, payload: Buffer, signer, alg): Promise<SignedFile>`
    - Internal, exported for the vector generator.
  - `verify(signed: string | object, opts?: {now?: number}): VerifyResult`
  - `VerifyResult = { valid: boolean, reason: string|null, header: object|null, certificate: X509Certificate|null, payload: Buffer|null }`
  - `REASONS`: an object holding the 12 codes.
  - `index.js` re-exports everything public.

- [ ] **Step 1: Write the failing tests.** Fix `now` at `iat` for every test except the time tests.
  - A round-trip passes for PS256/rsa2048 and ES256/ec256 with `{valid: true, reason: null}`, and `payload` equals the input.
  - The decoded header has exactly the keys `alg`, `iat`, `x5c`. `x5c` has length 1 and equals the Base64 of `rsa2048.cer`.
  - A one-byte change in `payload` → `BAD_SIGNATURE`.
  - A header with an extra `foo` member and `crit: ["foo"]`, signed via `signRaw`, is valid.
  - Time cases with `iat = 1_000_000`, as `now` → expected result:
    - `1_086_400` → valid
    - `1_086_401` → `EXPIRED`
    - `999_700` → valid
    - `999_699` → `NOT_YET_VALID`
  - PS256 signed with the EC key via `signRaw` → `ALG_KEY_MISMATCH`.
  - `rsa1024` → `WEAK_KEY`.
  - `ec384` with ES256 → `ALG_KEY_MISMATCH`.
- [ ] **Step 2:** Run `npm test`. Expected: the new tests FAIL.
- [ ] **Step 3:** Implement `sign.js`, `verify.js` and `reasons.js`. Verify follows the §4.3 order and returns the first failing reason. It never throws for bad input.
  - The integer check for `iat` is `Number.isInteger`.
  - Certificates are parsed with `new crypto.X509Certificate(der)`.
- [ ] **Step 4:** Run `npm test`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(node): file-mode sign and verify`.

### Task 4: Node REST mode — `signRest`, `verifyRest`, `send`, `sendFromFile`

**Files:**
- Create: `node/src/rest.js`, `node/src/http.js`
- Test: `node/test/rest.test.js`, `node/test/http.test.js`

**Interfaces:**
- **Consumes:** `sign` and `verify` from Task 3.
- **Produces:**
  - `signRest(body: Buffer, signer, alg): Promise<string>` — returns the header value
  - `verifyRest(headerValue: string, rawBody: Buffer, opts?: {now?}): VerifyResult`
    - Builds `{protected, payload: encode(rawBody), signature}` and calls `verify`.
  - `send({url, body: Buffer, signer, alg, mtls: {pfxPath, password}, method='POST', headers={}}): Promise<{status, headers, body: Buffer}>`
  - `sendFromFile({signedFile: string|object, url, mtls, method='POST', headers={}, verifyFirst=true}): Promise<{status, headers, body: Buffer}>`
    - When `verifyFirst` is set and Verify fails, throws `JadesVerifyError` with `.result`.
  - `HEADER_NAME = 'X-JAdES-Signature'`

- [ ] **Step 1: Write the failing tests.**
  - A `signRest` → `verifyRest` round-trip is valid.
  - The header matches `/^[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+$/`.
  - A header with a single dot → `MALFORMED_INPUT`.
  - A header with leading and trailing spaces is valid.
  - A body with `\n` appended → `BAD_SIGNATURE`.
  - Equivalence: for a file from `sign(payload)`, `verifyRest(file.protected + '..' + file.signature, payload)` is valid.
  - `http.test.js`:
    - Starts a local `https` server with `mock-server.pfx` and `requestCert: true`.
    - `sendFromFile` delivers a body byte-equal to the decoded `payload`.
    - The received header value equals `protected..signature`.
    - The server sees the client certificate with CN=Provider.
    - `send` delivers a body byte-equal to the input buffer.
    - `sendFromFile` with an expired file (`iat` 2 days old) throws `JadesVerifyError`, and the server receives nothing.
- [ ] **Step 2:** Run `npm test`. Expected: FAIL.
- [ ] **Step 3:** Implement with `node:https` `request()`:
  - `pfx` and `passphrase` come from `mtls`.
  - `ca` is the mock-server certificate in tests.
  - `Content-Type: application/json` unless overridden.
  - Write the `Buffer` body directly.
- [ ] **Step 4:** Run `npm test`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(node): REST mode and mTLS send`.

### Task 5: Shared vector generator and Node vector test

**Files:**
- Create: `node/tools/make-vectors.js`
- Create (generated, committed): `test-vectors/negative/*`, `test-vectors/negative/manifest.json`, `test-vectors/generated/node/*`, `test-vectors/generated/node/manifest.json`
- Create: `test-vectors/README.md`
- Test: `node/test/vectors.test.js`

**Interfaces:**
- **Consumes:** `sign`, `signRaw`, `signRest` and the signers.
- **Produces:** manifests in the Shared Test-Vector Contract format.
  - The `now` base is `1787255527`. Positive vectors use `iat = now`.
  - Other languages reproduce only the "positive" set, under `generated/<lang>/`. They use the same ids with `node` replaced by the language name.

**Positive vectors (`generated/node/`), all `expect valid`:**
- `pos-node-file-ps256`, `pos-node-file-es256`
- `pos-node-rest-ps256`, `pos-node-rest-es256`
- `pos-node-file-extra-members`: extra header members including `crit`
- `pos-node-file-reformatted`: a signed file pretty-printed with CRLF line endings
- `pos-node-rest-whitespace`: the header value wrapped in spaces
- `pos-node-time-boundary-expired`: `now = iat + 86400`
- `pos-node-time-boundary-future`: `iat = now + 300`

**Negative vectors (`negative/`)**, as `id` → `reason`:

| Vector id | Expected reason |
|---|---|
| `neg-not-json` | `MALFORMED_INPUT` |
| `neg-missing-signature` | `MALFORMED_INPUT` |
| `neg-padded-b64url` | `MALFORMED_INPUT` |
| `neg-std-b64` | `MALFORMED_INPUT` |
| `neg-rest-single-dot` | `MALFORMED_INPUT` |
| `neg-header-array` | `MALFORMED_HEADER` |
| `neg-missing-alg` | `MISSING_ALG` |
| `neg-missing-iat` | `MISSING_IAT` |
| `neg-iat-string` | `MISSING_IAT` |
| `neg-iat-float` | `MISSING_IAT` |
| `neg-missing-x5c` | `MISSING_X5C` |
| `neg-x5c-empty` | `MISSING_X5C` |
| `neg-alg-rs256` | `UNSUPPORTED_ALG` |
| `neg-bad-cert` | `BAD_CERTIFICATE` |
| `neg-ps256-ec-key` | `ALG_KEY_MISMATCH` |
| `neg-es256-p384` | `ALG_KEY_MISMATCH` |
| `neg-rsa1024` | `WEAK_KEY` |
| `neg-tampered-payload` | `BAD_SIGNATURE` |
| `neg-tampered-header` | `BAD_SIGNATURE` |
| `neg-es256-der-sig` | `BAD_SIGNATURE` |
| `neg-rest-crlf-body` | `BAD_SIGNATURE` |
| `neg-expired` | `EXPIRED` |
| `neg-future` | `NOT_YET_VALID` |

Vector notes:
- `neg-header-array`: `protected` = B64URL of `[1]`.
- `neg-iat-float`: `iat` = `1787255527.5`.
- `neg-tampered-header`: `iat` is changed after signing.
- `neg-es256-der-sig`: the valid signature converted to DER.
- `neg-expired`: `now = iat + 86401`.
- `neg-future`: `iat = now + 301`.

- [ ] **Step 1:** Write `vectors.test.js`. It globs every `test-vectors/**/manifest.json` and runs each entry per the contract. Run it: FAIL (no manifests).
- [ ] **Step 2:** Implement `make-vectors.js`.
  - CLI: `node tools/make-vectors.js --out ../test-vectors [--negative]`.
  - It writes body files as raw bytes and the CRLF variant with explicit `\r\n`.
- [ ] **Step 3:** Run `node tools/make-vectors.js --out ../test-vectors --negative`, then `npm test`.
  - Expected: PASS, and every vector id listed above is present.
- [ ] **Step 4:** Run `git add test-vectors && git diff --cached --stat`. Confirm that git reports no line-ending warning for `test-vectors/`.
- [ ] **Step 5:** Write `test-vectors/README.md`:
  - the manifest format
  - how each language regenerates its positives
  - the section "Running these against the real Customs verifier" (filled in by Task 15)
- [ ] **Step 6:** Commit: `test: shared cross-language test vectors`.

### Task 6: Node PKCS#11 signer

**Files:**
- Create: `node/src/signers/pkcs11.js`
- Create: `test-vectors/softhsm/setup.sh`, `test-vectors/softhsm/README.md`
- Test: `node/test/pkcs11.test.js`

**Interfaces:**
- **Produces:** `Pkcs11Signer.open({modulePath, tokenLabel?, slot?, pin, keyLabel?, keyId?, certificatePath?}): Pkcs11Signer`
  - It implements the signer interface and adds `close()`.
- **Mechanisms, PS256:** `CKM_SHA256_RSA_PKCS_PSS` with params `{hashAlg: CKM_SHA256, mgf: CKG_MGF1_SHA256, sLen: 32}`. Fall back to `CKM_RSA_PKCS_PSS` over a host SHA-256 digest when the token lacks the first.
- **Mechanisms, ES256:** `CKM_ECDSA` over a host SHA-256 digest. The output is already `R‖S`.
- **Certificate:** read from the `CKO_CERTIFICATE` object with the same `CKA_ID` as the key, unless `certificatePath` (DER or PEM) is given.
- **`CKA_ALWAYS_AUTHENTICATE`:** if it is true, call `C_Login(CKU_CONTEXT_SPECIFIC, pin)` after each `C_SignInit`.
- **Errors:** missing token or key → `JadesSignerError`, with a message naming the label it looked for.
- **Test token** (`softhsm/setup.sh`): label `jades-test`, user PIN `1234`, SO PIN `5678`. It imports `rsa2048` with label `rsa` and `ec256` with label `ec`, each with its certificate, using `pkcs11-tool`.

- [ ] **Step 1: Write the failing tests.** They are skipped unless `SOFTHSM2_MODULE` is set.
  - Signing with `keyLabel: 'rsa'` (PS256) and `'ec'` (ES256) gives files that `verify` reports as valid.
  - The `certificate` equals `rsa2048.cer`.
  - The `certificatePath` override is used when given.
  - A wrong `keyLabel` throws `JadesSignerError`.
- [ ] **Step 2:** Run `bash test-vectors/softhsm/setup.sh`, then run `SOFTHSM2_MODULE=<path> npm test`. Expected: FAIL.
- [ ] **Step 3:** Implement `pkcs11.js` with `pkcs11js`.
- [ ] **Step 4:** Run the tests. Expected: PASS. Without `SOFTHSM2_MODULE`, the tests are reported as skipped, not failed.
- [ ] **Step 5:** Write `softhsm/README.md`. It covers installing SoftHSM2 and OpenSC on Windows and Linux, and states the testing gap: always-authenticate has not been tested on real smart cards.
- [ ] **Step 6:** Commit: `feat(node): PKCS#11 signer`.

### Task 7: Node CLI

**Files:**
- Create: `node/bin/jades.js` (`"bin": {"jades": "bin/jades.js"}`)
- Test: `node/test/cli.test.js`

**Interfaces:**
- **CLI contract, shared with Python and .NET:**
  ```
  jades sign-file   --in <payload> --out <signed.json> --alg PS256|ES256 <signer opts>
  jades verify-file --in <signed.json> [--now <unix>]
  jades send        --url <u> --in <body> --alg ... <signer opts> <mtls opts> [--method POST]
  jades send-file   --url <u> --in <signed.json> <mtls opts> [--method POST] [--no-verify]
  jades verify-rest --header <value> --body <file> [--now <unix>]
  ```
- **Signer options:** either `--pfx <path> --password <pw>` or `--pkcs11-module <path> --token <label> --pin <pin> --key-label <label> [--cert <path>]`.
- **mTLS options:** `--mtls-pfx <path> --mtls-password <pw>` and an optional `--ca <path>`.
- **Output:**
  - `verify-*` prints JSON: `{valid, reason, alg, iat, subject}`, where `subject` is the certificate subject.
  - `send*` prints `{status, body}` (the body as UTF-8).
- **Exit codes:** `0` = valid or HTTP 2xx, `1` = invalid or non-2xx, `2` = usage error.

- [ ] **Step 1:** Write failing tests that spawn the CLI:
  - `sign-file` then `verify-file` gives exit code 0 and `valid: true`.
  - `verify-file` on `neg-expired.json` with its `now` gives exit code 1 and `reason` `EXPIRED`.
  - A missing `--alg` gives exit code 2.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement with `node:util` `parseArgs`.
- [ ] **Step 4:** Run. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(node): CLI`.

---

## Phase C — Python reference (`python/`)

Mirror the Node tasks. The package is `jades_sign`, and names are snake_case versions of the Node names.

### Task 8: Python core — encoding, PfxSigner, sign, verify

**Files:**
- Create: `python/pyproject.toml`
  - `requires-python >=3.10`
  - dependencies: `cryptography`, `requests`, `requests-pkcs12`
  - optional `pkcs11` = `python-pkcs11`
  - dev: `pytest`
- Create: `python/jades_sign/{__init__,b64url,algs,reasons,sign,verify}.py`, `python/jades_sign/signers/{__init__,pfx}.py`
- Test: `python/tests/test_b64url.py`, `test_pfx.py`, `test_sign_verify.py`, `test_vectors.py`

**Interfaces:**
- `class Alg(str, Enum): PS256 = "PS256"; ES256 = "ES256"`
- `PfxSigner.from_file(path: str, password: str)` provides `.certificate: bytes`, `.key_type: Literal["RSA","EC"]` and `.sign(data: bytes, alg: Alg) -> bytes`.
- `sign(payload: bytes, signer, alg: Alg, *, iat: int | None = None) -> dict`
- `sign_raw(protected_b64: str, payload: bytes, signer, alg) -> dict`
- `verify(signed: str | bytes | dict, *, now: int | None = None) -> VerifyResult`
  - `VerifyResult` is a frozen dataclass: `valid`, `reason`, `header`, `certificate: x509.Certificate | None`, `payload`.
- **ES256:** `cryptography` returns DER. Convert with `decode_dss_signature` into 32-byte big-endian `r‖s`, and back with `encode_dss_signature` on verify. A wrong-length signature is `BAD_SIGNATURE`, not an exception.
- **PS256:** `padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)`.
- **`iat` integer check:** `type(v) is int`. This excludes `bool`. It is safe for `1787255527.5` because `json.loads` returns a float for it.
- **JSON parsing:** use the standard library. Duplicate keys use the last value, the same as Node and .NET defaults. Note this as a point to confirm with the real verifier (Task 15).

- [ ] **Step 1:** Port the Node test cases from Tasks 2–3 as pytest tests, using the same values.
- [ ] **Step 2:** Port the vector runner from Task 5 as `test_vectors.py`, using `pathlib.Path.glob('**/manifest.json')` from the repo's `test-vectors/`.
- [ ] **Step 3:** Run `cd python && pytest`. Expected: FAIL.
- [ ] **Step 4:** Implement the modules.
- [ ] **Step 5:** Run `pytest`. Expected: PASS for unit tests and all `negative/` and `generated/node/` file-kind vectors. REST vectors fail until Task 9; mark them `xfail` with reason "Task 9" and remove the mark in Task 9.
- [ ] **Step 6:** Commit: `feat(python): file-mode sign and verify`.

### Task 9: Python REST mode, send, PKCS#11, CLI, vectors

**Files:**
- Create: `python/jades_sign/{rest,http,cli}.py`, `python/jades_sign/signers/pkcs11.py`, `python/tools/make_vectors.py`
- Create (generated, committed): `test-vectors/generated/python/*`
- Test: `python/tests/test_rest.py`, `test_http.py`, `test_pkcs11.py`, `test_cli.py`

**Interfaces:**
- `sign_rest(body: bytes, signer, alg) -> str`
- `verify_rest(header_value: str, raw_body: bytes, *, now=None) -> VerifyResult`
- `send(url, body: bytes, signer, alg, mtls: tuple[str, str], method="POST", headers=None, ca=None) -> requests.Response`
  - `mtls` is `(pfx_path, password)`, sent through `requests_pkcs12.post` / `request` with `pkcs12_filename` and `pkcs12_password`.
  - `body` is passed as `data=`. A `TypeError` is raised if `body` isn't `bytes`.
- `send_from_file(signed_file, url, mtls, method="POST", headers=None, verify_first=True, ca=None)`
  - Raises `JadesVerifyError(result)` when verification fails.
- `Pkcs11Signer.open(module_path, *, token_label=None, slot=None, pin, key_label=None, key_id=None, certificate_path=None)`
  - Same mechanisms and always-authenticate behaviour as Task 6.
- **CLI:** `python -m jades_sign <same subcommands, options and exit codes as Task 7>`.
- **`make_vectors.py`:** emits the positive set as `pos-python-*` into `generated/python/`.

- [ ] **Step 1:** Port the test cases from Tasks 4, 6 and 7. The HTTP test uses a stdlib `http.server` + `ssl` server with `mock-server.pfx` converted to PEM in a temp dir and `CERT_OPTIONAL`, and asserts byte-equal bodies and the CN=Provider client certificate. The PKCS#11 tests are skipped without `SOFTHSM2_MODULE`.
- [ ] **Step 2:** Run `pytest`. Expected: FAIL.
- [ ] **Step 3:** Implement the modules and remove the `xfail` marks from Task 8.
- [ ] **Step 4:** Run `python tools/make_vectors.py --out ../test-vectors`, then `pytest`. Expected: PASS for every vector from every producer.
- [ ] **Step 5:** Run `cd node && npm test`. Expected: PASS, so Node verifies `generated/python/` too.
- [ ] **Step 6:** Commit: `feat(python): REST mode, PKCS#11, CLI, vectors`.

---

## Phase D — .NET reference (`dotnet/`)

### Task 10: .NET core — encoding, PfxSigner, sign, verify

**Files:**
- Create: `dotnet/Jades.sln`, `dotnet/src/Customs.Jades/Customs.Jades.csproj` (net8.0, nullable enabled)
- Create: `dotnet/src/Customs.Jades/{B64Url,JadesAlg,Reasons,SignedFile,VerifyResult,Jades}.cs`, `Signers/{ISigner,PfxSigner}.cs`
- Create: `dotnet/tests/Customs.Jades.Tests/` (xUnit) with `B64UrlTests.cs`, `PfxSignerTests.cs`, `SignVerifyTests.cs`, `VectorTests.cs`

**Interfaces:**
- `enum JadesAlg { PS256, ES256 }`
- `interface ISigner { byte[] Certificate { get; } KeyType KeyType { get; } byte[] Sign(byte[] input, JadesAlg alg); }` with `enum KeyType { RSA, EC }`
- `PfxSigner.FromFile(string path, string password)` loads with `X509KeyStorageFlags.EphemeralKeySet`.
- `record SignedFile(string Protected, string Payload, string Signature)` serializes to lowercase JSON names `protected`, `payload`, `signature`.
- `record VerifyResult(bool Valid, string? Reason, JsonObject? Header, X509Certificate2? Certificate, byte[]? Payload)`
- `static class Jades`:
  - `Sign(byte[] payload, ISigner signer, JadesAlg alg, long? iat = null) -> SignedFile`
  - `SignRaw(...)`
  - `Verify(string signedFileJson, long? now = null) -> VerifyResult`
- **ES256:** `ECDsa.SignData` / `VerifyData` with `DSASignatureFormat.IeeeP1363FixedFieldConcatenation`. Pass it explicitly.
- **PS256:** `RSASignaturePadding.Pss`. .NET fixes the salt at the hash length, 32. Assert this in a test by verifying a Node-produced vector.
- **`iat` integer check:** the `JsonValue` must be a number with no fraction or exponent. Use `TryGetValue<long>` on the element, and reject `JsonValueKind.Number` values whose raw text contains `.` or `e`.

- [ ] **Step 1:** Port the test cases from Tasks 2–3. Port the vector runner from Task 5, with the repo root found by walking up to the folder containing `test-vectors/`.
- [ ] **Step 2:** Run `dotnet test dotnet/Jades.sln`. Expected: FAIL.
- [ ] **Step 3:** Implement the classes.
- [ ] **Step 4:** Run `dotnet test`. Expected: PASS for unit tests and file-kind vectors. REST vectors are skipped with reason "Task 11".
- [ ] **Step 5:** Commit: `feat(dotnet): file-mode sign and verify`.

### Task 11: .NET REST mode, send, PKCS#11, CLI, vectors

**Files:**
- Create: `dotnet/src/Customs.Jades/{JadesRest,JadesHttp}.cs`, `Signers/Pkcs11Signer.cs`
- Create: `dotnet/src/Customs.Jades.Cli/` (console app, assembly name `jades`)
- Create: `dotnet/tools/MakeVectors/`, or a `make-vectors` subcommand in the CLI (builder's choice)
- Create (generated, committed): `test-vectors/generated/dotnet/*`
- Test: `RestTests.cs`, `HttpTests.cs`, `Pkcs11Tests.cs`, `CliTests.cs`

**Interfaces:**
- `JadesRest.SignRest(byte[] body, ISigner signer, JadesAlg alg) -> string`
- `JadesRest.VerifyRest(string headerValue, byte[] rawBody, long? now = null) -> VerifyResult`
- `JadesHttp.SendAsync(Uri url, byte[] body, ISigner signer, JadesAlg alg, X509Certificate2 mtlsCert, HttpMethod? method = null, IDictionary<string,string>? headers = null, X509Certificate2? ca = null) -> Task<HttpResponseMessage>`
  - Use `ByteArrayContent` and `TryAddWithoutValidation` for the signature header.
- `JadesHttp.SendFromFileAsync(string signedFileJson, Uri url, X509Certificate2 mtlsCert, HttpMethod? method = null, IDictionary<string,string>? headers = null, bool verifyFirst = true, X509Certificate2? ca = null)`
  - Throws `JadesVerifyException` with `.Result`.
- `Pkcs11Signer.Open(string modulePath, string pin, string? tokenLabel = null, ulong? slot = null, string? keyLabel = null, byte[]? keyId = null, string? certificatePath = null) : ISigner, IDisposable`
  - Uses `Pkcs11Interop`, with the same mechanisms and always-authenticate behaviour as Task 6.
- **CLI:** same subcommands, options and exit codes as Task 7. Emits `pos-dotnet-*` vectors.

- [ ] **Step 1:** Port the test cases from Tasks 4, 6 and 7. The HTTP test uses an in-process Kestrel server with `ClientCertificateMode.AllowCertificate`. It asserts byte-equal bodies and the client certificate CN. The PKCS#11 tests are skipped without `SOFTHSM2_MODULE`.
- [ ] **Step 2:** Run `dotnet test`. Expected: FAIL.
- [ ] **Step 3:** Implement and un-skip the REST vectors.
- [ ] **Step 4:** Generate the `generated/dotnet/` vectors, then run all three suites: `cd node && npm test`, `cd python && pytest`, `dotnet test dotnet/Jades.sln`. Expected: all PASS, with every language verifying every producer.
- [ ] **Step 5:** Commit: `feat(dotnet): REST mode, PKCS#11, CLI, vectors`.

---

## Phase E — Cross-language gate, mock Customs, consumer spec

### Task 12: One command that runs everything

**Files:**
- Create: `scripts/test-all.sh`

- [ ] **Step 1:** Write the script. It regenerates the positives for all three languages into `generated/`, runs all three test suites, and exits non-zero on any failure. It prints a matrix of producer × verifier with pass counts.
- [ ] **Step 2:** Add a CLI round-trip section to the script. It runs `sign-file` with each language's CLI and `verify-file` with the other two. That is 6 pairs × 2 algorithms. Use `rsa2048.pfx` and `ec256.pfx`.
- [ ] **Step 3:** Run `bash scripts/test-all.sh`. Expected:
  - every cell in the 3×3 matrix passes
  - the negative vectors pass in all three columns
  - the CLI round-trip is 12/12 valid, all exit codes 0
- [ ] **Step 4:** Commit: `chore: cross-language test runner`.

### Task 13: Mock Customs server

**Files:**
- Create: `mock-customs/package.json`, `mock-customs/server.js`, `mock-customs/README.md`
- Test: `mock-customs/test/server.test.js`

**Interfaces:**
- **Consumes:** `verifyRest` and `HEADER_NAME` from `../node/src/index.js`.
- **Server:**
  - `node server.js [--port 8443]` starts an HTTPS server with `mock-server.pfx`, `requestCert: true` and `rejectUnauthorized: false`. Trust is out of scope, but a missing client certificate gets `403 {"error":"mTLS client certificate required"}`.
  - Any path, any method with a body. It reads the raw body bytes and runs `verifyRest`.
  - Valid → `200 {"valid": true, "signer": <signing cert subject>, "deliveredBy": <mTLS cert subject>, "alg", "iat"}`
  - Invalid → `401 {"valid": false, "reason": <code>}`. **Placeholder**: align with the real Customs API once its response is known.
  - It logs one line per request with the signer subject and the mTLS subject, labelled as separate identities.
  - A missing header → `401 {"valid": false, "reason": "MALFORMED_INPUT"}`.

- [ ] **Step 1: Write the failing tests.**
  - A relay scenario: sign with `ec256.pfx`, then `sendFromFile` with `mtls-client.pfx`. The response is 200, `signer` contains `JAdES Test EC`, and `deliveredBy` contains `Provider`.
  - The header name sent as `x-jades-signature` in lowercase is accepted.
  - A tampered body → 401 `BAD_SIGNATURE`.
  - No client certificate → 403.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement `server.js`.
- [ ] **Step 4:** Run. Expected: PASS. Manual check: start the server, then send `python -m jades_sign send-file ... --ca test-vectors/certs/mock-server.pem`. Expected: 200.
- [ ] **Step 5:** Write `README.md` with a three-language walkthrough of the direct path and the relay path against the mock.
- [ ] **Step 6:** Commit: `feat: mock Customs endpoint`.

### Task 14: Consumer spec

**Files:**
- Create: `spec/README.md` (the consumer-facing specification), `spec/sequence-relay.md` (Mermaid sequence diagrams)

- [ ] **Step 1:** Write `spec/README.md` covering every item in design §9, in this order:
  1. Purpose: author vs. deliverer, and the two certificates.
  2. Format, with a fully worked example. Take the real values from `test-vectors/generated/node/pos-node-file-es256.json` and show:
     - the header JSON
     - the B64URL
     - the signing input
     - the signature
     - the file
     - the header value
  3. File mode.
  4. REST mode.
  5. The relay flow.
  6. Verification rules and reason codes, in a table copied from §4.4 with `WEAK_KEY` included.
  7. The 24-hour window and 5-minute tolerance.
  8. The byte-exact body rule. It lists the specific breakers: JSON re-serialization, CRLF conversion, BOM, proxies that re-encode, and HTTP-client JSON helpers.
  9. Keys: PFX and PKCS#11, and the ES256 `R‖S` pitfall.
  10. Not covered: trust, replay, certificate validity.
  11. Error responses: marked placeholder.
  12. Links to the reference code and the mock.
- [ ] **Step 2:** Write the relay and direct sequence diagrams.
- [ ] **Step 3:** Check every value in the worked example against the vector file. Do it by running `verify-file` on the file the example is taken from. Expected: valid.
- [ ] **Step 4:** Commit: `docs: consumer specification`.

### Task 15: Real Customs verifier hand-off

The real Customs verifier is the authority (design §1). This task produces what the Customs team needs to run the vectors against it. It does not run them; that needs access we don't have.

**Files:**
- Modify: `test-vectors/README.md` (section "Running these against the real Customs verifier")
- Create: `test-vectors/customs-check.md`

- [ ] **Step 1:** Write `customs-check.md`: a checklist table with one row per vector id, columns for the expected result and the "Customs verifier result", and blank cells. Add open questions for the Customs team:
  - **Duplicate-key JSON handling:** all three reference implementations use the last occurrence.
  - **Strict B64URL:** padding is rejected.
  - **Error response format:** status, body, and whether reason codes are exposed.
  - **Whether certificate validity dates are checked.**
- [ ] **Step 2:** Add a `scripts/export-vectors.sh` that zips `test-vectors/` without the private keys. That excludes `*.pfx` and `*.pem` private keys; the `.cer` files are kept.
- [ ] **Step 3:** Run it. Expected: the zip is created, and `unzip -l` shows no `.pfx`.
- [ ] **Step 4:** Commit: `docs: hand-off for real Customs verifier check`.
