# JAdES Signing Demo

One self-contained HTML page that shows developers how to sign a payload as a JAdES-style JWS
and send it to the Customs API, as a signed file or in the `X-JAdES-Signature` HTTP header.

Open `demo/jades-demo.html` in a browser. No server and no internet are needed.

1. **Sign:** type or paste JSON, load a `.pfx` and its password (or use a smart card, see below),
   and create the signed file. Every step is shown: protected header, B64URL, signing input,
   signature and file.
2. **Verify:** load a signed file, or paste a header value and body, and see whether it is valid,
   with the reason code, the protected header and the body as JSON.
3. **Send as REST:** enter the method and path to get a ready `curl` command (bash or PowerShell)
   with the correct `X-JAdES-Signature` header and the exact body bytes in `body.json`.

## Smart card

A browser cannot reach a smart card, so a small local helper signs for the page:

```
powershell -ExecutionPolicy Bypass -File demo\smartcard-helper.ps1
```

The helper listens on `http://127.0.0.1:8765` only and prints an access token. Paste the token into
the page. The page lists the certificates in your Windows store that have a private key; smart-card
certificates appear there through the card driver. Windows asks for the PIN when you sign.

## Layout

```
demo/jades-demo.html        the page (built, self-contained)
demo/src/                   page source: index.html, style.css, jades.js (format logic), app.js (UI)
demo/vendor/                node-forge 1.4.3 (BSD-3-Clause), inlined by the build
demo/build.mjs              node demo/build.mjs → demo/jades-demo.html
demo/smartcard-helper.ps1   local smart-card signing helper (Windows PowerShell 5.1)
test-vectors/certs/         test certificates, PFX password test1234 (test material only)
docs/specs/                 the design (format rules: §3–§5)
```

After editing anything in `demo/src/`, run `node demo/build.mjs`. While developing you can also
open `demo/src/index.html` directly.

Regenerate the test certificates with `node test-vectors/certs/gen-certs.mjs` (requires `openssl` on PATH).
