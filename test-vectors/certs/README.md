# Test certificates

**Test material only. Never use these keys or this password for anything real.**

All `.pfx` files use the password `test1234`. All certificates are self-signed.

| Name | Key | Purpose |
|---|---|---|
| `rsa2048` | RSA 2048 | PS256 signer (CN=JAdES Test RSA) |
| `ec256` | EC P-256 | ES256 signer (CN=JAdES Test EC) |
| `rsa1024` | RSA 1024 | weak-key vectors |
| `ec384` | EC P-384 | curve-mismatch vectors |
| `mtls-client` | RSA 2048 | mTLS client certificate (CN=Provider) |
| `mock-server` | RSA 2048 | mock-Customs TLS server (CN=localhost, SAN `localhost`, `127.0.0.1`) |

For each name there are three files:

- `<name>.pfx`: certificate and private key (PKCS#12, password `test1234`)
- `<name>.cer`: certificate only, DER
- `<name>.pem`: certificate only, PEM (no private key)

Private keys exist only inside the `.pfx` files.

## Regenerating

```
node test-vectors/certs/gen-certs.mjs
```

Requires `openssl` on PATH (set the `OPENSSL` environment variable to use another binary). The script overwrites every file on each run, so regenerating invalidates any signed vectors made with the old keys.
