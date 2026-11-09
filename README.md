# JAdES Signing Reference

Reference implementations (Node.js, Python, .NET) and a consumer specification for signing payloads as JAdES-style JWS, either as a signed file or in the `X-JAdES-Signature` HTTP header. Every language implements the same operations and verifies the same shared test vectors.

## Layout

```
spec/             consumer-facing spec (Markdown), the source of truth
node/             Node.js 20+ implementation + CLI + tests
python/           Python 3.10+ implementation + CLI + tests
dotnet/           .NET 8 implementation + CLI + tests
test-vectors/     shared certs, signed files, header+body pairs, expected results
mock-customs/     local HTTPS+mTLS endpoint that runs VerifyRest and reports the result
docs/specs/       the design
```

Design: `docs/specs/2026-11-09-jades-signing-design.md`.

Regenerate the test certificates with `node test-vectors/certs/gen-certs.mjs` (requires `openssl` on PATH).
