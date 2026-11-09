import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PfxSigner } from '../src/signers/pfx.js';
import { rawVerify, ALGS } from '../src/algs.js';
import crypto from 'node:crypto';

const certs = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'test-vectors', 'certs');
const pw = 'test1234';
const input = Buffer.from('header.payload');
const pub = (der) => new crypto.X509Certificate(der).publicKey;

test('RSA PFX loads; certificate equals .cer bytes', () => {
  const s = PfxSigner.fromFile(path.join(certs, 'rsa2048.pfx'), pw);
  assert.equal(s.keyType, 'RSA');
  assert.deepEqual(s.certificate, fs.readFileSync(path.join(certs, 'rsa2048.cer')));
});

test('EC PFX loads', () => {
  const s = PfxSigner.fromFile(path.join(certs, 'ec256.pfx'), pw);
  assert.equal(s.keyType, 'EC');
  assert.deepEqual(s.certificate, fs.readFileSync(path.join(certs, 'ec256.cer')));
});

test('PS256 sign/verify round-trip', async () => {
  const s = PfxSigner.fromFile(path.join(certs, 'rsa2048.pfx'), pw);
  const sig = await s.sign(input, ALGS.PS256);
  assert.equal(sig.length, 256);
  assert.equal(rawVerify(pub(s.certificate), input, sig, ALGS.PS256), true);
  assert.equal(rawVerify(pub(s.certificate), Buffer.from('x'), sig, ALGS.PS256), false);
});

test('ES256 sign/verify round-trip, 64-byte raw signature', async () => {
  const s = PfxSigner.fromFile(path.join(certs, 'ec256.pfx'), pw);
  const sig = await s.sign(input, ALGS.ES256);
  assert.equal(sig.length, 64);
  assert.equal(rawVerify(pub(s.certificate), input, sig, ALGS.ES256), true);
  assert.equal(rawVerify(pub(s.certificate), Buffer.from('x'), sig, ALGS.ES256), false);
});

test('ec384 and rsa1024 also load', () => {
  assert.equal(PfxSigner.fromFile(path.join(certs, 'ec384.pfx'), pw).keyType, 'EC');
  assert.equal(PfxSigner.fromFile(path.join(certs, 'rsa1024.pfx'), pw).keyType, 'RSA');
});

test('wrong password throws a clear error', () => {
  assert.throws(() => PfxSigner.fromFile(path.join(certs, 'rsa2048.pfx'), 'nope'), /password|PFX/i);
});
