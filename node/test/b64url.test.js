import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encode, decode } from '../src/b64url.js';
import { JadesFormatError } from '../src/errors.js';

test('round-trip including bytes producing - and _', () => {
  const buf = Buffer.from([0xfb, 0xff, 0xfe, 0x00, 0x01]);
  const s = encode(buf);
  assert.equal(s, '-__-AAE');
  assert.deepEqual(decode(s), buf);
  assert.deepEqual(decode(encode(Buffer.alloc(0))), Buffer.alloc(0));
});

test('decode rejects padding', () => {
  assert.throws(() => decode('YQ=='), (e) => e instanceof JadesFormatError && e.code === 'MALFORMED_INPUT');
});

test('decode rejects + and /', () => {
  assert.throws(() => decode('a+b/'), JadesFormatError);
});

test('decode rejects whitespace and invalid length', () => {
  assert.throws(() => decode('YQ Q'), JadesFormatError);
  assert.throws(() => decode('Y'), JadesFormatError);
});
