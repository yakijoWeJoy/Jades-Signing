import { JadesFormatError } from './errors.js';

export function encode(buf) {
  return Buffer.from(buf).toString('base64url');
}

export function decode(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new JadesFormatError('invalid base64url: padding or non-alphabet character');
  }
  if (s.length % 4 === 1) {
    throw new JadesFormatError('invalid base64url: bad length');
  }
  return Buffer.from(s, 'base64url');
}
