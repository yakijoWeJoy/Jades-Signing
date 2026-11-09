import crypto from 'node:crypto';

export const ALGS = { PS256: 'PS256', ES256: 'ES256' };

function opts(key, alg) {
  if (alg === ALGS.PS256) {
    return { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 };
  }
  if (alg === ALGS.ES256) {
    return { key, dsaEncoding: 'ieee-p1363' };
  }
  throw new Error(`unsupported alg: ${alg}`);
}

export function rawSign(keyObject, input, alg) {
  return crypto.sign('sha256', input, opts(keyObject, alg));
}

export function rawVerify(publicKey, input, sig, alg) {
  return crypto.verify('sha256', input, opts(publicKey, alg), sig);
}
