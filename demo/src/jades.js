// JAdES-style JWS core for the demo page: encoding, certificate parsing, sign, verify.
// Format and verification rules: docs/specs/2026-11-09-jades-signing-design.md §3–§5.
// Needs `forge` (node-forge) for ASN.1 / PKCS#12 and WebCrypto for the signatures.
'use strict';

const Jades = (() => {
  const REASONS = Object.freeze({
    MALFORMED_INPUT: 'MALFORMED_INPUT',
    MALFORMED_HEADER: 'MALFORMED_HEADER',
    MISSING_ALG: 'MISSING_ALG',
    MISSING_IAT: 'MISSING_IAT',
    MISSING_X5C: 'MISSING_X5C',
    UNSUPPORTED_ALG: 'UNSUPPORTED_ALG',
    BAD_CERTIFICATE: 'BAD_CERTIFICATE',
    ALG_KEY_MISMATCH: 'ALG_KEY_MISMATCH',
    WEAK_KEY: 'WEAK_KEY',
    BAD_SIGNATURE: 'BAD_SIGNATURE',
    EXPIRED: 'EXPIRED',
    NOT_YET_VALID: 'NOT_YET_VALID',
  });

  const HEADER_NAME = 'X-JAdES-Signature';
  const MAX_AGE = 86400;      // 24 hours
  const MAX_FUTURE = 300;     // 5 minutes clock tolerance
  const MIN_RSA_BITS = 2048;

  const OID = {
    rsaEncryption: '1.2.840.113549.1.1.1',
    ecPublicKey: '1.2.840.10045.2.1',
    p256: '1.2.840.10045.3.1.7',
  };

  class FormatError extends Error {}

  // ---------- bytes and encodings ----------

  const utf8 = (s) => new TextEncoder().encode(s);
  const fromUtf8 = (bytes, fatal = false) => new TextDecoder('utf-8', { fatal }).decode(bytes);
  const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));

  const toBinary = (bytes) => {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return s;
  };
  const fromBinary = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));

  // Base64URL, RFC 4648 §5, no padding.
  function b64urlEncode(bytes) {
    return btoa(toBinary(bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // Strict: rejects padding, '+', '/', any non-alphabet char and non-canonical trailing bits.
  function b64urlDecode(s) {
    if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
      throw new FormatError('not valid Base64URL (no padding, alphabet A-Z a-z 0-9 - _)');
    }
    const std = s.replace(/-/g, '+').replace(/_/g, '/');
    const bytes = fromBinary(atob(std + '='.repeat((4 - (std.length % 4)) % 4)));
    if (b64urlEncode(bytes) !== s) throw new FormatError('non-canonical Base64URL');
    return bytes;
  }

  // Standard Base64 with padding (used by x5c).
  const b64Encode = (bytes) => btoa(toBinary(bytes));
  function b64Decode(s) {
    if (typeof s !== 'string' || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
      throw new FormatError('not valid standard Base64');
    }
    return fromBinary(atob(s));
  }

  // ---------- X.509 (minimal, via forge.asn1 so EC certificates work too) ----------

  const NAME_OIDS = {
    '2.5.4.3': 'CN', '2.5.4.4': 'SN', '2.5.4.42': 'GN', '2.5.4.5': 'SERIALNUMBER',
    '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU',
    '2.5.4.12': 'T', '1.2.840.113549.1.9.1': 'E',
  };

  function asn1String(node) {
    const raw = node.value;
    if (typeof raw !== 'string') return '?';
    if (node.type === forge.asn1.Type.UTF8) return forge.util.decodeUtf8(raw);
    if (node.type === forge.asn1.Type.BMPSTRING) {
      let s = '';
      for (let i = 0; i + 1 < raw.length; i += 2) s += String.fromCharCode((raw.charCodeAt(i) << 8) | raw.charCodeAt(i + 1));
      return s;
    }
    return raw;
  }

  function nameToString(nameNode) {
    const parts = [];
    for (const rdn of nameNode.value) {
      for (const atv of rdn.value) {
        const oid = forge.asn1.derToOid(atv.value[0].value);
        parts.push(`${NAME_OIDS[oid] || oid}=${asn1String(atv.value[1])}`);
      }
    }
    return parts.join(', ');
  }

  function asn1Time(node) {
    try {
      return node.type === forge.asn1.Type.UTCTIME
        ? forge.asn1.utcTimeToDate(node.value)
        : forge.asn1.generalizedTimeToDate(node.value);
    } catch { return null; }
  }

  // Parses a DER certificate. Throws on anything that is not a well-formed certificate.
  function parseCertificate(der) {
    const cert = forge.asn1.fromDer(forge.util.createBuffer(toBinary(der)));
    const tbs = cert.value[0];
    const off = tbs.value[0].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC ? 1 : 0;
    const issuer = tbs.value[off + 2];
    const validity = tbs.value[off + 3];
    const subject = tbs.value[off + 4];
    const spki = tbs.value[off + 5];
    const algOid = forge.asn1.derToOid(spki.value[0].value[0].value);

    const info = {
      der,
      subject: nameToString(subject),
      issuer: nameToString(issuer),
      notBefore: asn1Time(validity.value[0]),
      notAfter: asn1Time(validity.value[1]),
      spkiDer: fromBinary(forge.asn1.toDer(spki).getBytes()),
      keyType: 'OTHER',
      curve: null,
      rsaBits: null,
      algOid,
    };
    if (algOid === OID.rsaEncryption) {
      info.keyType = 'RSA';
      info.rsaBits = forge.pki.publicKeyFromAsn1(spki).n.bitLength();
    } else if (algOid === OID.ecPublicKey) {
      info.keyType = 'EC';
      const params = spki.value[0].value[1];
      info.curve = params && params.type === forge.asn1.Type.OID ? forge.asn1.derToOid(params.value) : null;
    }
    return info;
  }

  const describeKey = (c) =>
    c.keyType === 'RSA' ? `RSA ${c.rsaBits} bit`
      : c.keyType === 'EC' ? (c.curve === OID.p256 ? 'EC P-256' : `EC (curve ${c.curve || '?'})`)
        : `other (${c.algOid})`;

  // Which algs a certificate can sign with (alg = the default, algs = all choices), or a reason it cannot.
  function algForCertificate(c) {
    if (c.keyType === 'RSA') return c.rsaBits < MIN_RSA_BITS ? { error: REASONS.WEAK_KEY } : { alg: 'PS256', algs: ['PS256', 'RS256'] };
    if (c.keyType === 'EC' && c.curve === OID.p256) return { alg: 'ES256', algs: ['ES256'] };
    return { error: REASONS.ALG_KEY_MISMATCH };
  }

  // ---------- WebCrypto parameters ----------

  const PARAMS = {
    PS256: { import: { name: 'RSA-PSS', hash: 'SHA-256' }, sign: { name: 'RSA-PSS', saltLength: 32 } },
    ES256: { import: { name: 'ECDSA', namedCurve: 'P-256' }, sign: { name: 'ECDSA', hash: 'SHA-256' } },
    RS256: { import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, sign: { name: 'RSASSA-PKCS1-v1_5' } },
  };

  // ---------- signers ----------

  // Opens a .pfx/.p12 in the browser. Returns { certificate (parsed), algs, alg, sign(input) }.
  // alg is the one in use; set it to any entry of algs (RSA: PS256 or RS256) before signing.
  async function pfxSigner(pfxBytes, password) {
    let p12;
    try {
      const asn1 = forge.asn1.fromDer(forge.util.createBuffer(toBinary(pfxBytes)));
      p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password);
    } catch (e) {
      throw new Error('Cannot open the PFX: wrong password or not a PFX file.');
    }
    const bagsOf = (type) => p12.getBags({ bagType: type })[type] || [];
    const keyBag = bagsOf(forge.pki.oids.pkcs8ShroudedKeyBag)[0] || bagsOf(forge.pki.oids.keyBag)[0];
    const certBags = bagsOf(forge.pki.oids.certBag);
    if (!keyBag || certBags.length === 0) throw new Error('The PFX has no private key or no certificate.');

    // Pick the certificate that belongs to the key (same localKeyId); fall back to the first one.
    const keyId = keyBag.attributes && keyBag.attributes.localKeyId && keyBag.attributes.localKeyId[0];
    const certBag = certBags.find((b) => keyId && b.attributes.localKeyId && b.attributes.localKeyId[0] === keyId) || certBags[0];

    // forge parses RSA keys/certs into objects and leaves EC ones as raw ASN.1. Both become DER here.
    const der = (asn1) => fromBinary(forge.asn1.toDer(asn1).getBytes());
    const pkcs8 = keyBag.asn1 ? der(keyBag.asn1) : der(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(keyBag.key)));
    const certificate = parseCertificate(certBag.asn1 ? der(certBag.asn1) : der(forge.pki.certificateToAsn1(certBag.cert)));

    const choice = algForCertificate(certificate);
    if (choice.error) {
      throw new Error(`This key cannot sign: ${describeKey(certificate)} (${choice.error}). Use RSA ≥ 2048 or EC P-256.`);
    }
    // One WebCrypto key per alg: the padding scheme is fixed at import time.
    const keys = {};
    for (const a of choice.algs) keys[a] = await crypto.subtle.importKey('pkcs8', pkcs8, PARAMS[a].import, false, ['sign']);
    const signer = {
      kind: 'pfx',
      certificate,
      algs: choice.algs,
      alg: choice.alg,
      sign: async (input) => {
        if (!Object.hasOwn(keys, signer.alg)) throw new Error(`This key cannot sign with ${signer.alg}.`);
        return new Uint8Array(await crypto.subtle.sign(PARAMS[signer.alg].sign, keys[signer.alg], input));
      },
    };
    return signer;
  }

  // ---------- sign ----------

  // Signs payload bytes. Returns every intermediate value so the page can show them.
  async function sign(payloadBytes, signer, { iat } = {}) {
    const header = { alg: signer.alg, iat: iat ?? Math.floor(Date.now() / 1000), x5c: [b64Encode(signer.certificate.der)] };
    const headerJson = JSON.stringify(header);
    const protectedB64 = b64urlEncode(utf8(headerJson));
    const payloadB64 = b64urlEncode(payloadBytes);
    const signingInput = protectedB64 + '.' + payloadB64;
    const signature = await signer.sign(ascii(signingInput));
    const signatureB64 = b64urlEncode(signature);
    return {
      header, headerJson, protectedB64, payloadB64, signingInput, signature, signatureB64,
      file: { protected: protectedB64, payload: payloadB64, signature: signatureB64 },
      headerValue: protectedB64 + '..' + signatureB64,
    };
  }

  // ---------- verify (§4.3 order, first failure wins, never throws) ----------

  async function verify(signed, { now, requireIat = true } = {}) {
    now = now ?? Math.floor(Date.now() / 1000);
    const result = { valid: false, reason: null, header: null, certificate: null, payload: null, signingInput: null };
    const fail = (reason) => Object.assign(result, { reason });

    // 1. JSON object with string protected / payload / signature, all valid Base64URL.
    let obj = signed;
    if (typeof signed === 'string') {
      try { obj = JSON.parse(signed); } catch { return fail(REASONS.MALFORMED_INPUT); }
    }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return fail(REASONS.MALFORMED_INPUT);
    const { protected: p, payload, signature } = obj;
    if (typeof p !== 'string' || typeof payload !== 'string' || typeof signature !== 'string') return fail(REASONS.MALFORMED_INPUT);
    let headerBytes, sigBytes;
    try {
      headerBytes = b64urlDecode(p);
      result.payload = b64urlDecode(payload);
      sigBytes = b64urlDecode(signature);
    } catch { return fail(REASONS.MALFORMED_INPUT); }
    result.signingInput = p + '.' + payload;

    // 2. Protected header is a JSON object.
    let header;
    try { header = JSON.parse(fromUtf8(headerBytes, true)); } catch { return fail(REASONS.MALFORMED_HEADER); }
    if (!header || typeof header !== 'object' || Array.isArray(header)) return fail(REASONS.MALFORMED_HEADER);
    result.header = header;

    // 3. Required members and types.
    if (typeof header.alg !== 'string') return fail(REASONS.MISSING_ALG);
    // iat may be absent only when requireIat is off; a present iat must always be an integer.
    const hasIat = header.iat !== undefined;
    if (hasIat ? !Number.isInteger(header.iat) : requireIat) return fail(REASONS.MISSING_IAT);
    if (!Array.isArray(header.x5c) || header.x5c.length === 0 || !header.x5c.every((x) => typeof x === 'string')) {
      return fail(REASONS.MISSING_X5C);
    }
    if (!Object.hasOwn(PARAMS, header.alg)) return fail(REASONS.UNSUPPORTED_ALG);

    // 4. Certificate parses and its key matches alg.
    let cert;
    try { cert = parseCertificate(b64Decode(header.x5c[0])); } catch { return fail(REASONS.BAD_CERTIFICATE); }
    result.certificate = cert;
    if (header.alg !== 'ES256' && cert.keyType !== 'RSA') return fail(REASONS.ALG_KEY_MISMATCH);
    if (header.alg === 'ES256' && !(cert.keyType === 'EC' && cert.curve === OID.p256)) return fail(REASONS.ALG_KEY_MISMATCH);
    if (cert.keyType === 'RSA' && cert.rsaBits < MIN_RSA_BITS) return fail(REASONS.WEAK_KEY);

    // 5. Signature over ASCII(protected + "." + payload), exactly as received.
    let ok = false;
    try {
      const key = await crypto.subtle.importKey('spki', cert.spkiDer, PARAMS[header.alg].import, false, ['verify']);
      ok = await crypto.subtle.verify(PARAMS[header.alg].sign, key, sigBytes, ascii(result.signingInput));
    } catch { ok = false; }
    if (!ok) return fail(REASONS.BAD_SIGNATURE);

    // 6. Time window: now - 24h <= iat <= now + 5 min. Skipped when iat is absent (requireIat off).
    if (hasIat) {
      if (now - header.iat > MAX_AGE) return fail(REASONS.EXPIRED);
      if (header.iat - now > MAX_FUTURE) return fail(REASONS.NOT_YET_VALID);
    }

    result.valid = true;
    return result;
  }

  // REST: header value "protected..signature" + exact body bytes.
  async function verifyRest(headerValue, bodyBytes, opts) {
    const parts = String(headerValue ?? '').trim().split('.');
    if (parts.length !== 3 || parts[1] !== '') {
      return { valid: false, reason: REASONS.MALFORMED_INPUT, header: null, certificate: null, payload: bodyBytes, signingInput: null };
    }
    return verify({ protected: parts[0], payload: b64urlEncode(bodyBytes), signature: parts[2] }, opts);
  }

  return {
    REASONS, HEADER_NAME, MAX_AGE, MAX_FUTURE, FormatError,
    utf8, fromUtf8, b64urlEncode, b64urlDecode, b64Encode, b64Decode,
    parseCertificate, describeKey, algForCertificate, pfxSigner, sign, verify, verifyRest,
  };
})();
