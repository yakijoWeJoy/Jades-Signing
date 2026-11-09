import fs from 'node:fs';
import crypto from 'node:crypto';
import forge from 'node-forge';
import { rawSign } from '../algs.js';

const toBuf = (asn1) => Buffer.from(forge.asn1.toDer(asn1).getBytes(), 'binary');

export class PfxSigner {
  #key;

  constructor(keyObject, certificate) {
    this.#key = keyObject;
    this.certificate = certificate;
    this.keyType = keyObject.asymmetricKeyType === 'rsa' ? 'RSA' : 'EC';
  }

  static fromFile(path, password) {
    const der = fs.readFileSync(path);
    let p12;
    try {
      const asn1 = forge.asn1.fromDer(forge.util.createBuffer(der.toString('binary')));
      p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, password);
    } catch (e) {
      throw new Error(`Cannot open PFX ${path}: wrong password or corrupt file (${e.message})`);
    }
    const keyBag = (p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || [])[0];
    const certBag = (p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [])[0];
    if (!keyBag || !certBag) throw new Error(`PFX ${path} has no private key or certificate`);
    const keyObject = crypto.createPrivateKey({ key: pkcs8Der(keyBag), format: 'der', type: 'pkcs8' });
    return new PfxSigner(keyObject, certDer(certBag));
  }

  async sign(input, alg) {
    return rawSign(this.#key, input, alg);
  }
}

// node-forge fills bag.asn1 (raw, unparsed) only for key/cert types it cannot parse (EC);
// for RSA it parses into bag.key / bag.cert and leaves asn1 unset. Both paths yield the same DER.
function pkcs8Der(bag) {
  if (bag.asn1) return toBuf(bag.asn1); // decrypted PKCS#8 PrivateKeyInfo
  return toBuf(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(bag.key)));
}

function certDer(bag) {
  return toBuf(bag.asn1 || forge.pki.certificateToAsn1(bag.cert));
}
