// Generates the self-signed test certificates used by every language implementation.
// Idempotent: overwrites all outputs on every run.
// Usage: node test-vectors/certs/gen-certs.mjs   (set OPENSSL to override the binary)
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const OPENSSL = process.env.OPENSSL || 'openssl';
const PASSWORD = 'test1234';
const outDir = dirname(fileURLToPath(import.meta.url));
const tmp = mkdtempSync(join(tmpdir(), 'jades-certs-'));

const openssl = (args) => execFileSync(OPENSSL, args, { stdio: ['ignore', 'pipe', 'pipe'] });

const certs = [
  { name: 'rsa2048', key: ['rsa', 2048], cn: 'JAdES Test RSA' },
  { name: 'ec256', key: ['ec', 'prime256v1'], cn: 'JAdES Test EC' },
  { name: 'rsa1024', key: ['rsa', 1024], cn: 'JAdES Test RSA 1024' },
  { name: 'ec384', key: ['ec', 'secp384r1'], cn: 'JAdES Test EC P-384' },
  { name: 'mtls-client', key: ['rsa', 2048], cn: 'Provider' },
  {
    name: 'mock-server',
    key: ['rsa', 2048],
    cn: 'localhost',
    san: 'DNS:localhost,IP:127.0.0.1',
  },
];

try {
  for (const c of certs) {
    const keyFile = join(tmp, `${c.name}.key`);
    const pemFile = join(outDir, `${c.name}.pem`);
    const cerFile = join(outDir, `${c.name}.cer`);
    const pfxFile = join(outDir, `${c.name}.pfx`);

    // Private key
    if (c.key[0] === 'rsa') {
      openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', `rsa_keygen_bits:${c.key[1]}`, '-out', keyFile]);
    } else {
      openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', `ec_paramgen_curve:${c.key[1]}`, '-out', keyFile]);
    }

    // Self-signed certificate
    const req = [
      'req', '-x509', '-new', '-key', keyFile, '-sha256', '-days', '3650',
      '-subj', `/CN=${c.cn}`, '-out', pemFile,
    ];
    if (c.san) {
      req.push('-addext', `subjectAltName=${c.san}`);
    }
    openssl(req);

    // DER certificate (no key)
    openssl(['x509', '-in', pemFile, '-outform', 'DER', '-out', cerFile]);

    // PFX (cert + key)
    openssl([
      'pkcs12', '-export', '-inkey', keyFile, '-in', pemFile, '-name', c.cn,
      '-certpbe', 'AES-256-CBC', '-keypbe', 'AES-256-CBC', '-macalg', 'sha256',
      '-passout', `pass:${PASSWORD}`, '-out', pfxFile,
    ]);

    if (![pemFile, cerFile, pfxFile].every(existsSync)) {
      throw new Error(`missing output for ${c.name}`);
    }
    console.log(`generated ${c.name}.{pfx,cer,pem}`);
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
