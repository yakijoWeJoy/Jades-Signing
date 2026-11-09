// UI wiring for the demo page. The JAdES logic itself is in jades.js.
'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const state = { signer: null, lastSigned: null };

  // ---------- small helpers ----------

  const setStatus = (el, text, kind = '') => { el.textContent = text; el.className = 'status ' + kind; };
  const readBytes = (file) => file.arrayBuffer().then((b) => new Uint8Array(b));
  const pretty = (v) => JSON.stringify(v, null, 2);

  function download(name, bytes, type = 'application/json') {
    const url = URL.createObjectURL(new Blob([bytes], { type }));
    const a = Object.assign(document.createElement('a'), { href: url, download: name });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function copy(text, btn) {
    try { await navigator.clipboard.writeText(text); } catch { return; }
    const old = btn.textContent; btn.textContent = 'הועתק ✓';
    setTimeout(() => { btn.textContent = old; }, 1200);
  }

  const fmtTime = (unix) => `${unix} (${new Date(unix * 1000).toISOString().replace('.000Z', 'Z')})`;

  const REASON_HE = {
    MALFORMED_INPUT: 'קלט לא תקין (JSON, חלקים חסרים או Base64URL שגוי)',
    MALFORMED_HEADER: 'ה-protected header אינו אובייקט JSON',
    MISSING_ALG: 'חסר alg או שהוא מסוג שגוי',
    MISSING_IAT: 'חסר iat או שאינו מספר שלם',
    MISSING_X5C: 'חסר x5c או שאינו מערך מחרוזות לא ריק',
    UNSUPPORTED_ALG: 'אלגוריתם לא נתמך (רק PS256 / ES256)',
    BAD_CERTIFICATE: 'x5c[0] אינו תעודה תקינה',
    ALG_KEY_MISMATCH: 'האלגוריתם לא מתאים למפתח שבתעודה',
    WEAK_KEY: 'מפתח RSA קטן מ-2048 ביט',
    BAD_SIGNATURE: 'החתימה לא תקינה: התוכן או הכותרת שונו',
    EXPIRED: 'פג תוקף: נחתם לפני יותר מ-24 שעות',
    NOT_YET_VALID: 'iat בעתיד (יותר מ-5 דקות)',
  };

  function renderVerdict(el, r) {
    el.className = 'verdict ' + (r.valid ? 'ok' : 'bad');
    el.textContent = '';
    const b = document.createElement('b');
    b.textContent = r.valid ? '✓ חתימה תקינה' : '✗ לא תקין';
    el.append(b);
    if (!r.valid) {
      const code = document.createElement('code');
      code.textContent = r.reason;
      el.append(' ', code, ' – ' + (REASON_HE[r.reason] || ''));
    } else if (r.header) {
      el.append(` · ${r.header.alg} · נחתם ${fmtTime(r.header.iat)}`);
    }
  }

  // Shows payload bytes as pretty JSON if they are JSON, else as text.
  function payloadView(bytes) {
    if (!bytes) return '—';
    const text = Jades.fromUtf8(bytes);
    try { return pretty(JSON.parse(text)); } catch { return text; }
  }

  // ---------- tabs ----------

  function showTab(name) {
    document.querySelectorAll('.tabs [role=tab]').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.tab === name)));
    document.querySelectorAll('.tab').forEach((s) => { s.hidden = s.id !== 'tab-' + name; });
  }
  document.querySelectorAll('.tabs [role=tab]').forEach((t) => t.addEventListener('click', () => showTab(t.dataset.tab)));

  function radioValue(name) { return document.querySelector(`input[name=${name}]:checked`).value; }
  function bindRadio(name, map) {
    const apply = () => { const v = radioValue(name); Object.entries(map).forEach(([k, id]) => { $(id).hidden = k !== v; }); };
    document.querySelectorAll(`input[name=${name}]`).forEach((r) => r.addEventListener('change', apply));
    apply();
  }

  // ================= SIGN =================

  const payloadStatus = $('payload-status');
  function checkPayload() {
    try { JSON.parse($('payload').value); setStatus(payloadStatus, `JSON תקין · ${Jades.utf8($('payload').value).length} בתים`, 'ok'); return true; }
    catch (e) { setStatus(payloadStatus, 'JSON לא תקין: ' + e.message, 'bad'); return false; }
  }
  $('payload').addEventListener('input', checkPayload);
  $('btn-pretty').addEventListener('click', () => { if (checkPayload()) { $('payload').value = pretty(JSON.parse($('payload').value)); checkPayload(); } });
  $('btn-compact').addEventListener('click', () => { if (checkPayload()) { $('payload').value = JSON.stringify(JSON.parse($('payload').value)); checkPayload(); } });
  $('payload-file').addEventListener('change', async (e) => {
    const f = e.target.files[0]; if (!f) return;
    $('payload').value = Jades.fromUtf8(await readBytes(f)).replace(/^﻿/, '');
    e.target.value = '';
    checkPayload();
  });

  bindRadio('keysrc', { pfx: 'src-pfx', card: 'src-card' });
  document.querySelectorAll('input[name=keysrc]').forEach((r) => r.addEventListener('change', () => setSigner(null)));

  function setSigner(signer) {
    state.signer = signer;
    $('btn-sign').disabled = !signer;
    const info = $('signer-info');
    info.hidden = !signer;
    if (!signer) return;
    const c = signer.certificate;
    info.textContent = '';
    const rows = [
      ['נושא', c.subject], ['מנפיק', c.issuer], ['מפתח', Jades.describeKey(c)], ['אלגוריתם', signer.alg],
      ['בתוקף', `${c.notBefore ? c.notBefore.toISOString().slice(0, 10) : '?'} – ${c.notAfter ? c.notAfter.toISOString().slice(0, 10) : '?'}`],
    ];
    const dl = document.createElement('dl'); dl.className = 'kv';
    for (const [k, v] of rows) {
      const dt = document.createElement('dt'); dt.textContent = k;
      const dd = document.createElement('dd'); dd.textContent = v; dd.dir = 'ltr';
      dl.append(dt, dd);
    }
    info.append(dl);
  }

  $('btn-load-pfx').addEventListener('click', async () => {
    const f = $('pfx-file').files[0];
    if (!f) return setStatus($('sign-status'), 'בחרו קובץ PFX', 'bad');
    setStatus($('sign-status'), 'פותח את ה-PFX…');
    try {
      setSigner(await Jades.pfxSigner(await readBytes(f), $('pfx-password').value));
      setStatus($('sign-status'), 'המפתח נטען', 'ok');
    } catch (e) {
      setSigner(null);
      setStatus($('sign-status'), e.message, 'bad');
    }
  });

  // ----- smart card through the local helper (demo/smartcard-helper.ps1) -----

  let helperCerts = [];

  async function helperCall(path, body) {
    const base = $('helper-url').value.trim().replace(/\/+$/, '');
    let res;
    try {
      res = await fetch(base + path, {
        method: body ? 'POST' : 'GET',
        headers: { 'X-Helper-Token': $('helper-token').value.trim(), ...(body ? { 'Content-Type': 'application/json' } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch {
      throw new Error('אין חיבור לעוזר המקומי. האם הוא רץ? האם הכתובת נכונה?');
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `העוזר החזיר ${res.status}`);
    return data;
  }

  $('btn-helper-list').addEventListener('click', async () => {
    const sel = $('helper-certs');
    setStatus($('sign-status'), 'מבקש תעודות מהעוזר…');
    try {
      const { certificates } = await helperCall('/certs');
      helperCerts = certificates.map((c) => {
        try { return { ...c, parsed: Jades.parseCertificate(Jades.b64Decode(c.der)) }; } catch { return null; }
      }).filter(Boolean);
      sel.textContent = '';
      for (const [i, c] of helperCerts.entries()) {
        const choice = Jades.algForCertificate(c.parsed);
        const opt = new Option(`${c.parsed.subject} · ${Jades.describeKey(c.parsed)}${choice.error ? ' (לא נתמך)' : ''}`, String(i));
        opt.disabled = Boolean(choice.error);
        sel.add(opt);
      }
      sel.disabled = helperCerts.length === 0;
      setStatus($('sign-status'), helperCerts.length ? `נמצאו ${helperCerts.length} תעודות עם מפתח פרטי` : 'לא נמצאו תעודות עם מפתח פרטי', helperCerts.length ? 'ok' : 'bad');
      const first = [...sel.options].find((o) => !o.disabled);
      if (first) { sel.value = first.value; pickHelperCert(); } else setSigner(null);
    } catch (e) {
      setSigner(null);
      setStatus($('sign-status'), e.message, 'bad');
    }
  });

  function pickHelperCert() {
    const c = helperCerts[Number($('helper-certs').value)];
    if (!c) return setSigner(null);
    const { alg, error } = Jades.algForCertificate(c.parsed);
    if (error) return setSigner(null);
    setSigner({
      kind: 'card',
      certificate: c.parsed,
      alg,
      sign: async (input) => {
        const { signature } = await helperCall('/sign', { thumbprint: c.thumbprint, alg, data: Jades.b64urlEncode(input) });
        return Jades.b64urlDecode(signature);
      },
    });
  }
  $('helper-certs').addEventListener('change', pickHelperCert);

  // ----- sign -----

  $('btn-sign').addEventListener('click', async () => {
    if (!checkPayload()) return;
    setStatus($('sign-status'), state.signer.kind === 'card' ? 'חותם… (אשרו את ה-PIN בחלון של Windows)' : 'חותם…');
    try {
      const s = await Jades.sign(Jades.utf8($('payload').value), state.signer);
      state.lastSigned = s;
      $('o-header').textContent = pretty(s.header);
      $('o-protected').textContent = s.protectedB64;
      $('o-payload').textContent = s.payloadB64;
      $('o-input').textContent = s.signingInput;
      $('o-sigdesc').textContent = s.header.alg === 'ES256'
        ? `ECDSA P-256 SHA-256: ${s.signature.length} bytes R‖S`
        : `RSASSA-PSS SHA-256, salt 32: ${s.signature.length} bytes`;
      $('o-signature').textContent = s.signatureB64;
      $('o-file').textContent = pretty(s.file);
      $('sign-out').hidden = false;
      $('c-signed').value = pretty(s.file);
      $('v-signed').value = pretty(s.file);
      setStatus($('sign-status'), 'נחתם ✓', 'ok');
      $('sign-out').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
      setStatus($('sign-status'), 'החתימה נכשלה: ' + e.message, 'bad');
    }
  });

  $('btn-download-signed').addEventListener('click', () => download('signed.json', Jades.utf8(pretty(state.lastSigned.file) + '\n')));
  $('btn-copy-signed').addEventListener('click', (e) => copy(pretty(state.lastSigned.file), e.target));
  $('btn-to-verify').addEventListener('click', () => { showTab('verify'); $('btn-verify').click(); });
  $('btn-to-curl').addEventListener('click', () => { showTab('curl'); $('btn-curl').click(); });

  // ================= VERIFY =================

  bindRadio('vmode', { file: 'v-file', rest: 'v-rest' });

  let restBodyBytes = null; // set when the body comes from a file, so its bytes are used exactly
  $('v-body').addEventListener('input', () => { restBodyBytes = null; setStatus($('v-body-status'), ''); });
  $('v-body-file').addEventListener('change', async (e) => {
    const f = e.target.files[0]; if (!f) return;
    restBodyBytes = await readBytes(f);
    $('v-body').value = Jades.fromUtf8(restBodyBytes);
    setStatus($('v-body-status'), `${f.name}: ${restBodyBytes.length} בתים מהקובץ`, 'ok');
    e.target.value = '';
  });
  $('v-file-input').addEventListener('change', async (e) => {
    const f = e.target.files[0]; if (!f) return;
    $('v-signed').value = Jades.fromUtf8(await readBytes(f));
    e.target.value = '';
    $('btn-verify').click();
  });

  function readNow(input) {
    const v = input.value.trim();
    if (!v) return undefined;
    if (!/^-?\d+$/.test(v)) throw new Error('זמן אימות חייב להיות מספר שלם (Unix seconds)');
    return Number(v);
  }

  $('btn-verify').addEventListener('click', async () => {
    let now;
    try { now = readNow($('v-now')); } catch (e) { return alert(e.message); }
    const r = radioValue('vmode') === 'file'
      ? await Jades.verify($('v-signed').value, { now })
      : await Jades.verifyRest($('v-header').value, restBodyBytes || Jades.utf8($('v-body').value), { now });

    renderVerdict($('v-verdict'), r);
    $('v-o-header').textContent = r.header ? pretty(r.header) : '—';
    $('v-o-payload').textContent = payloadView(r.payload);
    $('v-o-raw').textContent = r.payload ? `${r.payload.length} bytes:\n${Jades.fromUtf8(r.payload)}` : '—';

    const dl = $('v-o-cert'); dl.textContent = '';
    const c = r.certificate;
    const rows = c ? [
      ['נושא', c.subject], ['מנפיק', c.issuer], ['מפתח', Jades.describeKey(c)],
      ['בתוקף (לא נבדק)', `${c.notBefore ? c.notBefore.toISOString().slice(0, 10) : '?'} – ${c.notAfter ? c.notAfter.toISOString().slice(0, 10) : '?'}`],
    ] : [['', '—']];
    if (r.header && Number.isInteger(r.header.iat)) rows.push(['iat', fmtTime(r.header.iat)]);
    for (const [k, v] of rows) {
      const dt = document.createElement('dt'); dt.textContent = k;
      const dd = document.createElement('dd'); dd.textContent = v; dd.dir = 'ltr';
      dl.append(dt, dd);
    }
    $('verify-out').hidden = false;
  });

  // ================= CURL =================

  $('c-file-input').addEventListener('change', async (e) => {
    const f = e.target.files[0]; if (!f) return;
    $('c-signed').value = Jades.fromUtf8(await readBytes(f));
    e.target.value = '';
  });

  const quote = {
    bash: (s) => `'${s.replace(/'/g, `'\\''`)}'`,
    ps: (s) => `'${s.replace(/'/g, `''`)}'`,
  };

  function buildCurl({ shell, method, url, headerValue, mtls }) {
    const q = quote[shell];
    const lines = [
      `${shell === 'ps' ? 'curl.exe' : 'curl'} -X ${method} ${q(url)}`,
      `-H ${q('Content-Type: application/json')}`,
      `-H ${q(`${Jades.HEADER_NAME}: ${headerValue}`)}`,
      // PowerShell reads a bare @name as splatting, so the @file argument must be quoted there.
      `--data-binary ${shell === 'ps' ? q('@body.json') : '@body.json'}`,
    ];
    if (mtls) lines.push(`--cert-type P12 --cert ${q('provider-mtls.pfx:PASSWORD')}`);
    const cont = shell === 'ps' ? ' `' : ' \\';
    return lines.map((l, i) => (i === 0 ? l : '  ' + l)).join(cont + '\n');
  }

  let curlBody = null;

  $('btn-curl').addEventListener('click', async () => {
    let file;
    try { file = JSON.parse($('c-signed').value); } catch { file = null; }
    const r = await Jades.verify($('c-signed').value);
    renderVerdict($('c-verdict'), r);
    if (!r.valid) {
      $('c-verdict').append(' · Customs ידחו את הקריאה הזו.');
    }
    $('curl-out').hidden = false;
    if (!file || !r.payload) {
      $('c-body').textContent = '—';
      $('c-cmd').textContent = 'אין קובץ חתום תקין במבנה {protected, payload, signature}.';
      curlBody = null;
      return;
    }
    curlBody = r.payload;
    $('c-body').textContent = Jades.fromUtf8(curlBody);

    const base = $('c-base').value.trim().replace(/\/+$/, '');
    let path = $('c-path').value.trim();
    if (path && !path.startsWith('/')) path = '/' + path;
    $('c-cmd').textContent = buildCurl({
      shell: radioValue('shell'),
      method: $('c-method').value,
      url: base + path,
      headerValue: file.protected + '..' + file.signature,
      mtls: $('c-mtls').checked,
    });
    $('c-explain-mtls').hidden = !$('c-mtls').checked;
  });
  ['c-method', 'c-base', 'c-path', 'c-mtls'].forEach((id) => $(id).addEventListener('change', () => { if (!$('curl-out').hidden) $('btn-curl').click(); }));
  document.querySelectorAll('input[name=shell]').forEach((r) => r.addEventListener('change', () => { if (!$('curl-out').hidden) $('btn-curl').click(); }));

  $('btn-download-body').addEventListener('click', () => { if (curlBody) download('body.json', curlBody); });
  $('btn-copy-cmd').addEventListener('click', (e) => copy($('c-cmd').textContent, e.target));

  checkPayload();
})();
