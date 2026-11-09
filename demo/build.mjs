// Builds the single self-contained page: inlines style.css, node-forge, jades.js and app.js
// into demo/jades-demo.html so it works offline with no other files.
// Usage: node demo/build.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const read = (p) => readFileSync(join(here, p), 'utf8').replace(/^﻿/, '');

// Keep "</script" from closing the inline tag early.
const script = (code) => `<script>\n${code.replace(/<\/script/gi, '<\\/script')}\n</script>`;

let html = read('src/index.html');
const replace = (tag, content) => {
  if (!html.includes(tag)) throw new Error(`build: tag not found in index.html: ${tag}`);
  html = html.replace(tag, () => content);
};

replace('<link rel="stylesheet" href="style.css">', `<style>\n${read('src/style.css')}</style>`);
replace('<script src="../vendor/forge-1.4.3.min.js"></script>',
  `<!-- node-forge 1.4.3 (BSD-3-Clause), see demo/vendor/forge-LICENSE.txt -->\n${script(read('vendor/forge-1.4.3.min.js'))}`);
replace('<script src="jades.js"></script>', script(read('src/jades.js')));
replace('<script src="app.js"></script>', script(read('src/app.js')));

const out = join(here, 'jades-demo.html');
writeFileSync(out, html);
console.log(`wrote ${out} (${(Buffer.byteLength(html) / 1024).toFixed(0)} KB)`);
