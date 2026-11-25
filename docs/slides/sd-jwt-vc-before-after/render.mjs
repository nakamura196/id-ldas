// Render selected slides of this deck to PNG (1920x1080) for blog figures.
// Usage: node render.mjs <out-dir> <prefix> [slide ids...]
// Uses Playwright from the tech-blog checkout (no dependency added here).
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';

const require = createRequire(join(os.homedir(), 'git/zenn/web/package.json'));
const { chromium } = require('playwright');
const here = dirname(fileURLToPath(import.meta.url));
const [outDir, prefix, ...ids] = process.argv.slice(2);
const css = readFileSync(join(here, 'project/deck.css'), 'utf8');

// Stand-ins for the Slides runtime: arrow connector and table cells.
const shim = `
html,body{margin:0;padding:0}
section{width:1920px;height:1080px;position:relative;overflow:hidden}
section aside{display:none}
x-connector{display:block;position:relative;height:0;border-top-style:solid;border-top-color:currentColor;color:#7E8BA0;border-top-width:3px;flex:none}
x-connector::after{content:"";position:absolute;right:-2px;top:-11px;border-left:16px solid currentColor;border-top:9px solid transparent;border-bottom:9px solid transparent}
x-connector[head="both"]::before{content:"";position:absolute;left:-2px;top:-11px;border-right:16px solid currentColor;border-top:9px solid transparent;border-bottom:9px solid transparent}
table{border-collapse:collapse}
th,td{border-bottom:2px solid var(--line);padding:18px 20px;text-align:left;vertical-align:top}
th{font-weight:700;background:#DCE3EC}
`;
const fonts = '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=BIZ+UDPGothic:wght@400;700&family=BIZ+UDGothic:wght@400;700&display=swap">';

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
for (const id of ids) {
  const sec = readFileSync(join(here, 'project/slides', id + '.html'), 'utf8');
  await page.setContent(`<!doctype html><html><head><meta charset="utf-8">${fonts}<style>${css}${shim}</style></head><body>${sec}</body></html>`, { waitUntil: 'networkidle' });
  await page.evaluate(() => document.fonts.ready);
  const out = join(outDir, `${prefix}-${id}.png`);
  await page.locator('section').screenshot({ path: out });
  console.log(out);
}
await browser.close();
