#!/usr/bin/env node
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import { isMainModule } from './lib/cli.mjs';
import { finding, emptyReport, sortFindings } from './lib/findings.mjs';

// Format-control and invisible codepoints that can carry hidden instructions.
const INVISIBLE_RE = /[\u00AD\u034F\u061C\u115F\u1160\u180E\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u206F\u3164\uFEFF\uFFA0\uFFF9-\uFFFB]|[\u{1D173}-\u{1D17A}]|[\u{E0000}-\u{E007F}]/gu;

// A lone variation selector is ordinary — every emoji carries one — so these are
// matched separately and only reported as a run. See VS_RUN_RE below.
const VS_RUN_RE = /[\uFE00-\uFE0F\u{E0100}-\u{E01EF}]{2,}/gu;

const NAMES = new Map([
  [0x00ad, 'soft hyphen'],
  [0x034f, 'combining grapheme joiner'],
  [0x061c, 'arabic letter mark (bidi control)'],
  [0x115f, 'hangul choseong filler'],
  [0x1160, 'hangul jungseong filler'],
  [0x180e, 'mongolian vowel separator'],
  [0x3164, 'hangul filler'],
  [0xffa0, 'halfwidth hangul filler'],
  [0x200b, 'zero-width space'],
  [0x200c, 'zero-width non-joiner'],
  [0x200d, 'zero-width joiner'],
  [0x200e, 'left-to-right mark'],
  [0x200f, 'right-to-left mark'],
  [0x2060, 'word joiner'],
  [0x202a, 'bidi left-to-right embedding'],
  [0x202b, 'bidi right-to-left embedding'],
  [0x202c, 'bidi pop directional formatting'],
  [0x202d, 'bidi left-to-right override'],
  [0x202e, 'bidi right-to-left override'],
  [0xfeff, 'zero-width no-break space (BOM)'],
]);

export function describeCodepoint(cp) {
  if (NAMES.has(cp)) return NAMES.get(cp);
  if (cp >= 0xe0000 && cp <= 0xe007f) return 'Unicode tag character (invisible instruction carrier)';
  if (cp >= 0xfe00 && cp <= 0xfe0f) return 'variation selector';
  if (cp >= 0xe0100 && cp <= 0xe01ef) return 'variation selector supplement';
  if (cp >= 0x206a && cp <= 0x206f) return 'deprecated format control';
  if (cp >= 0xfff9 && cp <= 0xfffb) return 'interlinear annotation control';
  if (cp >= 0x1d173 && cp <= 0x1d17a) return 'musical format control';
  return 'invisible format-control character';
}

const hex = (cp) => `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;

export function scanTextForInvisibles(text, filePath) {
  const out = [];
  // A U+FEFF at offset 0 is a byte order mark — an encoding artifact, not a hidden
  // instruction. Reporting it HIGH/HIGH made every BOM-prefixed file a maximum
  // severity finding. A U+FEFF anywhere else is still the smuggling case.
  const body = text.startsWith('\uFEFF') ? text.slice(1) : text;
  body.split('\n').forEach((lineText, i) => {
    const details = [];
    const hits = [...lineText.matchAll(INVISIBLE_RE)];
    if (hits.length > 0) {
      const seen = [...new Set(hits.map(h => h[0].codePointAt(0)))];
      details.push(...seen.map(cp => `${hex(cp)} (${describeCodepoint(cp)})`));
    }
    // Single selectors are legitimate; consecutive runs are the smuggling vector.
    for (const run of lineText.matchAll(VS_RUN_RE)) {
      const cps = [...run[0]];
      details.push(`${hex(cps[0].codePointAt(0))} (run of ${cps.length} variation selectors, hidden data carrier)`);
    }
    if (details.length === 0) return;
    const detail = details.join(', ');
    out.push(finding({
      id: 'MCP002', severity: 'HIGH', confidence: 'HIGH', source: 'rule',
      file: filePath, line: i + 1,
      message: `invisible character(s) in source: ${detail}`,
      hint: 'Invisible codepoints can carry instructions the reviewer cannot see. Remove them, or treat the file as hostile.',
    }));
  });
  return out;
}

const SCAN_EXT = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.json', '.md']);
const SKIP_DIR = new Set(['node_modules', '.git', 'dist', 'build', '.venv', '__pycache__', 'coverage']);
const MAX_FILE_BYTES = 2_000_000;

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIR.has(entry.name)) yield* walk(join(dir, entry.name));
    } else if (SCAN_EXT.has(extname(entry.name))) {
      yield join(dir, entry.name);
    }
  }
}

export function scanUnicode(rootPath) {
  const report = emptyReport();
  const stat = statSync(rootPath);
  const files = stat.isDirectory() ? [...walk(rootPath)] : [rootPath];
  for (const file of files) {
    let text;
    try {
      if (statSync(file).size > MAX_FILE_BYTES) {
        report.skipped.push(`${file}: unicode scan skipped — file larger than 2 MB`);
        continue;
      }
      text = readFileSync(file, 'utf8');
    } catch (err) {
      report.skipped.push(`${file}: unicode scan skipped — ${err.message}`);
      continue;
    }
    report.scanned.push(file);
    report.findings.push(...scanTextForInvisibles(text, file));
  }
  report.findings = sortFindings(report.findings);
  return report;
}

function main() {
  const path = process.argv[2];
  if (!path) { console.error('usage: scan-unicode.mjs <path>'); process.exit(2); }
  try { console.log(JSON.stringify(scanUnicode(path), null, 2)); }
  catch (err) { console.error(`scan failed: ${err.message}`); process.exit(2); }
}

if (isMainModule(import.meta.url)) main();
