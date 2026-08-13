#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { isMainModule } from './lib/cli.mjs';
import { emptyReport, sortFindings } from './lib/findings.mjs';
import { scanConfig, discoverConfigs, CONFIG_NAMES } from './scan-config.mjs';
import { scanUnicode } from './scan-unicode.mjs';
import { scanDependencies, collectLockfiles, collectDirectDeps } from './scan-lockfile.mjs';

/**
 * Rules that only a model can apply.
 *
 * The deterministic scripts own everything with an exact answer. Everything here needs
 * reading comprehension — whether a description is issuing orders, whether a parameter
 * reaches a sink, whether a path check actually contains — and a CLI has no model.
 *
 * They are listed by name in every CLI report's `skipped[]`, because a tool that quietly
 * applies half its rule set while its own documentation advertises all of them is the
 * "unknown reads as clean" failure at product level. The user should know which half
 * they got.
 */
export const MODEL_ONLY_RULES = [
  'MCP001', 'MCP003', 'MCP004', 'MCP005',
  'MCP006', 'MCP007', 'MCP008',
  'MCP010', 'MCP011', 'MCP012', 'MCP013', 'MCP014', 'MCP015',
  'MCP020', 'MCP021', 'MCP022', 'MCP023', 'MCP024', 'MCP025',
];

const MODEL_SKIP =
  `model-judgment rules did not run — the CLI runs only the deterministic scripts. `
  + `Not checked: ${MODEL_ONLY_RULES.join(', ')}. `
  + `Run /aisec-review in Claude Code for these; nothing above was verified about them.`;

/**
 * Run every deterministic scanner over `root` and merge the results.
 *
 * Each scanner reports its own gaps in `skipped[]`; this only concatenates and sorts.
 * Nothing here decides a check passed — that stays with the scanner that ran it.
 */
export async function scanAll(root, { offline = false } = {}) {
  let stat;
  try { stat = statSync(root); }
  catch (err) { throw new Error(`target does not exist: ${root} (${err.code ?? err.message})`); }
  if (!stat.isDirectory()) throw new Error(`target is not a directory: ${root}`);

  const report = emptyReport();
  const absorb = (r) => {
    report.findings.push(...r.findings);
    report.scanned.push(...r.scanned);
    report.skipped.push(...r.skipped);
  };

  // ---- Agent config
  const configs = discoverConfigs(root);
  if (configs.length === 0) {
    report.skipped.push(
      `${root}: no agent config found (looked for ${CONFIG_NAMES.join(', ')}) — config rules did not run`);
  }
  for (const file of configs) {
    try { absorb(scanConfig(readFileSync(file, 'utf8'), file)); }
    catch (err) { report.skipped.push(`${file}: config rules skipped — ${err.message}`); }
  }

  // ---- Invisible characters
  try { absorb(scanUnicode(root)); }
  catch (err) { report.skipped.push(`${root}: unicode scan skipped — ${err.message}`); }

  // ---- Dependencies
  try {
    const locks = collectLockfiles(root);
    const direct = collectDirectDeps(root);
    absorb(await scanDependencies({
      lockfiles: locks.lockfiles,
      directDeps: direct.deps,
      offline,
      scanned: direct.scanned,
      // Both collectors report what they could not read; carry those through rather
      // than dropping them, or an unreadable manifest becomes an invisible gap.
      skipped: [...locks.skipped, ...direct.skipped],
    }));
  } catch (err) {
    report.skipped.push(`${root}: dependency scan skipped — ${err.message}`);
  }

  report.skipped.push(MODEL_SKIP);
  report.findings = sortFindings(report.findings);
  report.scanned = [...new Set(report.scanned)];
  return report;
}

async function main() {
  const args = process.argv.slice(2);
  const offline = args.includes('--offline');
  const root = args.find(a => !a.startsWith('-'));
  const unknown = args.find(a => a.startsWith('-') && a !== '--offline');
  if (unknown) { console.error(`unknown option: ${unknown}`); process.exit(2); }
  if (!root) { console.error('usage: scan-all.mjs <project-dir> [--offline]'); process.exit(2); }
  try {
    console.log(JSON.stringify(await scanAll(root, { offline }), null, 2));
  } catch (err) {
    console.error(`scan failed: ${err.message}`);
    process.exit(2);
  }
}

if (isMainModule(import.meta.url)) main();
