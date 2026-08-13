#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scanAll } from '../plugin/scripts/scan-all.mjs';
import { toSarif } from '../plugin/scripts/to-sarif.mjs';
import { gate, buildBaseline, THRESHOLDS } from '../plugin/scripts/gate.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf8'));

const USAGE = `aisec ${pkg.version} — security scanning for MCP servers and agent applications

  aisec scan [path] [options]     scan a project (default path: .)
  aisec version
  aisec help

Options
  --format text|json|sarif   output format (default: text)
  --offline                  no network: skip OSV and registry lookups
  --fail-on high|med|low|none  exit 1 at or above this severity (default: high)
  --fail-on-skipped          exit 1 if any check could not run
  --baseline <file>          suppress findings recorded in this file
  --write-baseline <file>    record current findings and exit 0
  -o, --out <file>           write output to a file instead of stdout

Exit codes
  0  gate passed        1  gate failed        2  aisec itself failed

The CLI runs the deterministic scripts only. Rules needing model judgment are
listed in every report's skipped section — use /aisec-review in Claude Code for
those. A skipped check is never a passed check.`;

function parseArgs(argv) {
  const o = {
    command: null, path: '.', format: 'text', offline: false,
    failOn: 'high', failOnSkipped: false, baseline: null, writeBaseline: null, out: null,
  };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = (name) => {
      const v = argv[++i];
      if (v === undefined || v.startsWith('-')) throw new Error(`${name} needs a value`);
      return v;
    };
    if (a === '--format') o.format = need('--format');
    else if (a === '--offline') o.offline = true;
    else if (a === '--fail-on') o.failOn = need('--fail-on');
    else if (a === '--fail-on-skipped') o.failOnSkipped = true;
    else if (a === '--baseline') o.baseline = need('--baseline');
    else if (a === '--write-baseline') o.writeBaseline = need('--write-baseline');
    else if (a === '-o' || a === '--out') o.out = need(a);
    else if (a === '-h' || a === '--help') o.command = 'help';
    else if (a === '-v' || a === '--version') o.command = 'version';
    else if (a.startsWith('-')) throw new Error(`unknown option: ${a}`);
    else rest.push(a);
  }
  if (!o.command) {
    o.command = rest.length > 0 && ['scan', 'help', 'version'].includes(rest[0]) ? rest.shift() : 'scan';
  }
  if (rest.length > 1) throw new Error(`unexpected argument: ${rest[1]}`);
  if (rest.length === 1) o.path = rest[0];
  if (!['text', 'json', 'sarif'].includes(o.format)) {
    throw new Error(`unknown format: ${o.format} (expected text, json or sarif)`);
  }
  if (!THRESHOLDS.includes(o.failOn)) {
    throw new Error(`unknown threshold: ${o.failOn} (expected one of ${THRESHOLDS.join(', ')})`);
  }
  return o;
}

function textReport(report, result, target) {
  const lines = [`aisec — ${target}`, ''];
  if (report.findings.length === 0) {
    lines.push('No findings from the deterministic scripts.');
  } else {
    let severity = null;
    for (const f of report.findings) {
      if (f.severity !== severity) { severity = f.severity; lines.push(`${severity}`); }
      const at = f.line ? `${f.file}:${f.line}` : f.file;
      lines.push(`  ${f.id.padEnd(16)} ${at}  [${f.source}]`);
      lines.push(`    ${f.message}`);
      if (f.hint) lines.push(`    → ${f.hint}`);
    }
  }
  lines.push('', result.summary);
  lines.push('', `${report.findings.length} finding(s), ${report.skipped.length} check(s) not run.`);
  lines.push('Automated scan, not a code audit, not a guarantee.');
  return lines.join('\n');
}

async function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); }
  catch (err) { console.error(`${err.message}\n\n${USAGE}`); process.exit(2); }

  if (o.command === 'help') { console.log(USAGE); return; }
  if (o.command === 'version') { console.log(pkg.version); return; }

  try {
    const report = await scanAll(o.path, { offline: o.offline });

    if (o.writeBaseline) {
      writeFileSync(o.writeBaseline, JSON.stringify(buildBaseline(report), null, 2) + '\n');
      console.log(`wrote baseline with ${report.findings.length} finding(s) to ${o.writeBaseline}`);
      return;
    }

    const baseline = o.baseline ? JSON.parse(readFileSync(o.baseline, 'utf8')) : null;
    const result = gate(report, {
      failOn: o.failOn, failOnSkipped: o.failOnSkipped, baseline,
    });

    const out = o.format === 'json' ? JSON.stringify(report, null, 2)
      : o.format === 'sarif' ? JSON.stringify(toSarif(report, { version: pkg.version }), null, 2)
        : textReport(report, result, o.path);

    if (o.out) writeFileSync(o.out, out + '\n');
    else console.log(out);

    // The gate decides the exit code in every format. A machine-readable run that
    // always exited 0 would make `--format sarif` silently unusable in CI.
    process.exit(result.exitCode);
  } catch (err) {
    console.error(`aisec: ${err.message}`);
    process.exit(2);
  }
}

main();
