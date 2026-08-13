#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { isMainModule } from './lib/cli.mjs';
import { fingerprint } from './lib/fingerprint.mjs';

export const THRESHOLDS = ['high', 'med', 'low', 'none'];

// Which severities each threshold blocks on. WARN sits with MED rather than below LOW:
// TRIFECTA is a risk posture, not something milder than a LOW defect, and a team that
// asked to be told about MED-level risk wants to hear about it.
const BLOCKS = {
  high: new Set(['HIGH']),
  med: new Set(['HIGH', 'MED', 'WARN']),
  low: new Set(['HIGH', 'MED', 'WARN', 'LOW']),
  none: new Set(),
};

/**
 * A baseline records findings only, never skips.
 *
 * Suppressing a skip would hide the fact that a check stopped running, which is the one
 * thing this tool refuses to do. A skip you have accepted is expressed by not passing
 * --fail-on-skipped, which is visible in your CI config, rather than by burying it in a
 * file nobody rereads.
 */
export function buildBaseline(report, { note = '' } = {}) {
  const findings = report?.findings ?? [];
  return {
    version: 1,
    createdAt: new Date().toISOString(),
    note,
    // Enough context to review the baseline by hand. A file of bare hashes is a file
    // nobody can audit, and an unauditable suppression list is how findings disappear.
    fingerprints: findings.map(f => ({
      fingerprint: fingerprint(f),
      id: f.id,
      severity: f.severity,
      file: f.file,
      line: f.line,
      message: f.message,
    })),
  };
}

function describe(f) {
  const at = f.line ? `${f.file}:${f.line}` : f.file;
  return `  ${f.severity.padEnd(4)} ${f.id.padEnd(16)} ${at}\n         ${f.message}`;
}

export function gate(report, { failOn = 'high', failOnSkipped = false, baseline = null } = {}) {
  if (!report || typeof report !== 'object') throw new Error('expected a report object');
  if (report.findings !== undefined && !Array.isArray(report.findings)) {
    throw new Error('report.findings must be an array');
  }
  if (!THRESHOLDS.includes(failOn)) {
    throw new Error(`unknown threshold: ${failOn} (expected one of ${THRESHOLDS.join(', ')})`);
  }

  const findings = report.findings ?? [];
  const skipped = Array.isArray(report.skipped) ? report.skipped : [];
  const blocks = BLOCKS[failOn];

  const known = new Set((baseline?.fingerprints ?? []).map(e => e.fingerprint));
  const seen = new Set();

  const baselined = [];
  const blocking = [];
  for (const f of findings) {
    const fp = fingerprint(f);
    seen.add(fp);
    if (known.has(fp)) { baselined.push(f); continue; }
    if (blocks.has(f.severity)) blocking.push(f);
  }

  // Baselined entries that no longer appear: the finding was fixed, or it moved. Either
  // way the entry is now suppressing nothing and should be pruned, or it will silently
  // suppress some future finding that happens to hash the same.
  const staleBaseline = [...known].filter(fp => !seen.has(fp));

  const blockingSkips = failOnSkipped ? [...skipped] : [];
  const exitCode = blocking.length > 0 || blockingSkips.length > 0 ? 1 : 0;

  // "Clean" means every check ran and found nothing. A scan that skipped work is not
  // clean, whatever its exit code — saying otherwise is the failure this tool exists to
  // prevent, and a green build is exactly where nobody looks twice.
  const clean = findings.length === 0 && skipped.length === 0;

  const lines = [];
  if (blocking.length > 0) {
    lines.push(`FAIL — ${blocking.length} finding(s) at or above ${failOn.toUpperCase()}:`);
    lines.push(...blocking.map(describe));
  }
  if (blockingSkips.length > 0) {
    lines.push(`FAIL — ${blockingSkips.length} check(s) did not run, and --fail-on-skipped is set:`);
    lines.push(...blockingSkips.map(s => `  ${s}`));
  }
  if (blocking.length === 0 && blockingSkips.length === 0) {
    lines.push(clean
      ? 'PASS — every check ran and found nothing.'
      : `PASS — nothing at or above ${failOn.toUpperCase()}.`);
  }
  if (skipped.length > 0) {
    lines.push('', `${skipped.length} check(s) did not run — this target was not fully checked:`);
    lines.push(...skipped.map(s => `  ${s}`));
    lines.push('A skipped check is not a passed check. Nothing was verified there.');
  }
  if (baselined.length > 0) lines.push('', `${baselined.length} finding(s) suppressed by the baseline.`);
  if (staleBaseline.length > 0) {
    lines.push(`${staleBaseline.length} baseline entr(ies) no longer match anything — prune them.`);
  }
  const belowThreshold = findings.length - blocking.length - baselined.length;
  if (belowThreshold > 0) lines.push(`${belowThreshold} finding(s) below the ${failOn.toUpperCase()} threshold, reported but not blocking.`);

  return {
    exitCode,
    clean,
    blocking,
    blockingSkips,
    baselined,
    staleBaseline,
    findingCount: findings.length,
    skippedCount: skipped.length,
    summary: lines.join('\n'),
  };
}

function parseArgs(argv) {
  const opts = { failOn: 'high', failOnSkipped: false, baselinePath: null, writeBaselinePath: null, input: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--fail-on') opts.failOn = argv[++i];
    else if (a === '--fail-on-skipped') opts.failOnSkipped = true;
    else if (a === '--baseline') opts.baselinePath = argv[++i];
    else if (a === '--write-baseline') opts.writeBaselinePath = argv[++i];
    else if (a.startsWith('-')) throw new Error(`unknown option: ${a}`);
    else if (opts.input === null) opts.input = a;
    else throw new Error(`unexpected argument: ${a}`);
  }
  return opts;
}

function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); }
  catch (err) {
    console.error(`${err.message}
usage: gate.mjs [report.json] [--fail-on high|med|low|none] [--fail-on-skipped]
                [--baseline b.json] [--write-baseline b.json]`);
    process.exit(2);
  }

  try {
    const text = opts.input ? readFileSync(opts.input, 'utf8') : readFileSync(0, 'utf8');
    let report;
    try { report = JSON.parse(text); }
    catch { throw new Error('input is not valid JSON — expected an aisec report'); }

    if (opts.writeBaselinePath) {
      writeFileSync(opts.writeBaselinePath, JSON.stringify(buildBaseline(report), null, 2) + '\n');
      console.log(`wrote baseline with ${report.findings?.length ?? 0} finding(s) to ${opts.writeBaselinePath}`);
      return; // exit 0: writing a baseline is not a gate run
    }

    const baseline = opts.baselinePath
      ? JSON.parse(readFileSync(opts.baselinePath, 'utf8'))
      : null;

    const result = gate(report, {
      failOn: opts.failOn, failOnSkipped: opts.failOnSkipped, baseline,
    });
    console.log(result.summary);
    process.exit(result.exitCode);
  } catch (err) {
    console.error(`gate failed: ${err.message}`);
    process.exit(2);
  }
}

if (isMainModule(import.meta.url)) main();
