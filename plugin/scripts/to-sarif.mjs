#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { isMainModule } from './lib/cli.mjs';
import { fingerprint, skipFingerprint } from './lib/fingerprint.mjs';

const SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const INFO_URI = 'https://github.com/Macchha/aisec';

export const SKIPPED_RULE_ID = 'AISEC_SKIPPED';

// SARIF has four levels; aisec has four severities, but they do not line up one to one.
// WARN is not "less than LOW" — it is TRIFECTA, a risk posture rather than a defect — so
// it maps alongside MED rather than below LOW.
const LEVEL = { HIGH: 'error', MED: 'warning', LOW: 'note', WARN: 'warning' };

// GitHub code scanning ranks and filters on this, and ignores `level` for that purpose.
// Without it every finding sorts as if unrated.
const SECURITY_SEVERITY = { HIGH: '8.0', MED: '5.0', LOW: '3.0', WARN: '5.0' };

// A `file` that is a package name rather than a path. SCA findings and TRIFECTA carry
// `line: null`, and SCA additionally puts a package name in `file` — emitting that as an
// artifactLocation invents a path that is not in the repository, and a consumer that
// tries to open it gets nothing.
const looksLikePath = (s) =>
  typeof s === 'string' && (s.includes('/') || s.includes('\\') || /\.[A-Za-z0-9]+$/.test(s));

function ruleFor(id, sample) {
  const rule = {
    id,
    name: id,
    shortDescription: { text: sample.message.split('\n')[0].slice(0, 120) },
    properties: {
      'security-severity': SECURITY_SEVERITY[sample.severity] ?? '5.0',
      tags: ['security', sample.source === 'rule' ? 'deterministic' : 'model-judgment'],
    },
  };
  if (sample.hint) rule.help = { text: sample.hint };
  return rule;
}

function resultFor(f) {
  const result = {
    ruleId: f.id,
    level: LEVEL[f.severity] ?? 'warning',
    message: { text: f.message },
    properties: { source: f.source, confidence: f.confidence, aisecSeverity: f.severity },
    partialFingerprints: { aisecFinding: fingerprint(f) },
  };

  if (looksLikePath(f.file)) {
    const physicalLocation = { artifactLocation: { uri: f.file } };
    // Only attach a region when there is a line. `startLine: null` is invalid SARIF, and
    // `startLine: 0` is worse — it validates, and points at nothing.
    if (Number.isInteger(f.line) && f.line > 0) physicalLocation.region = { startLine: f.line };
    result.locations = [{ physicalLocation }];
  } else if (f.file) {
    // logicalLocations hangs off a *location*, not off the result. Putting it directly
    // on the result validates against nothing and a strict consumer rejects the whole
    // document — which is how 21 of 22 findings on a real dependency scan would have
    // been thrown away. Caught by schema validation, not by hand-written assertions.
    result.locations = [{ logicalLocations: [{ name: f.file, kind: 'package' }] }];
  }

  return result;
}

// Most skips open with the thing they are about — "package.json: devDependencies were
// not collected", ".: no agent config found". Anchor the result there when we can read
// it, so the gap surfaces on the file it concerns.
const SKIP_SUBJECT_RE = /^([^\s:]+):\s/;

function skipLocation(text) {
  const m = SKIP_SUBJECT_RE.exec(text);
  const subject = m && m[1] !== '.' && looksLikePath(m[1]) ? m[1] : '.';
  return [{ physicalLocation: { artifactLocation: { uri: subject } } }];
}

function skippedResult(text) {
  return {
    ruleId: SKIPPED_RULE_ID,
    level: 'warning',
    message: { text },
    // SARIF permits a result with no location, and the schema validates one happily.
    // GitHub code scanning does not: it rejects the *entire* submission with
    // "locationFromSarifResult: expected at least one location", so three location-less
    // skips took every real finding down with them and the Security tab stayed empty.
    // The skips exist to keep gaps visible; emitting them in a form that voids the whole
    // report is that failure inverted.
    locations: skipLocation(text),
    properties: { source: 'rule', aisecSeverity: 'WARN' },
    partialFingerprints: { aisecFinding: skipFingerprint(text) },
  };
}

const SKIPPED_RULE = {
  id: SKIPPED_RULE_ID,
  name: SKIPPED_RULE_ID,
  shortDescription: { text: 'A check could not run, so this target was not fully checked' },
  fullDescription: {
    text: 'aisec records every check it could not complete rather than omitting it. '
      + 'A skipped check is not a passed check: nothing was verified here, and the '
      + 'absence of a finding for it means nothing.',
  },
  help: { text: 'Re-run with the missing input available — a network connection, a lockfile, a config file — or accept the stated gap knowingly.' },
  properties: { 'security-severity': '5.0', tags: ['security', 'coverage'] },
};

export function toSarif(report, { version = '0.1.0' } = {}) {
  if (!report || typeof report !== 'object') throw new Error('expected a report object');
  if (report.findings !== undefined && !Array.isArray(report.findings)) {
    throw new Error('report.findings must be an array');
  }
  const findings = report.findings ?? [];
  const scanned = Array.isArray(report.scanned) ? report.scanned : [];
  const skipped = Array.isArray(report.skipped) ? report.skipped : [];

  const rules = [];
  const seen = new Set();
  for (const f of findings) {
    if (seen.has(f.id)) continue;
    seen.add(f.id);
    rules.push(ruleFor(f.id, f));
  }
  if (skipped.length > 0) rules.push(SKIPPED_RULE);

  const notifications = skipped.map(text => ({
    level: 'warning',
    message: { text },
    descriptor: { id: SKIPPED_RULE_ID },
  }));

  return {
    $schema: SCHEMA,
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'aisec', version, informationUri: INFO_URI, rules } },
      // executionSuccessful describes whether the *tool* ran, not whether the target was
      // clean. A scan that completed while skipping checks still ran successfully; the
      // skips are reported, not disguised as a crash.
      invocations: [{ executionSuccessful: true, toolExecutionNotifications: notifications }],
      artifacts: scanned.map(uri => ({ location: { uri } })),
      results: [...findings.map(resultFor), ...skipped.map(skippedResult)],
      properties: { findingCount: findings.length, skippedCount: skipped.length },
    }],
  };
}

function readInput(path) {
  if (path) return readFileSync(path, 'utf8');
  return readFileSync(0, 'utf8'); // stdin, so a scanner can be piped straight in
}

function main() {
  const args = process.argv.slice(2);
  const bad = args.find(a => a.startsWith('-'));
  if (bad) { console.error(`unknown option: ${bad}\nusage: to-sarif.mjs [report.json]  (or pipe JSON on stdin)`); process.exit(2); }
  try {
    const text = readInput(args[0]);
    let parsed;
    try { parsed = JSON.parse(text); }
    catch { throw new Error('input is not valid JSON — expected an aisec report'); }
    console.log(JSON.stringify(toSarif(parsed), null, 2));
  } catch (err) {
    console.error(`sarif conversion failed: ${err.message}`);
    process.exit(2);
  }
}

if (isMainModule(import.meta.url)) main();
