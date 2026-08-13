// Validates real converter output against the official SARIF 2.1.0 schema.
//
// The other SARIF tests assert the shape we intended. This one asserts the shape
// the spec actually requires, which is a different question — a document can pass
// every hand-written assertion and still be rejected by a consumer. ajv and the
// vendored schema are devDependencies only; the runtime stays dependency-free.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { toSarif } from '../../plugin/scripts/to-sarif.mjs';

const schema = JSON.parse(readFileSync('tests/fixtures/sarif-schema-2.1.0.json', 'utf8'));

const ajv = new Ajv({ strict: false, allErrors: true });
addFormats(ajv);
const validate = ajv.compile(schema);

const check = (doc) => {
  const ok = validate(doc);
  // Surface the actual schema error rather than a bare `false`.
  if (!ok) throw new Error(ajv.errorsText(validate.errors, { separator: '\n  ' }));
  return ok;
};

const f = (over = {}) => ({
  id: 'MCP010', severity: 'HIGH', confidence: 'HIGH', source: 'model',
  file: 'src/tools.ts', line: 42, message: 'param reaches a shell', hint: 'use execFile',
  ...over,
});

describe('SARIF output validates against the official 2.1.0 schema', () => {
  it('an empty report', () => {
    expect(check(toSarif({ findings: [], scanned: [], skipped: [] }))).toBe(true);
  });

  it('a located finding', () => {
    expect(check(toSarif({ findings: [f()], scanned: ['src/tools.ts'], skipped: [] }))).toBe(true);
  });

  it('every severity level', () => {
    const findings = ['HIGH', 'MED', 'LOW', 'WARN'].map((severity, i) =>
      f({ severity, line: i + 1 }));
    expect(check(toSarif({ findings, scanned: [], skipped: [] }))).toBe(true);
  });

  // The shape most likely to be rejected: no line, and a package name where a
  // consumer expects a path.
  it('a package finding with no line', () => {
    const findings = [f({ id: 'VULN_KNOWN', file: 'lodash', line: null, source: 'rule' })];
    expect(check(toSarif({ findings, scanned: [], skipped: [] }))).toBe(true);
  });

  it('a path-shaped finding with no line', () => {
    const findings = [f({ id: 'TRIFECTA', severity: 'WARN', file: '.mcp.json', line: null, source: 'rule' })];
    expect(check(toSarif({ findings, scanned: [], skipped: [] }))).toBe(true);
  });

  it('skips, which appear as both results and notifications', () => {
    const doc = toSarif({
      findings: [f()],
      scanned: ['src/tools.ts'],
      skipped: ['vulnerability lookup skipped for 100 packages — offline mode'],
    });
    expect(check(doc)).toBe(true);
    expect(doc.runs[0].invocations[0].toolExecutionNotifications).toHaveLength(1);
  });

  it('a full mixed report', () => {
    const doc = toSarif({
      findings: [
        f(),
        f({ id: 'MCP002', source: 'rule', line: 7 }),
        f({ id: 'VULN_KNOWN', file: 'lodash', line: null, source: 'rule', severity: 'MED' }),
        f({ id: 'TRIFECTA', file: '.mcp.json', line: null, source: 'rule', severity: 'WARN' }),
      ],
      scanned: ['src/tools.ts', '.mcp.json', 'package-lock.json'],
      skipped: ['no lockfile found', 'registry metadata checks skipped — offline mode'],
    });
    expect(check(doc)).toBe(true);
  });
});
