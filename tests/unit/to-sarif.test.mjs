import { describe, it, expect } from 'vitest';
import { toSarif, SKIPPED_RULE_ID } from '../../plugin/scripts/to-sarif.mjs';

const report = (over = {}) => ({ findings: [], scanned: [], skipped: [], ...over });

const f = (over = {}) => ({
  id: 'MCP010', severity: 'HIGH', confidence: 'HIGH', source: 'model',
  file: 'src/tools.ts', line: 42,
  message: 'Tool parameter `target` reaches child_process.exec.',
  hint: 'Use execFile with an argument array.',
  ...over,
});

const run = (s) => s.runs[0];
const results = (s) => run(s).results;

describe('envelope', () => {
  it('declares SARIF 2.1.0 with the schema and the tool driver', () => {
    const s = toSarif(report(), { version: '0.1.0' });
    expect(s.version).toBe('2.1.0');
    expect(s.$schema).toMatch(/sarif-2\.1\.0/);
    expect(run(s).tool.driver.name).toBe('aisec');
    expect(run(s).tool.driver.version).toBe('0.1.0');
  });

  it('produces a valid empty run for a clean report', () => {
    const s = toSarif(report());
    expect(results(s)).toEqual([]);
    expect(run(s).invocations[0].executionSuccessful).toBe(true);
  });
});

describe('findings become results', () => {
  it('maps a located finding to a result with a physical location', () => {
    const [r] = results(toSarif(report({ findings: [f()] })));
    expect(r.ruleId).toBe('MCP010');
    expect(r.level).toBe('error');
    expect(r.message.text).toContain('child_process.exec');
    const loc = r.locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toBe('src/tools.ts');
    expect(loc.region.startLine).toBe(42);
  });

  it('maps every severity to a SARIF level', () => {
    const levels = ['HIGH', 'MED', 'LOW', 'WARN'].map(severity =>
      results(toSarif(report({ findings: [f({ severity })] })))[0].level);
    expect(levels).toEqual(['error', 'warning', 'note', 'warning']);
  });

  it('carries security-severity so GitHub can rank it', () => {
    const s = toSarif(report({ findings: [f()] }));
    const rule = run(s).tool.driver.rules.find(x => x.id === 'MCP010');
    expect(Number(rule.properties['security-severity'])).toBeGreaterThanOrEqual(7);
  });

  it('preserves source and confidence as result properties', () => {
    const [r] = results(toSarif(report({ findings: [f({ source: 'rule', confidence: 'MED' })] })));
    expect(r.properties.source).toBe('rule');
    expect(r.properties.confidence).toBe('MED');
  });

  it('puts the hint in the rule help, not the message', () => {
    const s = toSarif(report({ findings: [f()] }));
    const rule = run(s).tool.driver.rules.find(x => x.id === 'MCP010');
    expect(rule.help.text).toContain('execFile');
    expect(results(s)[0].message.text).not.toContain('execFile');
  });

  it('declares each distinct rule once, however many findings use it', () => {
    const s = toSarif(report({ findings: [f({ line: 1 }), f({ line: 2 }), f({ id: 'MCP011', line: 3 })] }));
    const ids = run(s).tool.driver.rules.map(r => r.id);
    expect(ids.filter(i => i === 'MCP010')).toHaveLength(1);
    expect(ids).toContain('MCP011');
  });

  it('gives each result a stable fingerprint that survives a re-scan', () => {
    const a = results(toSarif(report({ findings: [f()] })))[0];
    const b = results(toSarif(report({ findings: [f()] })))[0];
    expect(a.partialFingerprints.aisecFinding).toBe(b.partialFingerprints.aisecFinding);
    const other = results(toSarif(report({ findings: [f({ line: 43 })] })))[0];
    expect(other.partialFingerprints.aisecFinding).not.toBe(a.partialFingerprints.aisecFinding);
  });
});

// SCA and TRIFECTA findings carry line: null and put a package name in `file`.
// A naive mapping emits `startLine: null`, which is invalid SARIF, or invents a
// file path that does not exist in the repo.
describe('findings with no line', () => {
  it('omits region entirely rather than emitting a null startLine', () => {
    const [r] = results(toSarif(report({
      findings: [f({ id: 'VULN_KNOWN', file: 'lodash', line: null, source: 'rule' })],
    })));
    const region = r.locations?.[0]?.physicalLocation?.region;
    expect(region?.startLine ?? undefined).toBeUndefined();
    expect(JSON.stringify(r)).not.toContain('"startLine":null');
  });

  // logicalLocations hangs off a `location`, not off the result. The first version of
  // this test asserted the wrong nesting and passed, so it encoded the bug rather than
  // catching it; schema validation caught it instead.
  it('describes a package as a logical location, not a file path', () => {
    const [r] = results(toSarif(report({
      findings: [f({ id: 'VULN_KNOWN', file: 'lodash', line: null, source: 'rule' })],
    })));
    expect(r.logicalLocations).toBeUndefined();
    expect(r.locations[0].logicalLocations[0]).toEqual({ name: 'lodash', kind: 'package' });
    expect(r.locations[0].physicalLocation).toBeUndefined();
  });

  it('still treats a path-shaped file with no line as a file', () => {
    const [r] = results(toSarif(report({
      findings: [f({ id: 'TRIFECTA', severity: 'WARN', file: '.mcp.json', line: null, source: 'rule' })],
    })));
    expect(r.locations[0].physicalLocation.artifactLocation.uri).toBe('.mcp.json');
    expect(r.locations[0].logicalLocations).toBeUndefined();
  });
});

// The product's whole thesis is that "could not check" never reads as "clean".
// SARIF has no first-class slot for that, so skips go BOTH places: results, so
// every consumer shows them, and notifications, which is what SARIF intends.
describe('skipped checks survive the conversion', () => {
  const skipped = ['vulnerability lookup skipped for 100 packages — offline mode'];

  it('emits each skip as a result under a dedicated rule', () => {
    const rs = results(toSarif(report({ skipped })));
    expect(rs).toHaveLength(1);
    expect(rs[0].ruleId).toBe(SKIPPED_RULE_ID);
    expect(rs[0].level).toBe('warning');
    expect(rs[0].message.text).toContain('offline mode');
  });

  it('also emits each skip as a tool execution notification', () => {
    const notes = run(toSarif(report({ skipped }))).invocations[0].toolExecutionNotifications;
    expect(notes).toHaveLength(1);
    expect(notes[0].message.text).toContain('offline mode');
    expect(notes[0].level).toBe('warning');
  });

  it('declares the skipped rule so consumers can name it', () => {
    const rule = run(toSarif(report({ skipped }))).tool.driver.rules.find(r => r.id === SKIPPED_RULE_ID);
    expect(rule.shortDescription.text).toMatch(/could not run|not checked/i);
  });

  it('keeps skips out of the findings count but present in results', () => {
    const s = toSarif(report({ findings: [f()], skipped }));
    expect(run(s).properties.findingCount).toBe(1);
    expect(run(s).properties.skippedCount).toBe(1);
    expect(results(s)).toHaveLength(2);
  });
});

describe('scanned files are recorded', () => {
  it('lists them as artifacts', () => {
    const s = toSarif(report({ scanned: ['src/index.ts', '.mcp.json'] }));
    expect(run(s).artifacts.map(a => a.location.uri)).toEqual(['src/index.ts', '.mcp.json']);
  });
});

describe('masking is preserved', () => {
  it('never reconstructs a secret the scanner masked', () => {
    const masked = 'env TOKEN contains a Anthropic API key in plaintext (sk-a…(35 chars))';
    const [r] = results(toSarif(report({
      findings: [f({ id: 'SECRET_INLINE', source: 'rule', message: masked })],
    })));
    expect(r.message.text).toBe(masked);
    expect(r.message.text).not.toMatch(/sk-ant-[A-Za-z0-9]{10,}/);
  });
});

describe('input validation', () => {
  it('rejects a payload that is not a report', () => {
    expect(() => toSarif(null)).toThrow(/report/i);
    expect(() => toSarif({ findings: 'nope' })).toThrow(/findings/i);
  });

  it('tolerates a report missing optional arrays', () => {
    const s = toSarif({ findings: [f()] });
    expect(results(s)).toHaveLength(1);
    expect(run(s).invocations[0].toolExecutionNotifications).toEqual([]);
  });
});
