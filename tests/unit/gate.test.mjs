import { describe, it, expect } from 'vitest';
import { gate, buildBaseline, THRESHOLDS } from '../../plugin/scripts/gate.mjs';
import { fingerprint } from '../../plugin/scripts/lib/fingerprint.mjs';

const report = (over = {}) => ({ findings: [], scanned: [], skipped: [], ...over });
const f = (over = {}) => ({
  id: 'MCP010', severity: 'HIGH', confidence: 'HIGH', source: 'model',
  file: 'src/tools.ts', line: 42, message: 'param reaches a shell', hint: 'use execFile',
  ...over,
});

describe('threshold', () => {
  it('defaults to failing on HIGH only', () => {
    expect(gate(report({ findings: [f({ severity: 'HIGH' })] })).exitCode).toBe(1);
    expect(gate(report({ findings: [f({ severity: 'MED' })] })).exitCode).toBe(0);
    expect(gate(report({ findings: [f({ severity: 'LOW' })] })).exitCode).toBe(0);
  });

  it('failOn med also catches WARN, which is a posture not a lesser severity', () => {
    const r = gate(report({ findings: [f({ severity: 'WARN' })] }), { failOn: 'med' });
    expect(r.exitCode).toBe(1);
    expect(r.blocking.map(x => x.severity)).toEqual(['WARN']);
  });

  it('failOn low catches everything that is a finding', () => {
    const findings = ['HIGH', 'MED', 'LOW', 'WARN'].map((severity, i) => f({ severity, line: i + 1 }));
    expect(gate(report({ findings }), { failOn: 'low' }).blocking).toHaveLength(4);
  });

  it('failOn none never fails on findings', () => {
    const r = gate(report({ findings: [f({ severity: 'HIGH' })] }), { failOn: 'none' });
    expect(r.exitCode).toBe(0);
    expect(r.blocking).toEqual([]);
  });

  it('rejects an unknown threshold rather than guessing', () => {
    expect(() => gate(report(), { failOn: 'critical' })).toThrow(/critical/);
    expect(THRESHOLDS).toContain('high');
  });
});

// The product's core claim is that "could not check" never reads as "clean".
// A gate that prints a green PASS while 100 packages went unchecked breaks it.
describe('skipped checks', () => {
  const skipped = ['vulnerability lookup skipped for 100 packages — offline mode'];

  it('does not fail the build by default', () => {
    expect(gate(report({ skipped })).exitCode).toBe(0);
  });

  it('never calls the result clean when something was skipped', () => {
    const r = gate(report({ skipped }));
    expect(r.clean).toBe(false);
    expect(r.summary).toMatch(/not fully checked|did not run/i);
    expect(r.summary).not.toMatch(/\bclean\b/i);
  });

  it('does call it clean when nothing was skipped and nothing found', () => {
    const r = gate(report());
    expect(r.clean).toBe(true);
    expect(r.exitCode).toBe(0);
  });

  it('fails on skips when asked to', () => {
    const r = gate(report({ skipped }), { failOnSkipped: true });
    expect(r.exitCode).toBe(1);
    expect(r.blockingSkips).toHaveLength(1);
  });

  it('counts skips separately from findings', () => {
    const r = gate(report({ findings: [f()], skipped }));
    expect(r.findingCount).toBe(1);
    expect(r.skippedCount).toBe(1);
  });
});

describe('baseline', () => {
  const known = f({ severity: 'HIGH' });
  const fresh = f({ severity: 'HIGH', line: 99, message: 'a different one' });

  it('suppresses a finding whose fingerprint is baselined', () => {
    const baseline = buildBaseline(report({ findings: [known] }));
    const r = gate(report({ findings: [known] }), { baseline });
    expect(r.exitCode).toBe(0);
    expect(r.baselined).toHaveLength(1);
    expect(r.blocking).toEqual([]);
  });

  it('still fails on a finding that is not baselined', () => {
    const baseline = buildBaseline(report({ findings: [known] }));
    const r = gate(report({ findings: [known, fresh] }), { baseline });
    expect(r.exitCode).toBe(1);
    expect(r.blocking).toHaveLength(1);
    expect(r.blocking[0].message).toBe('a different one');
  });

  it('treats a moved finding as new, because it is a row worth re-reading', () => {
    const baseline = buildBaseline(report({ findings: [known] }));
    const moved = { ...known, line: known.line + 10 };
    expect(gate(report({ findings: [moved] }), { baseline }).exitCode).toBe(1);
  });

  it('reports baselined findings that no longer appear, so a baseline can be pruned', () => {
    const baseline = buildBaseline(report({ findings: [known, fresh] }));
    const r = gate(report({ findings: [known] }), { baseline });
    expect(r.staleBaseline).toHaveLength(1);
    expect(r.staleBaseline[0]).toBe(fingerprint(fresh));
  });

  it('builds a baseline carrying enough context to review it by hand', () => {
    const baseline = buildBaseline(report({ findings: [known], skipped: ['x'] }));
    expect(baseline.fingerprints[0]).toMatchObject({
      fingerprint: fingerprint(known), id: 'MCP010', severity: 'HIGH', file: 'src/tools.ts',
    });
    // A baseline records findings, not skips: suppressing a skip would hide the fact
    // that a check stopped running.
    expect(JSON.stringify(baseline)).not.toContain('skipped');
  });

  it('a baseline never suppresses a skip', () => {
    const baseline = buildBaseline(report({ findings: [known] }));
    const r = gate(report({ skipped: ['still skipped'] }), { baseline, failOnSkipped: true });
    expect(r.exitCode).toBe(1);
  });
});

describe('summary', () => {
  it('states what blocked and why', () => {
    const r = gate(report({ findings: [f({ severity: 'HIGH' })] }));
    expect(r.summary).toContain('MCP010');
    expect(r.summary).toMatch(/HIGH/);
  });

  it('never prints a secret the scanner masked', () => {
    const masked = 'env TOKEN contains a Anthropic API key in plaintext (sk-a…(35 chars))';
    const r = gate(report({ findings: [f({ id: 'SECRET_INLINE', message: masked })] }));
    expect(r.summary).toContain('sk-a…(35 chars)');
    expect(r.summary).not.toMatch(/sk-ant-[A-Za-z0-9]{10,}/);
  });
});

describe('input validation', () => {
  it('rejects a payload that is not a report', () => {
    expect(() => gate(null)).toThrow(/report/i);
    expect(() => gate({ findings: 'nope' })).toThrow(/findings/i);
  });
});
