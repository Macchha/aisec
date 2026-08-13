// Exercises bin/aisec.mjs as a process, because the things most likely to break —
// argument parsing, exit codes, which stream output lands on — are invisible to a
// direct function call. The CLI's exit code is its entire contract in CI.
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const BIN = join(ROOT, 'bin', 'aisec.mjs');
const VULN = join(ROOT, 'tests', 'fixtures', 'vulnerable-server');
const CLEAN = join(ROOT, 'tests', 'fixtures', 'clean-server');

const run = (...args) => spawnSync('node', [BIN, ...args], { encoding: 'utf8' });

describe('exit codes are the CI contract', () => {
  it('exits 1 when the gate fails', () => {
    expect(run('scan', VULN, '--offline').status).toBe(1);
  });

  it('exits 0 when the gate passes', () => {
    expect(run('scan', CLEAN, '--offline').status).toBe(0);
  });

  it('exits 2 when aisec itself fails, never 0', () => {
    expect(run('scan', '/nope/not/here').status).toBe(2);
    expect(run('--nonsense').status).toBe(2);
    expect(run('scan', CLEAN, '--format', 'bogus').status).toBe(2);
    expect(run('scan', CLEAN, '--fail-on', 'critical').status).toBe(2);
  });

  it('honours --fail-on none', () => {
    expect(run('scan', VULN, '--offline', '--fail-on', 'none').status).toBe(0);
  });

  it('honours --fail-on-skipped, since an offline run always skips something', () => {
    expect(run('scan', CLEAN, '--offline', '--fail-on-skipped').status).toBe(1);
  });

  // A machine-readable run that always exited 0 would make --format sarif unusable
  // in CI, which is the one place it is meant to be used.
  it('applies the gate in every format', () => {
    expect(run('scan', VULN, '--offline', '--format', 'json').status).toBe(1);
    expect(run('scan', VULN, '--offline', '--format', 'sarif').status).toBe(1);
  });
});

describe('the model layer is never silently absent', () => {
  it('names the rules it did not run, on a passing scan', () => {
    const { stdout } = run('scan', CLEAN, '--offline');
    expect(stdout).toMatch(/model-judgment rules did not run/);
    expect(stdout).toContain('MCP010');
    expect(stdout).toMatch(/aisec-review/);
  });

  it('never calls a partially-checked target clean', () => {
    const { stdout } = run('scan', CLEAN, '--offline');
    expect(stdout).toMatch(/not fully checked/i);
    expect(stdout).not.toMatch(/every check ran/i);
  });
});

describe('output', () => {
  it('emits parseable JSON with the report shape', () => {
    const { stdout } = run('scan', CLEAN, '--offline', '--format', 'json');
    const report = JSON.parse(stdout);
    expect(Object.keys(report).sort()).toEqual(['findings', 'scanned', 'skipped']);
  });

  it('emits SARIF 2.1.0 naming itself with the real version', () => {
    const { stdout } = run('scan', CLEAN, '--offline', '--format', 'sarif');
    const doc = JSON.parse(stdout);
    expect(doc.version).toBe('2.1.0');
    expect(doc.runs[0].tool.driver.name).toBe('aisec');
    expect(doc.runs[0].tool.driver.version).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('keeps errors on stderr so stdout stays machine-readable', () => {
    const r = run('scan', '/nope/not/here', '--format', 'json');
    expect(r.stdout.trim()).toBe('');
    expect(r.stderr).toMatch(/aisec:/);
  });

  it('never prints a secret it masked', () => {
    const { stdout } = run('scan', VULN, '--offline');
    expect(stdout).toContain('sk-a…(35 chars)');
    expect(stdout).not.toMatch(/sk-ant-[A-Za-z0-9]{10,}/);
  });
});

describe('help and version', () => {
  it('prints usage and exits 0', () => {
    const r = run('help');
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/aisec scan/);
  });

  it('states the model-layer limit in the usage text itself', () => {
    expect(run('help').stdout).toMatch(/deterministic scripts only/i);
  });

  it('prints a semver version', () => {
    const r = run('version');
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
