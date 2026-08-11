import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';

const json = (p) => JSON.parse(readFileSync(p, 'utf8'));

describe('plugin manifest', () => {
  it('declares a name, description and version', () => {
    const m = json('plugin/.claude-plugin/plugin.json');
    expect(m.name).toBe('aisec');
    expect(m.description).toBeTruthy();
    expect(m.version).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('has a marketplace manifest pointing at this plugin', () => {
    const m = json('.claude-plugin/marketplace.json');
    expect(m.plugins.some(p => p.name === 'aisec')).toBe(true);
  });
});

describe('command', () => {
  const body = () => readFileSync('plugin/commands/aisec-review.md', 'utf8');

  it('exists with description frontmatter', () => {
    expect(existsSync('plugin/commands/aisec-review.md')).toBe(true);
    expect(body().split('---')[1]).toMatch(/description:\s*\S/);
  });

  it('allows the tools the scan needs', () => {
    const fm = body().split('---')[1];
    expect(fm).toMatch(/allowed-tools:/);
    expect(fm).toMatch(/Bash/);
    expect(fm).toMatch(/Read/);
  });

  it('delegates to the skill rather than restating the methodology', () => {
    expect(body()).toContain('scanning-mcp-servers');
  });

  it('passes the user argument through', () => {
    expect(body()).toContain('$ARGUMENTS');
  });

  it('documents the --json output option', () => {
    expect(body()).toContain('--json');
  });
});

describe('README', () => {
  it('documents install, usage, and the scan limitations', () => {
    const r = readFileSync('README.md', 'utf8');
    expect(r).toContain('/aisec-review');
    expect(r).toMatch(/not a code audit/i);
    expect(r).toMatch(/install/i);
  });
});

describe('runtime dependencies', () => {
  it('has none', () => {
    expect(json('package.json').dependencies ?? {}).toEqual({});
  });
});
