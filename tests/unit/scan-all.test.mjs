import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanAll, MODEL_ONLY_RULES } from '../../plugin/scripts/scan-all.mjs';

const roots = [];
const tmp = () => { const d = mkdtempSync(join(tmpdir(), 'aisec-cli-')); roots.push(d); return d; };
afterAll(() => { for (const d of roots) rmSync(d, { recursive: true, force: true }); });

function project({ mcp, src, lock, pkg } = {}) {
  const d = tmp();
  if (mcp) writeFileSync(join(d, '.mcp.json'), JSON.stringify(mcp, null, 2));
  if (pkg) writeFileSync(join(d, 'package.json'), JSON.stringify(pkg, null, 2));
  if (lock) writeFileSync(join(d, 'package-lock.json'), JSON.stringify(lock, null, 2));
  if (src) { mkdirSync(join(d, 'src'), { recursive: true }); writeFileSync(join(d, 'src/index.ts'), src); }
  return d;
}

const skipText = (r) => r.skipped.join('\n');

describe('the model layer is always recorded as not run', () => {
  it('names the rules the CLI cannot apply, on an otherwise empty project', async () => {
    const r = await scanAll(tmp(), { offline: true });
    expect(skipText(r)).toMatch(/model/i);
    for (const id of ['MCP001', 'MCP010', 'MCP021']) {
      expect(skipText(r), `${id} should be named as not run`).toContain(id);
    }
  });

  it('says so even when the deterministic scripts found plenty', async () => {
    const d = project({
      mcp: { mcpServers: { files: { command: 'npx', args: ['@modelcontextprotocol/server-filesystem', '~'] } } },
    });
    const r = await scanAll(d, { offline: true });
    expect(r.findings.length).toBeGreaterThan(0);
    expect(skipText(r)).toMatch(/model/i);
  });

  it('points at the plugin, which is where those rules do run', async () => {
    const r = await scanAll(tmp(), { offline: true });
    expect(skipText(r)).toMatch(/aisec-review/);
  });

  it('exports the list so the docs and the code cannot drift', () => {
    expect(MODEL_ONLY_RULES).toContain('MCP001');
    expect(MODEL_ONLY_RULES).toContain('MCP025');
    expect(MODEL_ONLY_RULES.length).toBeGreaterThan(15);
  });
});

describe('merging', () => {
  it('combines findings from every scanner that had an input', async () => {
    const d = project({
      mcp: { mcpServers: { r: { url: 'http://insecure.example/mcp' } } },
      src: 'const d = "hidden​char";\n',
      pkg: { name: 'x', dependencies: {} },
      lock: { lockfileVersion: 3, packages: { 'node_modules/lodash': { version: '4.17.21' } } },
    });
    const r = await scanAll(d, { offline: true });
    const ids = r.findings.map(f => f.id);
    expect(ids).toContain('REMOTE_HTTP');     // config
    expect(ids).toContain('MCP002');          // unicode
    expect(ids).toContain('TRUST_BOUNDARY');  // lockfile
  });

  it('sorts the merged findings by severity', async () => {
    const d = project({
      mcp: { mcpServers: { files: { command: 'npx', args: ['@modelcontextprotocol/server-filesystem', '~'] } } },
      pkg: { name: 'x', dependencies: {} },
      lock: { lockfileVersion: 3, packages: { 'node_modules/a': { version: '1.0.0' } } },
    });
    const r = await scanAll(d, { offline: true });
    const rank = { HIGH: 0, MED: 1, LOW: 2, WARN: 3 };
    const ranks = r.findings.map(f => rank[f.severity]);
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });

  it('records what each scanner scanned', async () => {
    const d = project({ src: 'const x = 1;\n', pkg: { name: 'x' } });
    const r = await scanAll(d, { offline: true });
    expect(r.scanned.some(p => p.endsWith('index.ts'))).toBe(true);
  });
});

// A missing input is not a clean result. Each scanner must say it had nothing to read.
describe('missing inputs are skipped, never silently clean', () => {
  it('records the absence of an agent config', async () => {
    const r = await scanAll(project({ src: 'const x = 1;\n' }), { offline: true });
    expect(skipText(r)).toMatch(/no agent config|config rules did not run/i);
  });

  it('records the absence of a lockfile', async () => {
    const r = await scanAll(project({ src: 'const x = 1;\n' }), { offline: true });
    expect(skipText(r)).toMatch(/lockfile/i);
  });

  it('records offline mode when it suppressed network checks', async () => {
    const d = project({
      pkg: { name: 'x', dependencies: {} },
      lock: { lockfileVersion: 3, packages: { 'node_modules/a': { version: '1.0.0' } } },
    });
    const r = await scanAll(d, { offline: true });
    expect(skipText(r)).toMatch(/offline/i);
  });
});

describe('report shape', () => {
  it('is the same shape the other tools consume', async () => {
    const r = await scanAll(tmp(), { offline: true });
    expect(Object.keys(r).sort()).toEqual(['findings', 'scanned', 'skipped']);
    expect(Array.isArray(r.findings)).toBe(true);
  });

  it('rejects a target that does not exist rather than reporting it clean', async () => {
    await expect(scanAll('/nope/not/here', { offline: true })).rejects.toThrow(/not.*exist|ENOENT/i);
  });
});
