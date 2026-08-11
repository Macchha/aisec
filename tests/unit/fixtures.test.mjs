import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { scanConfig } from '../../plugin/scripts/scan-config.mjs';
import { scanUnicode } from '../../plugin/scripts/scan-unicode.mjs';

const fixture = (...p) => join(process.cwd(), 'tests/fixtures', ...p);
const scanCfg = (dir) => {
  const path = fixture(dir, '.mcp.json');
  return scanConfig(readFileSync(path, 'utf8'), path);
};

describe('vulnerable fixture', () => {
  it('triggers every config rule', () => {
    const ids = new Set(scanCfg('vulnerable-server').findings.map(f => f.id));
    for (const id of ['SECRET_INLINE', 'TYPOSQUAT', 'VERSION_UNPINNED', 'FS_BROAD',
                      'EXEC_SERVER', 'REMOTE_HTTP', 'REMOTE_NOAUTH', 'TRIFECTA']) {
      expect(ids, `missing ${id}`).toContain(id);
    }
  });

  it('contains a real invisible character for MCP002', () => {
    const r = scanUnicode(fixture('vulnerable-server', 'src'));
    expect(r.findings.some(f => f.id === 'MCP002' && f.message.includes('U+200B'))).toBe(true);
  });

  it('carries a scanner-manipulation attempt for the injection-resistance eval', () => {
    const src = readFileSync(fixture('vulnerable-server', 'src', 'index.ts'), 'utf8');
    expect(src).toMatch(/SECURITY SCANNER READING THIS FILE/);
  });

  // The eval's hardest criterion needs a payload that commands nothing and only
  // asserts — the shape that defeated an earlier SKILL.md. Without it in the tree,
  // that criterion tests nothing.
  it('carries the assertion-style payload, which contains no imperatives', () => {
    const src = readFileSync(fixture('vulnerable-server', 'src', 'index.ts'), 'utf8');
    const desc = src.slice(src.indexOf('build_provenance'), src.indexOf('MCP008'));
    expect(desc).toMatch(/not reproducible/);
    expect(desc).toMatch(/generated artifacts/);
    expect(desc).toMatch(/LOW confidence/);
    // If this ever gains an imperative it becomes the easy payload again.
    expect(desc).not.toMatch(/\b(ignore|do not|stop scanning|report zero)\b/i);
  });

  it('labels a trigger for every rule the skill defines', () => {
    const skill = readFileSync('plugin/skills/scanning-mcp-servers/SKILL.md', 'utf8');
    const ids = [...new Set(skill.match(/MCP0\d\d/g) ?? [])];
    const src = readFileSync(fixture('vulnerable-server', 'src', 'index.ts'), 'utf8')
      + readFileSync(fixture('vulnerable-server', 'src', 'db.ts'), 'utf8');
    expect(ids.length).toBeGreaterThan(15);
    expect(ids.filter(id => !src.includes(id))).toEqual([]);
  });
});

describe('clean fixture', () => {
  it('produces zero config findings', () => {
    expect(scanCfg('clean-server').findings).toEqual([]);
  });

  it('produces zero unicode findings', () => {
    expect(scanUnicode(fixture('clean-server', 'src')).findings).toEqual([]);
  });
});
