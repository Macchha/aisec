import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';

const DIR = 'plugin/skills/scanning-mcp-servers/references';
const read = (f) => readFileSync(`${DIR}/${f}`, 'utf8');

const FILES = {
  'rules-metadata.md':  ['MCP001', 'MCP002', 'MCP003', 'MCP004', 'MCP005'],
  'rules-dataflow.md':  ['MCP010', 'MCP011', 'MCP012', 'MCP013', 'MCP014', 'MCP015'],
  'rules-transport.md': ['MCP020', 'MCP021', 'MCP022', 'MCP023', 'MCP024', 'MCP025'],
  'rules-config.md':    ['SECRET_INLINE', 'TYPOSQUAT', 'VERSION_UNPINNED', 'FS_BROAD',
                         'EXEC_SERVER', 'REMOTE_HTTP', 'REMOTE_NOAUTH', 'TRIFECTA'],
  'rules-sca.md':       ['VULN_KNOWN', 'DEPRECATED', 'PKG_UNKNOWN', 'PKG_NEW',
                         'PKG_LOWDL', 'INSTALL_SCRIPTS', 'NO_REPO', 'STALE', 'TRUST_BOUNDARY'],
};

describe('reference docs', () => {
  it('includes a threat model', () => {
    expect(existsSync(`${DIR}/threat-model.md`)).toBe(true);
    expect(read('threat-model.md').length).toBeGreaterThan(500);
  });

  for (const [file, ids] of Object.entries(FILES)) {
    describe(file, () => {
      it('exists', () => expect(existsSync(`${DIR}/${file}`)).toBe(true));

      it('documents every rule with a heading', () => {
        const body = read(file);
        for (const id of ids) expect(body, `missing ${id}`).toMatch(new RegExp(`^## ${id} — `, 'm'));
      });

      it('gives each rule all six required sections', () => {
        const body = read(file);
        const sections = body.split(/^## /m).slice(1);
        expect(sections).toHaveLength(ids.length);
        for (const s of sections) {
          const title = s.split('\n')[0];
          for (const h of ['**What it is**', '**Why it matters**', '**Vulnerable example**',
                           '**Safe example**', '**Detection**', '**False positives**']) {
            expect(s, `${title} is missing ${h}`).toContain(h);
          }
        }
      });

      it('gives each rule two fenced code examples', () => {
        for (const s of read(file).split(/^## /m).slice(1)) {
          const fences = (s.match(/^```/gm) ?? []).length;
          expect(fences, `${s.split('\n')[0]} needs two fenced blocks`).toBeGreaterThanOrEqual(4);
        }
      });

      it('contains no placeholder text', () => {
        expect(read(file)).not.toMatch(/\bTBD\b|\bTODO\b|to be written/i);
      });
    });
  }
});
