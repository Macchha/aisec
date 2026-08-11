import { describe, it, expect } from 'vitest';
import { shannonEntropy, levenshtein } from '../../plugin/scripts/lib/entropy.mjs';
import { scanConfig } from '../../plugin/scripts/scan-config.mjs';

const ids = (r) => r.findings.map(f => f.id);
const scan = (obj) => scanConfig(JSON.stringify(obj, null, 2), '.mcp.json');

describe('entropy helpers', () => {
  it('gives zero entropy for a single repeated character', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
  });

  it('gives 1 bit for two equally frequent characters', () => {
    expect(shannonEntropy('abab')).toBe(1);
  });

  it('computes edit distance', () => {
    expect(levenshtein('kitten', 'sitting')).toBe(3);
    expect(levenshtein('same', 'same')).toBe(0);
  });
});

describe('SECRET_INLINE', () => {
  it('flags a known key pattern and never prints the value', () => {
    const secret = 'sk-ant-abcdefghijklmnopqrstuvwxyz012345';
    const r = scan({ mcpServers: { a: { command: 'npx', args: ['pkg@1.0.0'], env: { KEY: secret } } } });
    const f = r.findings.find(x => x.id === 'SECRET_INLINE');
    expect(f.severity).toBe('HIGH');
    expect(JSON.stringify(r)).not.toContain(secret);
    expect(f.message).toContain('…(39 chars)');
  });

  it('flags a high-entropy value with no known pattern', () => {
    const r = scan({ mcpServers: { a: { command: 'npx', args: ['pkg@1.0.0'],
      env: { TOK: 'Zq7Z4vK2mR9pXw3LtB6nYc1Hd8Fj5Gs0' } } } });
    expect(ids(r)).toContain('SECRET_INLINE');
  });

  it('ignores placeholders and env references', () => {
    const r = scan({ mcpServers: { a: { command: 'npx', args: ['pkg@1.0.0'],
      env: { A: '${MY_TOKEN}', B: '<YOUR_KEY_HERE>', C: 'CHANGEME' } } } });
    expect(ids(r)).not.toContain('SECRET_INLINE');
  });
});

describe('TYPOSQUAT', () => {
  it('flags a near-miss of a known server name', () => {
    const r = scan({ mcpServers: { a: { command: 'npx', args: ['@modelcontextprotocol/server-filesysten@1.0.0'] } } });
    expect(ids(r)).toContain('TYPOSQUAT');
  });

  it('does not flag an exact known name', () => {
    const r = scan({ mcpServers: { a: { command: 'npx', args: ['@modelcontextprotocol/server-filesystem@1.0.0', '/srv/project'] } } });
    expect(ids(r)).not.toContain('TYPOSQUAT');
  });
});

describe('VERSION_UNPINNED', () => {
  it.each(['pkg', 'pkg@latest', 'pkg@^1.0.0', 'pkg@~1.0.0'])('flags %s', (spec) => {
    const r = scan({ mcpServers: { a: { command: 'npx', args: [spec] } } });
    expect(ids(r)).toContain('VERSION_UNPINNED');
  });

  it('does not flag an exact pin', () => {
    const r = scan({ mcpServers: { a: { command: 'npx', args: ['pkg@1.0.0'] } } });
    expect(ids(r)).not.toContain('VERSION_UNPINNED');
  });
});

describe('FS_BROAD', () => {
  it('flags a filesystem server rooted at home', () => {
    const r = scan({ mcpServers: { files: { command: 'npx',
      args: ['@modelcontextprotocol/server-filesystem@1.0.0', '~'] } } });
    expect(ids(r)).toContain('FS_BROAD');
  });

  it('does not flag a scoped project directory', () => {
    const r = scan({ mcpServers: { files: { command: 'npx',
      args: ['@modelcontextprotocol/server-filesystem@1.0.0', '/srv/project'] } } });
    expect(ids(r)).not.toContain('FS_BROAD');
  });
});

describe('EXEC_SERVER', () => {
  it('flags a known exec-capable server', () => {
    const r = scan({ mcpServers: { a: { command: 'npx', args: ['@wonderwhy-er/desktop-commander@1.0.0'] } } });
    const f = r.findings.find(x => x.id === 'EXEC_SERVER');
    expect(f).toBeTruthy();
    expect(f.severity).toBe('MED');
    expect(ids(r)).not.toContain('TRIFECTA');
  });
});

describe('remote transport rules', () => {
  it('flags plaintext http to a non-local host', () => {
    const r = scan({ mcpServers: { r: { url: 'http://evil.example/mcp' } } });
    expect(ids(r)).toContain('REMOTE_HTTP');
    expect(ids(r)).toContain('REMOTE_NOAUTH');
  });

  it('exempts localhost from both remote rules', () => {
    const r = scan({ mcpServers: { r: { url: 'http://127.0.0.1:3000/mcp' } } });
    expect(ids(r)).not.toContain('REMOTE_HTTP');
    expect(ids(r)).not.toContain('REMOTE_NOAUTH');
  });
});

describe('TRIFECTA', () => {
  it('fires when private data, untrusted web, and an exfil channel coexist', () => {
    const r = scan({ mcpServers: {
      files: { command: 'npx', args: ['@modelcontextprotocol/server-filesystem@1.0.0', '/srv/p'] },
      web:   { command: 'npx', args: ['@modelcontextprotocol/server-brave-search@1.0.0'] },
    } });
    const f = r.findings.find(x => x.id === 'TRIFECTA');
    expect(f.severity).toBe('WARN');
  });

  it('does not fire for a filesystem server alone', () => {
    const r = scan({ mcpServers: {
      files: { command: 'npx', args: ['@modelcontextprotocol/server-filesystem@1.0.0', '/srv/p'] },
    } });
    expect(ids(r)).not.toContain('TRIFECTA');
  });
});

describe('report contract', () => {
  it('records the scanned file and marks every finding as rule-sourced', () => {
    const r = scan({ mcpServers: { a: { command: 'npx', args: ['pkg@1.0.0'] } } });
    expect(r.scanned).toContain('.mcp.json');
    expect(r.findings.every(f => f.source === 'rule')).toBe(true);
  });

  it('reports a parse failure as skipped rather than clean', () => {
    const r = scanConfig('{ not json', '.mcp.json');
    expect(r.findings).toEqual([]);
    expect(r.skipped[0]).toMatch(/\.mcp\.json/);
  });

  it('attaches a line number for a server-specific finding', () => {
    const r = scan({ mcpServers: { a: { command: 'npx', args: ['pkg'] } } });
    expect(r.findings.find(f => f.id === 'VERSION_UNPINNED').line).toBeGreaterThan(0);
  });
});

// --- Task 8/11 review follow-ups -------------------------------------------

describe('VERSION_UNPINNED range forms', () => {
  const pinned = (spec) => {
    const cfg = JSON.stringify({ mcpServers: { s: { command: 'npx', args: [spec] } } });
    return scan(JSON.parse(cfg)).findings.some(f => f.id === 'VERSION_UNPINNED');
  };

  // @next and @* are exactly the "whatever the registry serves next run" case the
  // rule exists for, and were silently clean before.
  it('flags dist-tags and wildcard and range specifiers', () => {
    for (const spec of ['@modelcontextprotocol/server-filesystem@next',
                        '@modelcontextprotocol/server-filesystem@*',
                        '@modelcontextprotocol/server-filesystem@1.x',
                        '@modelcontextprotocol/server-filesystem@>=1.0.0',
                        '@modelcontextprotocol/server-filesystem@1.2.x',
                        '@modelcontextprotocol/server-filesystem@^1.0.0',
                        '@modelcontextprotocol/server-filesystem@latest']) {
      expect(pinned(spec), `${spec} should be flagged`).toBe(true);
    }
  });

  it('accepts an exact pin', () => {
    expect(pinned('@modelcontextprotocol/server-filesystem@1.0.0')).toBe(false);
    expect(pinned('@modelcontextprotocol/server-filesystem@1.0.0-rc.1')).toBe(false);
  });
});
