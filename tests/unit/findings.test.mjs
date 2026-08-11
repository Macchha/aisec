import { describe, it, expect } from 'vitest';
import { finding, sortFindings, emptyReport, mask, lineOf, lineOfKey } from '../../plugin/scripts/lib/findings.mjs';

describe('finding', () => {
  it('builds a finding with defaults', () => {
    const f = finding({ id: 'MCP001', severity: 'HIGH', file: 'a.ts', message: 'm', hint: 'h' });
    expect(f).toEqual({
      id: 'MCP001', severity: 'HIGH', confidence: 'HIGH', source: 'rule',
      file: 'a.ts', line: null, message: 'm', hint: 'h',
    });
  });

  it('rejects an unknown severity', () => {
    expect(() => finding({ id: 'X', severity: 'SPICY', file: 'a', message: 'm', hint: 'h' }))
      .toThrow(/severity/);
  });

  it('rejects an unknown source', () => {
    expect(() => finding({ id: 'X', severity: 'LOW', source: 'vibes', file: 'a', message: 'm', hint: 'h' }))
      .toThrow(/source/);
  });
});

describe('sortFindings', () => {
  it('orders by severity then confidence', () => {
    const mk = (id, severity, confidence) =>
      finding({ id, severity, confidence, file: 'a', message: 'm', hint: 'h' });
    const sorted = sortFindings([
      mk('d', 'WARN', 'HIGH'), mk('c', 'LOW', 'HIGH'),
      mk('b', 'HIGH', 'LOW'), mk('a', 'HIGH', 'HIGH'),
    ]);
    expect(sorted.map(f => f.id)).toEqual(['a', 'b', 'c', 'd']);
  });

  it('does not mutate its input', () => {
    const list = [
      finding({ id: 'z', severity: 'LOW', file: 'a', message: 'm', hint: 'h' }),
      finding({ id: 'y', severity: 'HIGH', file: 'a', message: 'm', hint: 'h' }),
    ];
    sortFindings(list);
    expect(list[0].id).toBe('z');
  });
});

describe('mask', () => {
  it('shows only the first four characters and the length', () => {
    expect(mask('sk-ant-abcdefghijklmnop')).toBe('sk-a…(23 chars)');
  });

  it('does not leak short values', () => {
    expect(mask('ab')).toBe('…(2 chars)');
  });
});

describe('lineOf', () => {
  it('returns the 1-indexed line containing the needle', () => {
    expect(lineOf('alpha\nbeta\ngamma', 'beta')).toBe(2);
  });

  it('returns null when absent', () => {
    expect(lineOf('alpha\nbeta', 'delta')).toBe(null);
  });
});

describe('emptyReport', () => {
  it('starts with three empty arrays', () => {
    expect(emptyReport()).toEqual({ findings: [], scanned: [], skipped: [] });
  });
});

// --- deferred minors from the review rounds --------------------------------

describe('finding() validates confidence', () => {
  it('rejects a confidence outside the enum', () => {
    expect(() => finding({
      id: 'X', severity: 'HIGH', confidence: 'PRETTY_SURE',
      file: 'a.ts', message: 'm', hint: 'h',
    })).toThrow(/bad confidence/);
  });
});

describe('lineOfKey', () => {
  const cfg = [
    '{',
    '  "mcpServers": {',
    '    "a": {',
    '      "command": "npx",',
    '      "args": ["pkg"]',
    '    }',
    '  }',
    '}',
  ].join('\n');

  // lineOf(text, '"a"') matches line 5, inside "args" — the old behaviour.
  it('finds the property line, not the first quoted substring', () => {
    expect(lineOfKey(cfg, 'a')).toBe(3);
  });

  it('tolerates whitespace before the colon', () => {
    expect(lineOfKey('{\n  "db" : 1\n}', 'db')).toBe(2);
  });

  it('returns null when the key is absent', () => {
    expect(lineOfKey(cfg, 'nope')).toBe(null);
  });

  it('escapes regex metacharacters in the key', () => {
    expect(lineOfKey('{\n  "a.b+c": 1\n}', 'a.b+c')).toBe(2);
    expect(lineOfKey('{\n  "axbxc": 1\n}', 'a.b+c')).toBe(null);
  });
});
