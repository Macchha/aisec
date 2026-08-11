import { describe, it, expect } from 'vitest';
import { scanTextForInvisibles, describeCodepoint } from '../../plugin/scripts/scan-unicode.mjs';

describe('scanTextForInvisibles', () => {
  it('flags a zero-width space inside a description', () => {
    const src = 'const d = "safe\u200Btool";';
    const [f] = scanTextForInvisibles(src, 'a.ts');
    expect(f.id).toBe('MCP002');
    expect(f.severity).toBe('HIGH');
    expect(f.line).toBe(1);
    expect(f.message).toContain('U+200B');
  });

  it('flags Unicode tag-block characters used to hide instructions', () => {
    const src = 'x\n"tool\u{E0041}\u{E0042}"';
    const found = scanTextForInvisibles(src, 'a.ts');
    expect(found).toHaveLength(1);
    expect(found[0].line).toBe(2);
    expect(found[0].message).toContain('U+E0041');
  });

  it('flags bidirectional override characters', () => {
    const found = scanTextForInvisibles('a\u202Eb', 'a.ts');
    expect(found[0].message).toContain('U+202E');
  });

  it('reports one finding per line, listing every codepoint on it', () => {
    const found = scanTextForInvisibles('a\u200Bb\u200Cc', 'a.ts');
    expect(found).toHaveLength(1);
    expect(found[0].message).toContain('U+200B');
    expect(found[0].message).toContain('U+200C');
  });

  it('flags the Arabic letter mark, a bidi control', () => {
    const found = scanTextForInvisibles('a\u061Cb', 'a.ts');
    expect(found).toHaveLength(1);
    expect(found[0].id).toBe('MCP002');
    expect(found[0].severity).toBe('HIGH');
    expect(found[0].message).toContain('U+061C');
  });

  it('flags Hangul fillers and deprecated format controls', () => {
    const found = scanTextForInvisibles('a\u3164b\u115Fc\u206Ad', 'a.ts');
    expect(found).toHaveLength(1);
    expect(found[0].message).toContain('U+3164');
    expect(found[0].message).toContain('U+115F');
    expect(found[0].message).toContain('U+206A');
  });

  it('returns nothing for ordinary source', () => {
    expect(scanTextForInvisibles('const x = "hello world";\n', 'a.ts')).toEqual([]);
  });

  it('does not flag ordinary whitespace or newlines', () => {
    expect(scanTextForInvisibles('a\tb \n c\r\n', 'a.ts')).toEqual([]);
  });
});

describe('variation selectors', () => {
  it('does not flag a single variation selector on an ordinary emoji', () => {
    expect(scanTextForInvisibles('status: \u2764\uFE0F done', 'a.md')).toEqual([]);
  });

  it('flags a run of consecutive variation selectors as smuggled data', () => {
    const found = scanTextForInvisibles('x\uFE0F\uFE0F\uFE0F', 'a.md');
    expect(found).toHaveLength(1);
    expect(found[0].id).toBe('MCP002');
    expect(found[0].severity).toBe('HIGH');
    expect(found[0].line).toBe(1);
    expect(found[0].message).toContain('3');
  });
});

describe('describeCodepoint', () => {
  it('names known offenders', () => {
    expect(describeCodepoint(0x200b)).toMatch(/zero.width/i);
    expect(describeCodepoint(0x202e)).toMatch(/bidi|override/i);
  });

  it('falls back to a generic label', () => {
    expect(describeCodepoint(0xe0041)).toMatch(/tag/i);
  });

  it('labels variation selectors in both ranges', () => {
    expect(describeCodepoint(0xfe0f)).toMatch(/variation selector/i);
    expect(describeCodepoint(0xe0100)).toMatch(/variation selector/i);
  });
});

// --- Task 9/10 review follow-ups -------------------------------------------

describe('codepoint set edge cases', () => {
  it('matches U+2065, which the documented U+2060-206F range implies', () => {
    expect(scanTextForInvisibles('a\u2065b', 'a.ts')).toHaveLength(1);
  });

  // A BOM at offset 0 is an encoding artifact, not a hidden instruction. Reporting
  // it HIGH/HIGH made the docs tell readers to dismiss a maximum-severity finding.
  it('does not flag a byte order mark at the very start of a file', () => {
    expect(scanTextForInvisibles('\uFEFFconst x = 1;\n', 'a.ts')).toEqual([]);
  });

  it('still flags a U+FEFF anywhere other than offset 0', () => {
    expect(scanTextForInvisibles('const x = 1;\nlet y\uFEFF = 2;\n', 'a.ts')).toHaveLength(1);
    expect(scanTextForInvisibles('const\uFEFF x = 1;\n', 'a.ts')).toHaveLength(1);
  });
});
