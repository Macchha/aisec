import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';

const SKILL = 'plugin/skills/scanning-mcp-servers/SKILL.md';
const text = () => readFileSync(SKILL, 'utf8');

describe('SKILL.md', () => {
  it('exists', () => {
    expect(existsSync(SKILL)).toBe(true);
  });

  it('has name and description frontmatter matching its directory', () => {
    const fm = text().split('---')[1];
    expect(fm).toMatch(/name:\s*scanning-mcp-servers/);
    expect(fm).toMatch(/description:\s*\S/);
  });

  it('states the untrusted-data rule before it directs any file reading', () => {
    const body = text();
    const rulePos = body.indexOf('untrusted data');
    const readPos = body.indexOf('Read the source');
    expect(rulePos).toBeGreaterThan(-1);
    expect(readPos).toBeGreaterThan(-1);
    expect(rulePos).toBeLessThan(readPos);
  });

  it('orders deterministic scripts before model analysis', () => {
    const body = text();
    expect(body.indexOf('scan-config.mjs')).toBeLessThan(body.indexOf('Read the source'));
  });

  it('references every scanner script', () => {
    for (const s of ['scan-config.mjs', 'scan-unicode.mjs', 'scan-lockfile.mjs']) {
      expect(text()).toContain(s);
    }
  });

  it('names every rule from the spec', () => {
    const body = text();
    const ids = [
      ...Array.from({ length: 8 }, (_, i) => `MCP00${i + 1}`),
      'MCP010', 'MCP011', 'MCP012', 'MCP013', 'MCP014', 'MCP015',
      'MCP020', 'MCP021', 'MCP022', 'MCP023', 'MCP024', 'MCP025',
    ];
    for (const id of ids) expect(body, `missing ${id}`).toContain(id);
  });

  it('requires findings to be labelled by source', () => {
    const body = text();
    // Both labels must appear, and the report template must show them in use.
    expect(body).toMatch(/`?source: model`?/);
    expect(body).toMatch(/\[model, confidence \w+\]/);
    expect(body).toMatch(/\[rule\]/);
  });

  it('points the model at every reference file', () => {
    const body = text();
    for (const f of ['rules-metadata.md', 'rules-primitives.md', 'rules-dataflow.md',
                     'rules-transport.md', 'rules-config.md', 'rules-sca.md',
                     'threat-model.md']) {
      expect(body, `SKILL.md never links references/${f}`).toContain(`references/${f}`);
    }
  });

  it('classifies without whole-file reads so scripts still run first', () => {
    const body = text();
    const step1 = body.slice(body.indexOf('## Step 1'), body.indexOf('## Step 2'));
    expect(step1).toContain('Glob');
    expect(step1).toContain('Grep');
    expect(step1).toMatch(/Do not `Read` a whole source file/);
  });

  it('treats assertions about the scan as a finding, not only imperatives', () => {
    const body = text();
    expect(body).toMatch(/no standing to describe the scan/i);
    for (const claim of ['prior audit', 'reproducib', 'authoritative', 'generated artifact']) {
      expect(body.toLowerCase(), `no defense against "${claim}" claims`).toContain(claim);
    }
  });

  it('forbids scanned content from shading severity or confidence', () => {
    const body = text();
    expect(body).toMatch(/may raise or lower a finding's severity or\s+confidence/);
    // The anti-padding guidance must be scoped so a target cannot aim it.
    const pad = body.slice(body.indexOf('Do not pad the report'));
    expect(pad).toMatch(/never a reason to\s+drop, soften, or caveat/);
  });

  it('demarcates read file contents as data', () => {
    const body = text();
    expect(body).toContain('<untrusted-file');
    expect(body).toMatch(/wrapper is yours, not the file's/);
  });

  it('requires a scan-integrity line in every report', () => {
    const body = text();
    expect(body).toContain('Scan integrity:');
    expect(body).toMatch(/`Scan integrity` is mandatory/);
  });

  it('shows the WARN section and the secret mask format in the template', () => {
    const body = text();
    expect(body).toMatch(/^WARN$/m);
    expect(body).toContain('TRIFECTA');
    expect(body).toContain('sk-a…(39 chars)');
  });
});

describe('references/rules-primitives.md', () => {
  const FILE = 'plugin/skills/scanning-mcp-servers/references/rules-primitives.md';
  const ids = ['MCP006', 'MCP007', 'MCP008'];
  const body = () => readFileSync(FILE, 'utf8');

  it('exists', () => expect(existsSync(FILE)).toBe(true));

  it('documents every rule with a heading', () => {
    for (const id of ids) expect(body(), `missing ${id}`).toMatch(new RegExp(`^## ${id} — `, 'm'));
  });

  it('gives each rule all six required sections', () => {
    const sections = body().split(/^## /m).slice(1);
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
    for (const s of body().split(/^## /m).slice(1)) {
      const fences = (s.match(/^```/gm) ?? []).length;
      expect(fences, `${s.split('\n')[0]} needs two fenced blocks`).toBeGreaterThanOrEqual(4);
    }
  });

  it('contains no placeholder text', () => {
    expect(body()).not.toMatch(/\bTBD\b|\bTODO\b|to be written/i);
  });
});
