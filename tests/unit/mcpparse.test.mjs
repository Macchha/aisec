import { describe, it, expect } from 'vitest';
import { parseMcpConfig } from '../../plugin/scripts/lib/mcpparse.mjs';
import { capsOf, KNOWN_SERVERS } from '../../plugin/scripts/lib/known-servers.mjs';

const cfg = (obj) => JSON.stringify(obj);

describe('parseMcpConfig', () => {
  it('parses an npx stdio server into a package', () => {
    const [s] = parseMcpConfig(cfg({
      mcpServers: { fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.2.3', '/tmp'] } },
    }));
    expect(s.serverKey).toBe('fs');
    expect(s.kind).toBe('stdio');
    expect(s.pkg).toEqual({ name: '@modelcontextprotocol/server-filesystem', ecosystem: 'npm', version: '1.2.3' });
  });

  it('keeps the scope when splitting a scoped spec without a version', () => {
    const [s] = parseMcpConfig(cfg({ mcpServers: { a: { command: 'npx', args: ['@scope/pkg'] } } }));
    expect(s.pkg).toEqual({ name: '@scope/pkg', ecosystem: 'npm', version: null });
  });

  it('parses uvx as PyPI with == version syntax', () => {
    const [s] = parseMcpConfig(cfg({ mcpServers: { p: { command: 'uvx', args: ['mcp-server-git==0.5.0'] } } }));
    expect(s.pkg).toEqual({ name: 'mcp-server-git', ecosystem: 'PyPI', version: '0.5.0' });
  });

  it('parses python -m module as PyPI', () => {
    const [s] = parseMcpConfig(cfg({ mcpServers: { p: { command: 'python3', args: ['-m', 'mcp_server_git'] } } }));
    expect(s.pkg).toEqual({ name: 'mcp-server-git', ecosystem: 'PyPI', version: null });
  });

  it('skips flags that consume the following token', () => {
    const [s] = parseMcpConfig(cfg({ mcpServers: { a: { command: 'npx', args: ['--registry', 'https://x', 'realpkg'] } } }));
    expect(s.pkg.name).toBe('realpkg');
  });

  it('classifies a url entry as remote and detects auth headers', () => {
    const [s] = parseMcpConfig(cfg({
      mcpServers: { r: { url: 'https://x.example/mcp', headers: { Authorization: 'Bearer t' } } },
    }));
    expect(s.kind).toBe('remote');
    expect(s.hasAuthHeader).toBe(true);
    expect(s.pkg).toBe(null);
  });

  it('accepts the "servers" key as well as "mcpServers"', () => {
    expect(parseMcpConfig(cfg({ servers: { a: { command: 'npx', args: ['p'] } } }))).toHaveLength(1);
  });

  it('rejects invalid JSON', () => {
    expect(() => parseMcpConfig('{nope')).toThrow(/valid JSON/);
  });

  it('rejects a config with no servers object', () => {
    expect(() => parseMcpConfig(cfg({ other: 1 }))).toThrow(/No MCP servers/);
  });

  it('rejects more than 50 servers', () => {
    const many = Object.fromEntries(
      Array.from({ length: 51 }, (_, i) => [`s${i}`, { command: 'npx', args: ['p'] }]));
    expect(() => parseMcpConfig(cfg({ mcpServers: many }))).toThrow(/Too many servers/);
  });
});

describe('capsOf', () => {
  it('uses the known-server capability list on exact match', () => {
    const [s] = parseMcpConfig(cfg({
      mcpServers: { a: { command: 'npx', args: ['@modelcontextprotocol/server-filesystem'] } },
    }));
    expect(capsOf(s)).toEqual(['fs']);
  });

  it('falls back to name heuristics for unknown servers', () => {
    const [s] = parseMcpConfig(cfg({ mcpServers: { myshell: { command: 'npx', args: ['random-exec-thing'] } } }));
    expect(capsOf(s)).toContain('exec');
  });

  it('ships a non-empty known-server list for typosquat comparison', () => {
    expect(KNOWN_SERVERS.length).toBeGreaterThan(20);
    expect(KNOWN_SERVERS.every(k => k.name && k.ecosystem && Array.isArray(k.caps))).toBe(true);
  });
});
