// Ported from vulnrable/src/lib/mcpparse.ts (TS types stripped).
//
// McpServerEntry = {
//   serverKey: string,
//   kind: 'stdio' | 'remote',
//   command: string | null,
//   args: string[],
//   env: Record<string, string>, // stays in browser; never transmitted
//   url: string | null,
//   hasAuthHeader: boolean,
//   pkg: { name: string, ecosystem: 'npm' | 'PyPI', version: string | null } | null,
// }

export const MAX_CONFIG_BYTES = 262_144; // 256 KB
export const MAX_SERVERS = 50;
const MAX_ARGS = 100;

const NPM_RUNNERS = new Set(['npx', 'bunx', 'pnpx']);

// '@scope/pkg@1.2.3' -> name/version; lastIndexOf('@') > 0 keeps the scope '@'.
function splitSpec(spec) {
  if (spec.includes('==')) {
    const [name, version] = spec.split('==');
    return { name, version: version || null };
  }
  const at = spec.lastIndexOf('@');
  if (at > 0) return { name: spec.slice(0, at), version: spec.slice(at + 1) || null };
  return { name: spec, version: null };
}

function firstPositional(args) {
  const valueConsumingFlags = new Set(['--prefix', '--registry', '--cache', '--userconfig', '--loglevel', '--node-options', '--call', '-c', '--shell']);

  for (let i = 0; i < args.length; i++) {
    const a = args[i];

    // Check if this is a -p or --package flag; treat next token as package spec
    if (a === '-p' || a === '--package') {
      return args[i + 1] ?? null;
    }

    // Skip flags and their values
    if (a.startsWith('-')) {
      // If this flag consumes the next token as its value, skip it
      if (valueConsumingFlags.has(a)) {
        i++; // Skip the next token (the flag's value)
      }
      continue;
    }

    // Found a positional argument
    return a;
  }

  return null;
}

function extractPkg(command, args) {
  if (!command) return null;
  const base = command.split(/[\\/]/).pop() ?? command;
  if (NPM_RUNNERS.has(base)) {
    const spec = firstPositional(args);
    if (!spec) return null;
    const { name, version } = splitSpec(spec);
    return { name, ecosystem: 'npm', version };
  }
  if (base === 'uvx') {
    const spec = firstPositional(args);
    if (!spec) return null;
    const { name, version } = splitSpec(spec);
    return { name, ecosystem: 'PyPI', version };
  }
  if (base === 'python' || base === 'python3') {
    const i = args.indexOf('-m');
    if (i >= 0 && typeof args[i + 1] === 'string') {
      return { name: args[i + 1].replace(/_/g, '-'), ecosystem: 'PyPI', version: null };
    }
  }
  return null;
}

export function parseMcpConfig(text) {
  if (new TextEncoder().encode(text).length > MAX_CONFIG_BYTES) throw new Error('Config too large (max 256 KB).');
  let json;
  try { json = JSON.parse(text); } catch {
    throw new Error('Not valid JSON — expected .mcp.json or claude_desktop_config.json.');
  }
  const map = (json && typeof json === 'object' && (json.mcpServers ?? json.servers)) || null;
  if (!map || typeof map !== 'object' || Array.isArray(map)) {
    throw new Error('No MCP servers found — expected an "mcpServers" object.');
  }
  const keys = Object.keys(map);
  if (keys.length === 0) throw new Error('No MCP servers found — "mcpServers" is empty.');
  if (keys.length > MAX_SERVERS) throw new Error(`Too many servers (max ${MAX_SERVERS}).`);

  return keys.map(serverKey => {
    const raw = map[serverKey] ?? {};
    const url = typeof raw.url === 'string' ? raw.url : null;
    const command = typeof raw.command === 'string' ? raw.command : null;
    const args = Array.isArray(raw.args)
      ? raw.args.slice(0, MAX_ARGS).filter((a) => typeof a === 'string')
      : [];
    const env = {};
    if (raw.env && typeof raw.env === 'object' && !Array.isArray(raw.env)) {
      for (const [k, v] of Object.entries(raw.env)) if (typeof v === 'string') env[k] = v;
    }
    const headers = raw.headers && typeof raw.headers === 'object' ? Object.keys(raw.headers) : [];
    return {
      serverKey,
      kind: url ? 'remote' : 'stdio',
      command,
      args,
      env,
      url,
      hasAuthHeader: headers.some(h => /auth/i.test(h) || /^x-api-key$/i.test(h)),
      pkg: url ? null : extractPkg(command, args),
    };
  });
}
