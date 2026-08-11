#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { isMainModule } from './lib/cli.mjs';
import { finding, mask, lineOfKey, emptyReport, sortFindings } from './lib/findings.mjs';
import { parseMcpConfig } from './lib/mcpparse.mjs';
import { KNOWN_SERVERS, capsOf } from './lib/known-servers.mjs';
import { shannonEntropy, levenshtein } from './lib/entropy.mjs';

const SECRET_PATTERNS = [
  { re: /^sk-ant-[A-Za-z0-9_-]{20,}$/, what: 'Anthropic API key' },
  { re: /^sk-[A-Za-z0-9_-]{20,}$/, what: 'OpenAI-style API key' },
  { re: /^(ghp|gho|ghu|ghs)_[A-Za-z0-9]{36,}$/, what: 'GitHub token' },
  { re: /^github_pat_[A-Za-z0-9_]{22,}$/, what: 'GitHub fine-grained token' },
  { re: /^AKIA[0-9A-Z]{16}$/, what: 'AWS access key ID' },
  { re: /^xox[baprs]-[A-Za-z0-9-]{10,}$/, what: 'Slack token' },
  { re: /^AIza[0-9A-Za-z_-]{35}$/, what: 'Google API key' },
];
const PLACEHOLDER_RE = /^\$|^<|YOUR|CHANGE|EXAMPLE|XXXX/i;
// An exact pin only: major.minor.patch with an optional prerelease/build suffix.
const EXACT_VERSION_RE = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const BROAD_ROOTS = new Set(['/', '~', '$HOME', '/Users', '/home', 'C:\\', 'C:/']);

export function scanConfig(text, filePath) {
  const report = emptyReport();
  let servers;
  try {
    servers = parseMcpConfig(text);
  } catch (err) {
    report.skipped.push(`${filePath}: config rules skipped — ${err.message}`);
    return report;
  }
  report.scanned.push(filePath);

  const at = (key) => lineOfKey(text, key);
  const add = (o) => report.findings.push(finding({ file: filePath, ...o }));
  const allCaps = new Set();

  for (const s of servers) {
    capsOf(s).forEach(c => allCaps.add(c));
    const line = at(s.serverKey);

    for (const [k, v] of Object.entries(s.env)) {
      if (!v || PLACEHOLDER_RE.test(v)) continue;
      const hit = SECRET_PATTERNS.find(p => p.re.test(v));
      if (hit) {
        add({ id: 'SECRET_INLINE', severity: 'HIGH', line,
          message: `env ${k} contains a ${hit.what} in plaintext (${mask(v)})`,
          hint: 'Move the value to an OS keychain / env manager and reference it as ${VAR}.' });
      } else if (v.length >= 24 && !v.includes(' ') && shannonEntropy(v) >= 4.2) {
        add({ id: 'SECRET_INLINE', severity: 'HIGH', line,
          message: `env ${k} looks like a hardcoded secret (high entropy, ${mask(v)})`,
          hint: 'Move the value to an OS keychain / env manager and reference it as ${VAR}.' });
      }
    }

    if (s.pkg) {
      const { name, ecosystem, version } = s.pkg;
      const exact = KNOWN_SERVERS.some(k => k.name === name && k.ecosystem === ecosystem);
      if (!exact) {
        const near = KNOWN_SERVERS.find(k =>
          k.ecosystem === ecosystem && Math.abs(k.name.length - name.length) <= 2 && levenshtein(k.name, name) <= 2);
        if (near) {
          add({ id: 'TYPOSQUAT', severity: 'HIGH', line,
            message: `"${name}" is suspiciously close to a well-known server name`,
            hint: `Did you mean ${near.name}? Typosquatted MCP packages can execute arbitrary code.` });
        }
      }
      // Anything that is not an exact version resolves to whatever the registry
      // serves at launch. Dist-tags (`next`, `latest`), wildcards (`*`, `1.x`) and
      // comparator ranges (`>=1.0.0`) are all that case, not just ^ and ~.
      if (!version || !EXACT_VERSION_RE.test(version)) {
        add({ id: 'VERSION_UNPINNED', severity: 'MED', line,
          message: `${name} runs without an exact pinned version`,
          hint: `Pin it, e.g. ${name}@1.2.3 — unpinned npx/uvx executes whatever the registry serves next run.` });
      }
      if (capsOf(s).includes('fs') && s.args.some(a => BROAD_ROOTS.has(a))) {
        add({ id: 'FS_BROAD', severity: 'HIGH', line,
          message: `filesystem server rooted at a broad path (${s.args.find(a => BROAD_ROOTS.has(a))})`,
          hint: 'Scope it to a project directory instead of / or your home directory.' });
      }
      if (capsOf(s).includes('exec')) {
        add({ id: 'EXEC_SERVER', severity: 'MED', line,
          message: `${name} can execute commands / drive a browser`,
          hint: 'Exec-capable servers turn any prompt injection into code execution. Remove if unused.' });
      }
    }

    if (s.kind === 'remote' && s.url) {
      let host = '';
      try { host = new URL(s.url).hostname; } catch { /* unparseable → still flagged below */ }
      const local = host === 'localhost' || host === '127.0.0.1' || host === '::1';
      if (s.url.startsWith('http://') && !local) {
        add({ id: 'REMOTE_HTTP', severity: 'HIGH', line,
          message: `remote MCP server over unencrypted http:// (${host || s.url})`,
          hint: 'Use https:// — tool calls and results are readable/modifiable on the wire.' });
      }
      if (!s.hasAuthHeader && !local) {
        add({ id: 'REMOTE_NOAUTH', severity: 'MED', line,
          message: 'remote MCP server configured without an auth header',
          hint: 'Add an Authorization header unless the server is intentionally public.' });
      }
    }
  }

  const hasPrivate = allCaps.has('fs') || allCaps.has('data') || allCaps.has('msg');
  const hasUntrusted = allCaps.has('fetch');
  const hasExfil = allCaps.has('fetch') || allCaps.has('exec') || allCaps.has('msg');
  if (hasPrivate && hasUntrusted && hasExfil) {
    add({ id: 'TRIFECTA', severity: 'WARN', line: null,
      message: 'Config combines private-data access, untrusted web content, and an exfiltration channel',
      hint: 'The "lethal trifecta": injected web content can read private data and send it out. Consider separate profiles.' });
  }

  report.findings = sortFindings(report.findings);
  return report;
}

// Names an agent config actually goes by. `/aisec-review` receives a project
// directory, so a scanner that only accepted a file path exited 2 and dropped
// every config rule into skipped[] — honest, but a total loss of the layer.
export const CONFIG_NAMES = [
  '.mcp.json', 'claude_desktop_config.json', 'mcp.json', '.vscode/mcp.json',
];

export function discoverConfigs(root) {
  const out = [];
  for (const name of CONFIG_NAMES) {
    const p = join(root, name);
    try { if (statSync(p).isFile()) out.push(p); } catch { /* absent */ }
  }
  return out;
}

function main() {
  const path = process.argv[2];
  if (!path) { console.error('usage: scan-config.mjs <config-path-or-project-dir>'); process.exit(2); }

  let isDir = false;
  try { isDir = statSync(path).isDirectory(); }
  catch (err) { console.error(`cannot read ${path}: ${err.message}`); process.exit(2); }

  if (!isDir) {
    let text;
    try { text = readFileSync(path, 'utf8'); }
    catch (err) { console.error(`cannot read ${path}: ${err.message}`); process.exit(2); }
    console.log(JSON.stringify(scanConfig(text, path), null, 2));
    return;
  }

  const found = discoverConfigs(path);
  const merged = emptyReport();
  if (found.length === 0) {
    // Not a clean result: there was nothing to check, and the report says so.
    merged.skipped.push(`${path}: no agent config found (looked for ${CONFIG_NAMES.join(', ')}) — config rules did not run`);
  }
  for (const file of found) {
    let text;
    try { text = readFileSync(file, 'utf8'); }
    catch (err) { merged.skipped.push(`${file}: config rules skipped — ${err.message}`); continue; }
    const r = scanConfig(text, file);
    merged.findings.push(...r.findings);
    merged.scanned.push(...r.scanned);
    merged.skipped.push(...r.skipped);
  }
  merged.findings = sortFindings(merged.findings);
  console.log(JSON.stringify(merged, null, 2));
}

if (isMainModule(import.meta.url)) main();
