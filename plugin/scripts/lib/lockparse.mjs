export const MAX_DEPS = 2000;
export const LOCKFILE_NAMES = [
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'requirements.txt', 'uv.lock', 'poetry.lock',
];

export class UnsupportedLockfile extends Error {}

// Anchored and linear — no nested quantifiers, no ReDoS on hostile input.
// Extras are matched and discarded: `uvicorn[standard]==0.27.0` is a name pin, not a package
// called `uvicorn[standard]`. `===` is PEP 440 arbitrary equality.
const REQ_LINE_RE = /^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9.*+!_-]+)/;
const YARN_HEADER_RE = /^"?((?:@[^/\s]+\/)?[^@\s"]+)@/;
// `my-alias@npm:minimist@^1.2.0` — the package that actually gets installed is after `npm:`.
const YARN_ALIAS_RE = /@npm:((?:@[^/\s]+\/)?[^@\s"]+)@/;
const YARN_VERSION_RE = /^\s+version\s+"([^"]+)"/;
// pnpm 9/10 single-quotes any key starting with '@', because YAML reserves it. Without the
// optional quotes the name group captures the quote itself and every scoped package is lost.
const PNPM_PKG_RE = /^\s{2,}['"]?\/?((?:@[^/'"\s]+\/)?[^@'"\s]+)@([^:('"\s]+)['"]?[:(]/;
const TOML_NAME_RE = /^name\s*=\s*"([^"]+)"/;
const TOML_VERSION_RE = /^version\s*=\s*"([^"]+)"/;

// Guards against emitting parse debris (a stray quote, a directory path) as a package name.
const NPM_NAME_RE = /^(@[a-z0-9~][a-z0-9-._~]*\/)?[a-z0-9~][a-z0-9-._~]*$/i;

function collector() {
  const out = [];
  const seen = new Set();
  return {
    push(ecosystem, name, version) {
      if (!name || typeof version !== 'string' || !version) return;
      const key = `${ecosystem}/${name}@${version}`;
      if (seen.has(key)) return;
      // Counted before the cap so `total` reflects the real tree, not what fit.
      seen.add(key);
      if (out.length >= MAX_DEPS) return;
      out.push({ ecosystem, name, version });
    },
    get deps() { return out; },
    // seen.size counts every unique dep found; out.length counts those that fit under the cap.
    get total() { return seen.size; },
  };
}

function result(c, format) {
  return { deps: c.deps, format, truncated: c.total > c.deps.length, total: c.total };
}

function parsePackageLock(text) {
  let json;
  try { json = JSON.parse(text); }
  catch { throw new Error('Not valid JSON — is this a package-lock.json?'); }
  const c = collector();

  if (json && typeof json.packages === 'object' && json.packages) {
    for (const [path, info] of Object.entries(json.packages)) {
      if (!path) continue; // the root "" entry is the project itself
      const marker = 'node_modules/';
      const idx = path.lastIndexOf(marker);
      // A key with no node_modules/ segment is a workspace directory — first-party code,
      // not a registry package. Emitting `packages/inner` would invent a dependency.
      if (idx < 0) continue;
      // `info.name` is where npm records the real package behind an `npm:` alias; the install
      // path only holds the alias, and looking the alias up finds nothing. Diverges from
      // vulnrable's lockparse.ts, which has this bug.
      const aliased = typeof info?.name === 'string' && info.name ? info.name : null;
      c.push('npm', aliased ?? path.slice(idx + marker.length), info?.version);
    }
  }
  if (c.deps.length === 0 && json && typeof json.dependencies === 'object' && json.dependencies) {
    const walk = (deps) => {
      for (const [name, info] of Object.entries(deps)) {
        c.push('npm', name, info?.version);
        if (typeof info?.dependencies === 'object' && info.dependencies) walk(info.dependencies);
      }
    };
    walk(json.dependencies);
  }
  return c;
}

function parseYarnLock(text) {
  const c = collector();
  const lines = text.split('\n');
  let pending = null;
  for (const line of lines) {
    if (/^\s/.test(line)) {
      const v = line.match(YARN_VERSION_RE);
      if (v && pending) { c.push('npm', pending, v[1]); pending = null; }
      continue;
    }
    const alias = line.match(YARN_ALIAS_RE);
    const h = line.match(YARN_HEADER_RE);
    pending = alias ? alias[1] : (h ? h[1] : null);
  }
  return c;
}

function parsePnpmLock(text) {
  const c = collector();
  for (const line of text.split('\n')) {
    const m = line.match(PNPM_PKG_RE);
    // Reject debris: a quoted sub-entry or a malformed key can still match shape-wise.
    if (m && NPM_NAME_RE.test(m[1])) c.push('npm', m[1], m[2]);
  }
  return c;
}

function parseRequirements(text) {
  const c = collector();
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const m = line.match(REQ_LINE_RE);
    if (m) c.push('PyPI', m[1], m[2]);
  }
  return c;
}

// uv.lock and poetry.lock are both TOML with [[package]] blocks.
function parseTomlPackages(text) {
  const c = collector();
  let name = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line === '[[package]]') { name = null; continue; }
    if (line.startsWith('[') && line !== '[[package]]') { name = null; continue; }
    const n = line.match(TOML_NAME_RE);
    if (n) { name = n[1]; continue; }
    const v = line.match(TOML_VERSION_RE);
    if (v && name) { c.push('PyPI', name, v[1]); name = null; }
  }
  return c;
}

export function parseLockfile(text, filename) {
  switch (filename) {
    case 'package-lock.json': return result(parsePackageLock(text), 'npm package-lock');
    case 'yarn.lock':         return result(parseYarnLock(text), 'yarn classic lockfile');
    case 'pnpm-lock.yaml':    return result(parsePnpmLock(text), 'pnpm lockfile');
    case 'requirements.txt':  return result(parseRequirements(text), 'pip requirements');
    case 'uv.lock':           return result(parseTomlPackages(text), 'uv lockfile');
    case 'poetry.lock':       return result(parseTomlPackages(text), 'poetry lockfile');
    default:
      throw new UnsupportedLockfile(`unsupported lockfile format: ${filename}`);
  }
}
