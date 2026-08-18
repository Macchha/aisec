#!/usr/bin/env node
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { isMainModule } from './lib/cli.mjs';
import { finding, emptyReport, sortFindings } from './lib/findings.mjs';
import { parseLockfile, UnsupportedLockfile, LOCKFILE_NAMES } from './lib/lockparse.mjs';
import { queryBatch, fetchVulnDetail, depKey } from './lib/osv.mjs';
import { lookupPackage } from './lib/registry.mjs';

const DAY = 86_400_000;
const MAX_DIRECT_LOOKUPS = 25;
// Advisory detail is one HTTP round trip per unique advisory id, each with a 10s timeout.
// Unbounded and serial, a stale 2000-package tree is tens of minutes of silence, so the
// stage is capped, run with bounded concurrency, and abandoned at a deadline. Everything
// dropped by any of the three is recorded in skipped[] — the finding itself is never lost,
// only its description and ranked severity.
const MAX_ADVISORY_DETAILS = 100;
const ADVISORY_CONCURRENCY = 5;
const ADVISORY_DEADLINE_MS = 60_000;

// Why a rule could not be applied to a package, for the skipped[] line. Both rules read
// npm-only fields, so every PyPI dependency lands here — and an npm dependency does too
// whenever the registry withheld the data.
const UNCHECKED_REASON = {
  PKG_LOWDL: 'download counts are published by npm only, and the npm downloads API is ' +
    'best-effort — no popularity signal was available',
  INSTALL_SCRIPTS: 'install-time hooks are read from npm version manifests only — ' +
    'a PyPI sdist can still execute code at install time via setup.py',
};

// Long dependency lists get truncated, but the count above is always exact.
const MAX_NAMES_LISTED = 10;
function nameList(names) {
  if (names.length <= MAX_NAMES_LISTED) return names.join(', ');
  return `${names.slice(0, MAX_NAMES_LISTED).join(', ')} and ${names.length - MAX_NAMES_LISTED} more`;
}

// UNKNOWN maps to MED, not LOW: an advisory we could not rank is unranked, not harmless.
// Mapping it down is the same silent-narrowing bug the queryBatch review caught.
const VULN_SEV = { CRITICAL: 'HIGH', HIGH: 'HIGH', MODERATE: 'MED', MEDIUM: 'MED', LOW: 'LOW', UNKNOWN: 'MED' };

// Lockfiles we cannot parse but must not pretend we did not see. The regex catches the
// `*.lock` / `*-lock.json` family; these four are named because they match no pattern.
const EXTRA_LOCKFILE_NAMES = new Set(['bun.lockb', 'bun.lock', 'go.sum', 'go.mod', 'gradle.lockfile']);
const LOCKFILE_SHAPE_RE = /\.lock$|-lock\.(json|yaml)$/;

// PEP 508: the requirement name is the leading run before any extras, specifier or marker.
const PEP508_NAME_RE = /^([A-Za-z0-9][A-Za-z0-9._-]*)/;

/** Run `fn` over `items` with at most `limit` in flight, stopping once `deadline` passes. */
async function mapBounded(items, limit, deadline, fn) {
  let next = 0;
  let abandoned = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      if (Date.now() >= deadline) { abandoned += items.length - i; next = items.length; return; }
      await fn(items[i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return abandoned;
}

export async function scanDependencies({
  lockfiles = [], directDeps = [], offline = false, lookup = lookupPackage,
  scanned = [], skipped = [],
} = {}) {
  const report = emptyReport();
  report.scanned.push(...scanned);
  report.skipped.push(...skipped);
  const add = (o) => report.findings.push(finding(o));

  // ---- 1. Parse lockfiles into a transitive dependency set.
  const deps = [];
  for (const lf of lockfiles) {
    try {
      const { deps: parsed, format, truncated, total } = parseLockfile(lf.text, lf.name);
      report.scanned.push(lf.path);
      deps.push(...parsed);
      if (truncated) {
        report.skipped.push(
          `${lf.path}: only the first ${parsed.length} of ${total} packages were scanned — ` +
          `the remainder were not checked for vulnerabilities`);
      }
      // A parse that understood nothing is not a clean tree. `requirements.txt` with only
      // `>=` pins, or a yarn Berry lockfile read by the classic parser, both return zero
      // deps as a *successful* parse — which would otherwise report a complete scan of a
      // tree that was never read.
      if (parsed.length === 0 && String(lf.text ?? '').trim() !== '') {
        report.skipped.push(
          `${lf.path}: parsed as ${format} but no packages were recognized — ` +
          `this dependency tree was not checked for vulnerabilities ` +
          `(unsupported dialect or an unpinned/unsupported specifier syntax)`);
      }
      add({ id: 'TRUST_BOUNDARY', severity: 'LOW', confidence: 'HIGH', file: lf.path, line: null,
        message: `${parsed.length} packages in the trust boundary (${format})`,
        hint: 'Every package here runs with the same privileges as the server itself.' });
    } catch (err) {
      const why = err instanceof UnsupportedLockfile ? err.message : `parse failed — ${err.message}`;
      report.skipped.push(`${lf.path}: dependency scan skipped — ${why}`);
    }
  }
  if (lockfiles.length === 0) {
    report.skipped.push(directDeps.length > 0
      ? 'no lockfile found — transitive dependencies were not scanned; direct dependencies only'
      : 'no lockfile and no direct dependencies — no dependency tree was scanned at all');
  }

  // Deps are deduplicated across lockfiles: a monorepo listing lodash@4.17.15 in three
  // lockfiles must not triple the apparent severity of one advisory.
  const uniqueDeps = [];
  const seenDeps = new Set();
  for (const d of deps) {
    const k = depKey(d);
    if (seenDeps.has(k)) continue;
    seenDeps.add(k);
    uniqueDeps.push(d);
  }

  // ---- 2. Vulnerability lookup over the full tree.
  if (uniqueDeps.length > 0) {
    if (offline) {
      report.skipped.push(`vulnerability lookup skipped for ${uniqueDeps.length} packages — offline mode`);
    } else {
      try {
        const { map: vulnMap, unknown, errors } = await queryBatch(uniqueDeps);
        // Deps OSV never answered for are not clean — they are unchecked, and say so.
        if (unknown.size > 0) {
          const why = errors.length ? ` (${[...new Set(errors)].join('; ')})` : '';
          report.skipped.push(
            `vulnerability lookup incomplete for ${unknown.size} package(s) — no answer from OSV${why}: ` +
            `${[...unknown].slice(0, 5).join(', ')}${unknown.size > 5 ? `, +${unknown.size - 5} more` : ''}`);
        }

        // id -> the dep keys it was reported against, so a failed detail fetch can name the
        // affected packages instead of emitting an opaque advisory id.
        const affected = new Map();
        for (const [key, idList] of vulnMap) {
          for (const id of idList) {
            if (!affected.has(id)) affected.set(id, []);
            affected.get(id).push(key);
          }
        }
        const pkgsFor = (id) => {
          const list = affected.get(id) ?? [];
          return list.slice(0, 3).join(', ') + (list.length > 3 ? `, +${list.length - 3} more` : '');
        };

        const allIds = [...affected.keys()];
        const targetIds = allIds.slice(0, MAX_ADVISORY_DETAILS);
        if (allIds.length > targetIds.length) {
          report.skipped.push(
            `advisory detail lookup limited to the first ${MAX_ADVISORY_DETAILS} of ${allIds.length} advisories — ` +
            `the remaining ${allIds.length - targetIds.length} are still reported against their packages, ` +
            `but with an unranked severity and no summary`);
        }

        const details = new Map();
        const failures = [];
        const abandoned = await mapBounded(
          targetIds, ADVISORY_CONCURRENCY, Date.now() + ADVISORY_DEADLINE_MS,
          async (id) => {
            try { details.set(id, await fetchVulnDetail(id)); }
            catch (err) { failures.push(`${id} (affects ${pkgsFor(id)}): ${err?.message ?? String(err)}`); }
          });
        if (failures.length > 0) {
          report.skipped.push(
            `advisory detail unavailable for ${failures.length} advisory/advisories — ` +
            `reported with an unranked severity: ${failures.slice(0, 5).join('; ')}` +
            `${failures.length > 5 ? `, +${failures.length - 5} more` : ''}`);
        }
        if (abandoned > 0) {
          report.skipped.push(
            `advisory detail lookup stopped after ${ADVISORY_DEADLINE_MS / 1000}s — ` +
            `${abandoned} advisory/advisories were not described and are reported with an unranked severity`);
        }

        for (const dep of uniqueDeps) {
          const key = depKey(dep);
          // A paginated answer lands in both `map` and `unknown`: keep the advisories we
          // did get (the incompleteness is already recorded above), and only drop the dep
          // when there is no answer at all.
          if (unknown.has(key) && !vulnMap.has(key)) continue;
          for (const id of vulnMap.get(key) ?? []) {
            const d = details.get(id);
            const label = d?.cveId ? `${d.cveId} (${id})` : id;
            const summary = d
              ? (d.summary || 'known vulnerability')
              : 'known vulnerability — advisory detail could not be retrieved, severity unranked';
            add({ id: 'VULN_KNOWN', severity: d ? (VULN_SEV[d.severity] ?? 'MED') : 'MED',
              confidence: d ? 'HIGH' : 'MED', file: dep.name, line: null,
              message: `${dep.name}@${dep.version} — ${label}: ${summary}`,
              hint: `See https://osv.dev/vulnerability/${id}` });
          }
        }
      } catch (err) {
        report.skipped.push(`vulnerability lookup skipped — ${err.message}`);
      }
    }
  }

  // ---- 3. Registry metadata checks on direct dependencies.
  if (directDeps.length === 0 && skipped.length === 0) {
    report.skipped.push(
      'no direct dependencies were supplied — registry metadata checks ' +
      '(PKG_UNKNOWN, DEPRECATED, PKG_NEW, PKG_LOWDL, INSTALL_SCRIPTS, NO_REPO, STALE) did not run');
  }
  if (directDeps.length > 0 && offline) {
    report.skipped.push(`registry metadata checks skipped for ${directDeps.length} packages — offline mode`);
  } else {
    // Per-rule gaps, accumulated across packages so the report carries one line per rule
    // rather than one per dependency.
    const unchecked = { PKG_LOWDL: [], INSTALL_SCRIPTS: [] };
    const targets = directDeps.slice(0, MAX_DIRECT_LOOKUPS);
    if (directDeps.length > targets.length) {
      report.skipped.push(
        `registry metadata checks limited to the first ${MAX_DIRECT_LOOKUPS} of ${directDeps.length} ` +
        `direct dependencies — ${directDeps.length - targets.length} were not checked`);
    }
    for (const d of targets) {
      let meta;
      try { meta = await lookup(d.name, d.ecosystem); }
      catch (err) { report.skipped.push(`${d.name}: registry lookup failed — ${err.message}`); continue; }

      if (meta.lookupError) {
        report.skipped.push(`${d.name}: registry lookup failed — no metadata checks were applied`);
        continue;
      }
      const file = d.name;
      if (!meta.found) {
        // A scoped name that does not resolve on the public registry is, far more often
        // than not, an internal package on a private registry. Same severity, lower
        // confidence, so a private-registry org is not buried in HIGH/HIGH findings.
        const scoped = typeof d.name === 'string' && d.name.startsWith('@');
        add({ id: 'PKG_UNKNOWN', severity: 'HIGH', confidence: scoped ? 'MED' : 'HIGH', file, line: null,
          message: `${d.name} not found on ${d.ecosystem}`,
          hint: scoped
            ? 'Unresolvable scoped package — usually an internal package on a private registry, ' +
              'but a removed or malicious package looks identical. Confirm the scope is yours.'
            : 'Unresolvable package — typo, private registry, or removed (possibly malicious) package.' });
        continue;
      }
      if (meta.deprecated) {
        add({ id: 'DEPRECATED', severity: 'HIGH', file, line: null,
          message: `${d.name} is marked deprecated on ${d.ecosystem}`,
          hint: 'Deprecated packages receive no security fixes. Migrate.' });
      }
      if (meta.publishedFirst && Date.now() - Date.parse(meta.publishedFirst) < 30 * DAY) {
        add({ id: 'PKG_NEW', severity: 'MED', file, line: null,
          message: `${d.name} was first published less than 30 days ago`,
          hint: 'Very new packages carry elevated supply-chain risk.' });
      }
      // Both of these are npm-only signals. A null means the registry never supplied the
      // data, which is not the same as supplying a clean answer — collect the names and
      // report them as unchecked below.
      if (meta.weeklyDownloads === null) {
        unchecked.PKG_LOWDL.push(d.name);
      } else if (meta.weeklyDownloads < 100) {
        add({ id: 'PKG_LOWDL', severity: 'LOW', file, line: null,
          message: `${d.name} has very low weekly downloads (${meta.weeklyDownloads})`,
          hint: 'Few users means few eyes on the code.' });
      }
      if (meta.hasInstallScripts === null) {
        unchecked.INSTALL_SCRIPTS.push(d.name);
      } else if (meta.hasInstallScripts) {
        add({ id: 'INSTALL_SCRIPTS', severity: 'MED', file, line: null,
          message: `${d.name} runs npm install scripts (preinstall/postinstall)`,
          hint: 'Install scripts execute arbitrary code at install time — a common supply-chain vector.' });
      }
      if (!meta.repoUrl) {
        add({ id: 'NO_REPO', severity: 'LOW', file, line: null,
          message: `${d.name} has no linked source repository`,
          hint: 'Unverifiable source. Prefer packages with a public repo.' });
      }
      if (meta.publishedLast && Date.now() - Date.parse(meta.publishedLast) > 548 * DAY) {
        add({ id: 'STALE', severity: 'LOW', file, line: null,
          message: `${d.name} has not been updated in over 18 months`,
          hint: 'Possibly unmaintained.' });
      }
    }

    for (const [id, names] of Object.entries(unchecked)) {
      if (names.length === 0) continue;
      report.skipped.push(
        `${id} did not run for ${names.length} package(s) — ${UNCHECKED_REASON[id]}. ` +
        `Not checked: ${nameList(names)}.`);
    }
  }

  report.scanned = [...new Set(report.scanned)];
  report.findings = sortFindings(report.findings);
  return report;
}

/**
 * Collect the lockfiles under `root`.
 * Returns `{lockfiles, skipped}`. A file we cannot read is skipped, never fatal —
 * one odd entry (a *directory* named `package-lock.json`) must not abort the scan.
 */
export function collectLockfiles(root) {
  const lockfiles = [];
  const skipped = [];
  for (const name of LOCKFILE_NAMES) {
    const path = join(root, name);
    if (!existsSync(path)) continue;
    try {
      lockfiles.push({ path, name, text: readFileSync(path, 'utf8') });
    } catch (err) {
      skipped.push(`${path}: could not be read — dependency scan skipped for this file (${err.message})`);
    }
  }
  // Surface lockfiles we cannot parse so they are reported as skipped, not ignored.
  let entries = [];
  try { entries = readdirSync(root, { withFileTypes: true }); }
  catch (err) {
    skipped.push(`${root}: directory listing failed — unrecognized lockfiles were not surveyed (${err.message})`);
  }
  for (const entry of entries) {
    if (!entry.isFile() || LOCKFILE_NAMES.includes(entry.name)) continue;
    if (!LOCKFILE_SHAPE_RE.test(entry.name) && !EXTRA_LOCKFILE_NAMES.has(entry.name)) continue;
    lockfiles.push({ path: join(root, entry.name), name: entry.name, text: '' });
  }
  return { lockfiles, skipped };
}

/** Body of a single TOML table, as raw lines. Good enough for the two keys we read. */
function tomlSection(text, header) {
  const out = [];
  let inSection = false;
  for (const raw of text.split('\n')) {
    const t = raw.trim();
    if (t.startsWith('[')) { inSection = t.replace(/\s*#.*$/, '').trim() === header; continue; }
    if (inSection) out.push(raw);
  }
  return out.join('\n');
}

/**
 * The contents of an inline/multi-line TOML array assigned to `key`, or null.
 * The closing bracket is found with quote and comment awareness: PEP 508 extras put a
 * literal `]` inside a string (`"httpx[http2]==0.27.0"`), and a naive indexOf stops there,
 * silently dropping every dependency after the first one that declares an extra.
 */
function tomlArray(body, key) {
  const m = body.match(new RegExp(`^\\s*${key}\\s*=\\s*\\[`, 'm'));
  if (!m) return null;
  const start = m.index + m[0].length;
  let quote = null;
  for (let i = start; i < body.length; i++) {
    const ch = body[i];
    if (quote) { if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch === '#') { while (i < body.length && body[i] !== '\n') i++; continue; }
    if (ch === ']') return body.slice(start, i);
  }
  return null;
}

const quotedStrings = (s) => [...s.matchAll(/["']([^"']+)["']/g)].map(m => m[1]);
const pep508Name = (req) => (String(req).trim().match(PEP508_NAME_RE) ?? [])[1] ?? null;

/**
 * Direct dependency names from `requirements.txt`, including specifiers `parseLockfile`
 * ignores — registry metadata checks need only a name, not a resolved version.
 */
function requirementNames(text) {
  const names = [];
  const notes = [];
  for (const raw of text.split('\n')) {
    const line = raw.split(/\s+#/)[0].trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('-')) { notes.push(line); continue; }
    if (line.includes('://')) { notes.push(line); continue; }
    const name = pep508Name(line);
    if (name) names.push(name);
  }
  return { names, notes };
}

/**
 * Collect direct dependencies under `root` across npm and PyPI.
 * Returns `{deps, scanned, skipped}`. Every manifest section left uncollected is named in
 * `skipped` — the registry rules are the only checks these packages get, so a section read
 * in silence is a check that silently never ran.
 */
export function collectDirectDeps(root) {
  const deps = [];
  const scanned = [];
  const skipped = [];
  const seen = new Set();
  const push = (ecosystem, name) => {
    if (!name) return;
    const key = `${ecosystem}/${name}`;
    if (seen.has(key)) return;
    seen.add(key);
    deps.push({ ecosystem, name });
  };

  const pkgPath = join(root, 'package.json');
  if (existsSync(pkgPath)) {
    let pkg = null;
    try {
      pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
      scanned.push(pkgPath);
    } catch (err) {
      skipped.push(`${pkgPath}: manifest unreadable — no direct npm dependencies were checked (${err.message})`);
    }
    if (pkg && typeof pkg === 'object') {
      // optionalDependencies are installed by default by npm; omitting them left a real
      // supply-chain vector entirely unscanned.
      for (const section of ['dependencies', 'optionalDependencies']) {
        const v = pkg[section];
        if (v && typeof v === 'object') for (const name of Object.keys(v)) push('npm', name);
      }
      const uncollected = ['devDependencies', 'peerDependencies']
        .filter(s => pkg[s] && typeof pkg[s] === 'object' && Object.keys(pkg[s]).length > 0);
      if (uncollected.length > 0) {
        skipped.push(`${pkgPath}: ${uncollected.join(' and ')} were not collected — ` +
          `registry metadata checks did not cover those sections`);
      }
    }
  }

  const pyPath = join(root, 'pyproject.toml');
  if (existsSync(pyPath)) {
    let text = null;
    try { text = readFileSync(pyPath, 'utf8'); scanned.push(pyPath); }
    catch (err) {
      skipped.push(`${pyPath}: manifest unreadable — no direct PyPI dependencies were checked (${err.message})`);
    }
    if (text !== null) {
      const frag = tomlArray(tomlSection(text, '[project]'), 'dependencies');
      if (frag === null) {
        skipped.push(`${pyPath}: no [project] dependencies array found — ` +
          `direct PyPI dependencies were not collected from this manifest`);
      } else {
        for (const req of quotedStrings(frag)) push('PyPI', pep508Name(req));
      }
      if (/^\s*\[project\.optional-dependencies\]/m.test(text)) {
        skipped.push(`${pyPath}: [project.optional-dependencies] was not collected — ` +
          `those extras received no registry metadata checks`);
      }
      if (/^\s*\[tool\.poetry\.dependencies\]/m.test(text)) {
        skipped.push(`${pyPath}: [tool.poetry.dependencies] was not collected — ` +
          `poetry-style direct dependencies received no registry metadata checks`);
      }
    }
  }

  const reqPath = join(root, 'requirements.txt');
  if (existsSync(reqPath)) {
    try {
      const { names, notes } = requirementNames(readFileSync(reqPath, 'utf8'));
      scanned.push(reqPath);
      for (const n of names) push('PyPI', n);
      for (const n of notes) {
        skipped.push(`${reqPath}: "${n}" was not resolved — ` +
          `included files, editable installs and direct URLs are not followed`);
      }
    } catch (err) {
      skipped.push(`${reqPath}: could not be read — no direct PyPI dependencies were checked (${err.message})`);
    }
  }

  if (scanned.length === 0) {
    skipped.push('no package.json, pyproject.toml or requirements.txt found — ' +
      'registry metadata checks did not run for any direct dependency');
  }
  return { deps, scanned, skipped };
}

const USAGE = 'usage: scan-lockfile.mjs <project-dir> [--offline]';

async function main() {
  const args = process.argv.slice(2);
  // An unrecognized flag is a usage error, never a silent no-op: `--ofline` used to fall
  // through and perform real network requests in what the caller believed was an air-gapped scan.
  const unknownFlags = args.filter(a => a.startsWith('-') && a !== '--offline');
  const positional = args.filter(a => !a.startsWith('-'));
  if (unknownFlags.length > 0 || positional.length !== 1) {
    if (unknownFlags.length > 0) console.error(`unrecognized argument(s): ${unknownFlags.join(', ')}`);
    console.error(USAGE);
    process.exit(2);
  }
  const root = positional[0];
  const offline = args.includes('--offline');
  if (!existsSync(root)) { console.error(`scan-lockfile.mjs: no such directory: ${root}`); process.exit(2); }
  try {
    const lf = collectLockfiles(root);
    const dd = collectDirectDeps(root);
    const report = await scanDependencies({
      lockfiles: lf.lockfiles, directDeps: dd.deps, offline,
      scanned: dd.scanned, skipped: [...lf.skipped, ...dd.skipped],
    });
    console.log(JSON.stringify(report, null, 2));
  } catch (err) {
    console.error(`scan failed: ${err.message}`);
    process.exit(2);
  }
}

if (isMainModule(import.meta.url)) main();
