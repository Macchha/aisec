import { describe, it, expect, vi, afterEach, afterAll, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, cpSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { scanDependencies, collectLockfiles, collectDirectDeps } from '../../plugin/scripts/scan-lockfile.mjs';
import { isMainModule } from '../../plugin/scripts/lib/cli.mjs';

afterEach(() => vi.restoreAllMocks());

const SCRIPTS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'plugin', 'scripts');
const tmpRoots = [];
const tmp = (prefix = 'aisec-') => {
  const d = mkdtempSync(join(tmpdir(), prefix));
  tmpRoots.push(d);
  return d;
};
afterAll(() => { for (const d of tmpRoots) rmSync(d, { recursive: true, force: true }); });

const ids = (r) => r.findings.map(f => f.id);
const lock = (text, name = 'package-lock.json', path = `/p/${name}`) => ({ path, name, text });

const npmLock = JSON.stringify({
  packages: { 'node_modules/lodash': { version: '4.17.15' }, 'node_modules/safe': { version: '1.0.0' } },
});

describe('offline mode', () => {
  it('parses the tree but records network checks as skipped, never as clean', async () => {
    const spy = vi.fn();
    vi.stubGlobal('fetch', spy);
    const r = await scanDependencies({ lockfiles: [lock(npmLock)], directDeps: [], offline: true });
    expect(spy).not.toHaveBeenCalled();
    expect(ids(r)).toContain('TRUST_BOUNDARY');
    expect(ids(r)).not.toContain('VULN_KNOWN');
    expect(r.skipped.join(' ')).toMatch(/offline/i);
  });
});

describe('vulnerability findings', () => {
  it('emits one VULN_KNOWN per vulnerable package with severity mapped', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url, init) => {
      if (String(url).includes('querybatch')) {
        const { queries } = JSON.parse(init.body);
        return { ok: true, json: async () => ({
          results: queries.map(q => q.package.name === 'lodash' ? { vulns: [{ id: 'GHSA-x' }] } : {}),
        }) };
      }
      return { ok: true, json: async () => ({
        id: 'GHSA-x', summary: 'Command Injection', aliases: ['CVE-2021-23337'],
        database_specific: { severity: 'HIGH' },
      }) };
    }));

    const r = await scanDependencies({ lockfiles: [lock(npmLock)], directDeps: [], offline: false });
    const f = r.findings.find(x => x.id === 'VULN_KNOWN');
    expect(f.severity).toBe('HIGH');
    expect(f.message).toContain('lodash@4.17.15');
    expect(f.message).toContain('CVE-2021-23337');
    expect(r.findings.filter(x => x.id === 'VULN_KNOWN')).toHaveLength(1);
  });

  // UNKNOWN maps to MED, not LOW — see the VULN_SEV comment. An advisory we could not rank
  // is unranked, not harmless, and OSV's MAL- malware records carry no severity key at all.
  it('maps MODERATE to MED and an unrecognized severity to MED', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url, init) => {
      if (String(url).includes('querybatch')) {
        const { queries } = JSON.parse(init.body);
        return { ok: true, json: async () => ({
          results: queries.map((q, i) => ({ vulns: [{ id: `V${i}` }] })),
        }) };
      }
      const id = String(url).split('/').pop();
      const severity = id === 'V0' ? 'MODERATE' : 'NOT-A-SEVERITY';
      return { ok: true, json: async () => ({ id, summary: 's', database_specific: { severity } }) };
    }));

    const r = await scanDependencies({ lockfiles: [lock(npmLock)], directDeps: [], offline: false });
    const sevs = r.findings.filter(f => f.id === 'VULN_KNOWN').map(f => f.severity).sort();
    expect(sevs).toEqual(['MED', 'MED']);
  });

  it('records a network failure as skipped rather than reporting a clean tree', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 503, json: async () => ({}) })));
    const r = await scanDependencies({ lockfiles: [lock(npmLock)], directDeps: [], offline: false });
    expect(ids(r)).not.toContain('VULN_KNOWN');
    expect(r.skipped.join(' ')).toMatch(/503|vulnerability/i);
  });

  // Regression guard for the Task 6 review's critical finding: an HTTP 200 carrying a
  // malformed body must not read as "every dependency is clean".
  it('reports a malformed OSV body as unchecked, not as a clean tree', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, json: async () => ({}) })));
    const r = await scanDependencies({ lockfiles: [lock(npmLock)], directDeps: [], offline: false });
    expect(ids(r)).not.toContain('VULN_KNOWN');
    expect(r.skipped.join(' ')).toMatch(/incomplete|no answer/i);
    expect(r.skipped.join(' ')).toMatch(/lodash/);
  });
});

describe('unsupported and missing lockfiles', () => {
  it('records an unsupported lockfile as skipped', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const r = await scanDependencies({
      lockfiles: [lock('x', 'Gemfile.lock', '/p/Gemfile.lock')], directDeps: [], offline: true,
    });
    expect(r.skipped.join(' ')).toMatch(/Gemfile\.lock/);
  });

  it('states the narrowing when no lockfile exists', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const r = await scanDependencies({ lockfiles: [], directDeps: [], offline: true });
    expect(r.skipped.join(' ')).toMatch(/no lockfile/i);
    expect(ids(r)).not.toContain('TRUST_BOUNDARY');
  });

  // Regression guard for the Task 5 review's third critical: a tree larger than MAX_DEPS
  // must not read as fully scanned.
  it('reports lockfile truncation as unscanned packages', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const packages = {};
    for (let i = 0; i < 2600; i++) packages[`node_modules/p${i}`] = { version: '1.0.0' };
    const r = await scanDependencies({
      lockfiles: [lock(JSON.stringify({ packages }))], directDeps: [], offline: true,
    });
    expect(r.skipped.join(' ')).toMatch(/2600/);
  });
});

describe('direct dependency registry checks', () => {
  const meta = (over = {}) => ({
    name: 'evil', ecosystem: 'npm', found: true, lookupError: false, description: null,
    latestVersion: '1.0.0', publishedFirst: new Date().toISOString(),
    publishedLast: new Date().toISOString(), repoUrl: null, deprecated: true,
    hasInstallScripts: true, weeklyDownloads: 3, vulns: [], ...over,
  });

  it('emits every registry rule for a maximally bad package', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ results: [] }) })));
    const r = await scanDependencies({
      lockfiles: [], offline: false,
      directDeps: [{ ecosystem: 'npm', name: 'evil' }],
      lookup: async () => meta(),
    });
    expect(ids(r)).toEqual(expect.arrayContaining(['DEPRECATED', 'PKG_NEW', 'PKG_LOWDL', 'INSTALL_SCRIPTS', 'NO_REPO']));
  });

  it('emits STALE for a package untouched for over 18 months', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ results: [] }) })));
    const old = new Date(Date.now() - 600 * 86_400_000).toISOString();
    const r = await scanDependencies({
      lockfiles: [], offline: false,
      directDeps: [{ ecosystem: 'npm', name: 'old' }],
      lookup: async () => meta({ publishedFirst: old, publishedLast: old, deprecated: false,
        hasInstallScripts: false, repoUrl: 'https://github.com/a/b', weeklyDownloads: 5000 }),
    });
    expect(ids(r)).toContain('STALE');
    expect(ids(r)).not.toContain('PKG_NEW');
  });

  it('emits PKG_UNKNOWN when the package does not exist', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ results: [] }) })));
    const r = await scanDependencies({
      lockfiles: [], offline: false,
      directDeps: [{ ecosystem: 'npm', name: 'ghost' }],
      lookup: async () => meta({ found: false, deprecated: false, hasInstallScripts: false }),
    });
    expect(ids(r)).toContain('PKG_UNKNOWN');
  });

  it('records a lookup failure as skipped and emits no grade-bearing finding', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ results: [] }) })));
    const r = await scanDependencies({
      lockfiles: [], offline: false,
      directDeps: [{ ecosystem: 'npm', name: 'flaky' }],
      lookup: async () => meta({ lookupError: true, found: false, deprecated: false, hasInstallScripts: false }),
    });
    expect(r.findings).toEqual([]);
    expect(r.skipped.join(' ')).toMatch(/flaky/);
  });

  it('caps registry lookups and records the remainder as skipped', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ results: [] }) })));
    const directDeps = Array.from({ length: 40 }, (_, i) => ({ ecosystem: 'npm', name: `p${i}` }));
    let calls = 0;
    const r = await scanDependencies({
      lockfiles: [], offline: false, directDeps,
      lookup: async () => { calls++; return meta({ deprecated: false, hasInstallScripts: false,
        repoUrl: 'https://github.com/a/b', weeklyDownloads: 5000,
        publishedFirst: new Date(Date.now() - 600 * 86_400_000).toISOString(),
        publishedLast: new Date().toISOString() }); },
    });
    expect(calls).toBe(25);
    expect(r.skipped.join(' ')).toMatch(/25/);
  });

  // Minor: the cap message never said how many packages went unchecked.
  it('states how many direct dependencies were left unchecked by the cap', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ results: [] }) })));
    const directDeps = Array.from({ length: 40 }, (_, i) => ({ ecosystem: 'npm', name: `p${i}` }));
    const r = await scanDependencies({
      lockfiles: [], offline: false, directDeps,
      lookup: async () => meta({ deprecated: false, hasInstallScripts: false,
        repoUrl: 'https://github.com/a/b', weeklyDownloads: 5000,
        publishedFirst: new Date(Date.now() - 600 * 86_400_000).toISOString(),
        publishedLast: new Date().toISOString() }),
    });
    const line = r.skipped.find(s => /registry metadata checks limited/.test(s));
    expect(line).toMatch(/40/);
    expect(line).toMatch(/15/);
  });

  // I6: a private-registry package is not evidence of malware. Scoped names drop to MED
  // confidence so an org with an internal scope is not buried in HIGH/HIGH findings.
  it('reports an unresolvable scoped package at MED confidence', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ results: [] }) })));
    const r = await scanDependencies({
      lockfiles: [], offline: false,
      directDeps: [{ ecosystem: 'npm', name: '@acme/internal' }],
      lookup: async () => meta({ found: false, deprecated: false, hasInstallScripts: false }),
    });
    const f = r.findings.find(x => x.id === 'PKG_UNKNOWN');
    expect(f.severity).toBe('HIGH');
    expect(f.confidence).toBe('MED');
    expect(f.hint).toMatch(/private registry/i);
  });

  it('keeps an unresolvable unscoped package at HIGH confidence', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ results: [] }) })));
    const r = await scanDependencies({
      lockfiles: [], offline: false,
      directDeps: [{ ecosystem: 'npm', name: 'ghost' }],
      lookup: async () => meta({ found: false, deprecated: false, hasInstallScripts: false }),
    });
    expect(r.findings.find(x => x.id === 'PKG_UNKNOWN').confidence).toBe('HIGH');
  });
});

// ---------------------------------------------------------------------------
// C1: a lockfile that parses to zero packages is not a clean scan.
// ---------------------------------------------------------------------------
describe('a lockfile that yields no packages', () => {
  it('records a skip for pip requirements that use no pinned specifiers', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const r = await scanDependencies({
      lockfiles: [lock('flask>=2.0\nrequests~=2.31\n', 'requirements.txt', '/p/requirements.txt')],
      directDeps: [], offline: true,
    });
    expect(r.skipped.join(' ')).toMatch(/requirements\.txt/);
    expect(r.skipped.join(' ')).toMatch(/no packages were recognized/i);
    // The trust-boundary note still stands; the skip sits beside it, not instead of it.
    expect(ids(r)).toContain('TRUST_BOUNDARY');
  });

  it('records a skip for a yarn berry lockfile the classic parser cannot read', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const berry = [
      '__metadata:', '  version: 8', '',
      '"lodash@npm:^4.17.21":', '  version: 4.17.21', '  resolution: "lodash@npm:4.17.21"', '',
    ].join('\n');
    const r = await scanDependencies({
      lockfiles: [lock(berry, 'yarn.lock', '/p/yarn.lock')], directDeps: [], offline: true,
    });
    expect(r.skipped.join(' ')).toMatch(/yarn\.lock/);
    expect(r.skipped.join(' ')).toMatch(/no packages were recognized/i);
  });

  it('does not claim a parse failure for a genuinely empty lockfile', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const r = await scanDependencies({
      lockfiles: [lock('   \n', 'requirements.txt', '/p/requirements.txt')], directDeps: [], offline: true,
    });
    expect(r.skipped.join(' ')).not.toMatch(/no packages were recognized/i);
  });
});

// ---------------------------------------------------------------------------
// I3 / I4: pagination and cross-lockfile duplicates.
// ---------------------------------------------------------------------------
describe('partial and duplicated vulnerability answers', () => {
  const detail = (id) => ({ ok: true, json: async () => ({
    id, summary: 'Prototype Pollution', aliases: ['CVE-2020-8203'],
    database_specific: { severity: 'HIGH' },
  }) });

  it('emits advisories from a paginated result and still records it as incomplete', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url, init) => {
      if (String(url).includes('querybatch')) {
        const { queries } = JSON.parse(init.body);
        return { ok: true, json: async () => ({
          results: queries.map(q => q.package.name === 'lodash'
            ? { vulns: [{ id: 'GHSA-page' }], next_page_token: 'more' }
            : {}),
        }) };
      }
      return detail('GHSA-page');
    }));
    const r = await scanDependencies({ lockfiles: [lock(npmLock)], directDeps: [], offline: false });
    const f = r.findings.find(x => x.id === 'VULN_KNOWN');
    expect(f).toBeDefined();
    expect(f.message).toContain('lodash@4.17.15');
    expect(r.skipped.join(' ')).toMatch(/incomplete|no answer/i);
  });

  it('emits one VULN_KNOWN when the same package appears in several lockfiles', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url, init) => {
      if (String(url).includes('querybatch')) {
        const { queries } = JSON.parse(init.body);
        return { ok: true, json: async () => ({
          results: queries.map(q => q.package.name === 'lodash' ? { vulns: [{ id: 'GHSA-dup' }] } : {}),
        }) };
      }
      return detail('GHSA-dup');
    }));
    const one = JSON.stringify({ packages: { 'node_modules/lodash': { version: '4.17.15' } } });
    const r = await scanDependencies({
      lockfiles: [
        lock(one, 'package-lock.json', '/a/package-lock.json'),
        lock(one, 'package-lock.json', '/b/package-lock.json'),
        lock(one, 'package-lock.json', '/c/package-lock.json'),
      ],
      directDeps: [], offline: false,
    });
    expect(r.findings.filter(x => x.id === 'VULN_KNOWN')).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// I5: advisory detail lookups are capped, concurrent and bounded by a deadline.
// ---------------------------------------------------------------------------
describe('advisory detail lookups', () => {
  const bigLock = () => {
    const packages = {};
    for (let i = 0; i < 120; i++) packages[`node_modules/p${i}`] = { version: '1.0.0' };
    return JSON.stringify({ packages });
  };

  it('caps the number of advisories described and records the remainder', async () => {
    let detailCalls = 0;
    vi.stubGlobal('fetch', vi.fn(async (url, init) => {
      if (String(url).includes('querybatch')) {
        const { queries } = JSON.parse(init.body);
        return { ok: true, json: async () => ({
          results: queries.map(q => ({ vulns: [{ id: `GHSA-${q.package.name}` }] })),
        }) };
      }
      detailCalls++;
      const id = String(url).split('/').pop();
      return { ok: true, json: async () => ({ id, summary: 's', database_specific: { severity: 'HIGH' } }) };
    }));

    const r = await scanDependencies({ lockfiles: [lock(bigLock())], directDeps: [], offline: false });
    expect(detailCalls).toBe(100);
    expect(r.skipped.join(' ')).toMatch(/advisory detail/i);
    expect(r.skipped.join(' ')).toMatch(/120/);
    // Every vulnerable package is still reported — the cap loses the description, not the finding.
    expect(r.findings.filter(f => f.id === 'VULN_KNOWN')).toHaveLength(120);
  });

  it('fetches advisory details concurrently rather than one at a time', async () => {
    let inFlight = 0;
    let peak = 0;
    vi.stubGlobal('fetch', vi.fn(async (url, init) => {
      if (String(url).includes('querybatch')) {
        const { queries } = JSON.parse(init.body);
        return { ok: true, json: async () => ({
          results: queries.map(q => ({ vulns: [{ id: `GHSA-${q.package.name}` }] })),
        }) };
      }
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise(res => setTimeout(res, 1));
      inFlight--;
      const id = String(url).split('/').pop();
      return { ok: true, json: async () => ({ id, summary: 's', database_specific: { severity: 'LOW' } }) };
    }));

    await scanDependencies({ lockfiles: [lock(bigLock())], directDeps: [], offline: false });
    expect(peak).toBeGreaterThan(1);
    expect(peak).toBeLessThanOrEqual(5);
  });

  // Minor: the old catch had no binding and no package name, so an outage produced
  // opaque lines that never said which dependency was affected.
  it('names the affected package and the cause when an advisory detail fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url, init) => {
      if (String(url).includes('querybatch')) {
        const { queries } = JSON.parse(init.body);
        return { ok: true, json: async () => ({
          results: queries.map(q => q.package.name === 'lodash' ? { vulns: [{ id: 'GHSA-x' }] } : {}),
        }) };
      }
      return { ok: false, status: 503, json: async () => ({}) };
    }));
    const r = await scanDependencies({ lockfiles: [lock(npmLock)], directDeps: [], offline: false });
    const line = r.skipped.find(s => s.includes('GHSA-x'));
    expect(line).toMatch(/lodash/);
    expect(line).toMatch(/503/);
    // The advisory is still reported against the package, at an unranked severity.
    const f = r.findings.find(x => x.id === 'VULN_KNOWN');
    expect(f.message).toContain('lodash@4.17.15');
    expect(f.severity).toBe('MED');
  });
});

// ---------------------------------------------------------------------------
// C2 and the collector minors.
// ---------------------------------------------------------------------------
describe('collectDirectDeps', () => {
  it('collects dependencies and optionalDependencies from package.json', () => {
    const root = tmp();
    writeFileSync(join(root, 'package.json'), JSON.stringify({
      dependencies: { lodash: '^4' },
      optionalDependencies: { fsevents: '^2' },
    }));
    const { deps } = collectDirectDeps(root);
    expect(deps).toContainEqual({ ecosystem: 'npm', name: 'lodash' });
    expect(deps).toContainEqual({ ecosystem: 'npm', name: 'fsevents' });
  });

  it('records package.json as scanned', () => {
    const root = tmp();
    writeFileSync(join(root, 'package.json'), JSON.stringify({ dependencies: { lodash: '^4' } }));
    expect(collectDirectDeps(root).scanned).toContain(join(root, 'package.json'));
  });

  it('records manifest sections it did not collect', () => {
    const root = tmp();
    writeFileSync(join(root, 'package.json'), JSON.stringify({
      dependencies: { lodash: '^4' }, devDependencies: { vitest: '^3' },
    }));
    expect(collectDirectDeps(root).skipped.join(' ')).toMatch(/devDependencies/);
  });

  it('collects [project].dependencies from pyproject.toml', () => {
    const root = tmp();
    writeFileSync(join(root, 'pyproject.toml'), [
      '[build-system]', 'requires = ["hatchling"]', '',
      '[project]', 'name = "srv"',
      'dependencies = [', '  "mcp>=1.0",', '  "httpx[http2]==0.27.0",', ']', '',
    ].join('\n'));
    const { deps } = collectDirectDeps(root);
    expect(deps).toContainEqual({ ecosystem: 'PyPI', name: 'mcp' });
    expect(deps).toContainEqual({ ecosystem: 'PyPI', name: 'httpx' });
    expect(deps).not.toContainEqual({ ecosystem: 'PyPI', name: 'hatchling' });
  });

  it('records pyproject sections it did not collect', () => {
    const root = tmp();
    writeFileSync(join(root, 'pyproject.toml'), [
      '[project]', 'dependencies = ["mcp"]', '',
      '[project.optional-dependencies]', 'dev = ["pytest"]', '',
    ].join('\n'));
    expect(collectDirectDeps(root).skipped.join(' ')).toMatch(/optional-dependencies/);
  });

  it('collects unpinned names from requirements.txt', () => {
    const root = tmp();
    writeFileSync(join(root, 'requirements.txt'), [
      '# comment', 'flask>=2.0', 'requests~=2.31', 'uvicorn[standard]==0.27.0',
      '-r other.txt', '',
    ].join('\n'));
    const { deps, skipped } = collectDirectDeps(root);
    expect(deps).toContainEqual({ ecosystem: 'PyPI', name: 'flask' });
    expect(deps).toContainEqual({ ecosystem: 'PyPI', name: 'requests' });
    expect(deps).toContainEqual({ ecosystem: 'PyPI', name: 'uvicorn' });
    expect(skipped.join(' ')).toMatch(/other\.txt/);
  });

  it('records an unparseable package.json rather than collecting nothing in silence', () => {
    const root = tmp();
    writeFileSync(join(root, 'package.json'), '{nope');
    const { deps, skipped } = collectDirectDeps(root);
    expect(deps).toEqual([]);
    expect(skipped.join(' ')).toMatch(/package\.json/);
  });

  it('records that no manifest was found at all', () => {
    const root = tmp();
    expect(collectDirectDeps(root).skipped.join(' ')).toMatch(/no package\.json/i);
  });
});

describe('collectLockfiles', () => {
  it('reads the lockfiles it understands', () => {
    const root = tmp();
    writeFileSync(join(root, 'package-lock.json'), npmLock);
    const { lockfiles } = collectLockfiles(root);
    expect(lockfiles.map(l => l.name)).toEqual(['package-lock.json']);
    expect(lockfiles[0].text).toBe(npmLock);
  });

  it('surfaces bun, go and gradle lockfiles as unrecognized rather than ignoring them', () => {
    const root = tmp();
    for (const n of ['bun.lockb', 'go.sum', 'go.mod', 'gradle.lockfile']) {
      writeFileSync(join(root, n), 'x');
    }
    const names = collectLockfiles(root).lockfiles.map(l => l.name).sort();
    expect(names).toEqual(['bun.lockb', 'go.mod', 'go.sum', 'gradle.lockfile']);
  });

  it('skips an unreadable lockfile path instead of aborting the scan', () => {
    const root = tmp();
    mkdirSync(join(root, 'package-lock.json'));
    const { lockfiles, skipped } = collectLockfiles(root);
    expect(lockfiles).toEqual([]);
    expect(skipped.join(' ')).toMatch(/package-lock\.json/);
  });
});

describe('nothing to scan at all', () => {
  it('does not claim "direct dependencies only" when there are none', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const r = await scanDependencies({ lockfiles: [], directDeps: [], offline: true });
    expect(r.skipped.join(' ')).not.toMatch(/direct dependencies only/);
    expect(r.skipped.join(' ')).toMatch(/no lockfile/i);
  });

  it('still says "direct dependencies only" when direct deps exist', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const r = await scanDependencies({
      lockfiles: [], directDeps: [{ ecosystem: 'npm', name: 'lodash' }], offline: true,
    });
    expect(r.skipped.join(' ')).toMatch(/direct dependencies only/);
  });

  it('does not throw when called with no arguments', async () => {
    vi.stubGlobal('fetch', vi.fn());
    await expect(scanDependencies()).resolves.toMatchObject({ findings: [] });
  });
});

// ---------------------------------------------------------------------------
// I1 / I2: the CLI entry point.
// ---------------------------------------------------------------------------
describe('isMainModule', () => {
  it('matches a script path containing a space', () => {
    const root = tmp('aisec guard-');
    const dir = join(root, 'proj a');
    mkdirSync(dir, { recursive: true });
    const file = join(dir, 'entry.mjs');
    writeFileSync(file, '');
    expect(isMainModule(pathToFileURL(realpathSync(file)).href, file)).toBe(true);
  });

  it('does not match a different script', () => {
    const root = tmp();
    const a = join(root, 'a.mjs');
    const b = join(root, 'b.mjs');
    writeFileSync(a, '');
    writeFileSync(b, '');
    expect(isMainModule(pathToFileURL(realpathSync(a)).href, b)).toBe(false);
  });

  it('returns false when there is no argv[1] and when it cannot be resolved', () => {
    expect(isMainModule('file:///x.mjs', undefined)).toBe(false);
    expect(isMainModule('file:///x.mjs', join(tmp(), 'missing.mjs'))).toBe(false);
  });
});

describe('CLI', () => {
  let spacedScripts;
  let project;

  const run = (script, args) =>
    spawnSync(process.execPath, [join(spacedScripts, script), ...args], { encoding: 'utf8' });

  beforeAll(() => {
    // The guard bug only reproduces when the *script* path contains a space, so the
    // scripts are copied into one before every CLI assertion below.
    const holder = tmp('aisec cli-');
    spacedScripts = join(holder, 'proj a', 'scripts');
    mkdirSync(join(holder, 'proj a'), { recursive: true });
    cpSync(SCRIPTS_DIR, spacedScripts, { recursive: true });

    project = tmp('aisec proj-');
    writeFileSync(join(project, 'package-lock.json'), npmLock);
    writeFileSync(join(project, 'package.json'), JSON.stringify({ dependencies: { lodash: '^4.17.15' } }));
    writeFileSync(join(project, 'mcp.json'), JSON.stringify({ mcpServers: {} }));
    writeFileSync(join(project, 'index.js'), 'const a = 1;\n');
  });

  it('scan-lockfile.mjs prints a report from a path containing a space', () => {
    const r = run('scan-lockfile.mjs', [project, '--offline']);
    expect(r.status).toBe(0);
    const report = JSON.parse(r.stdout);
    expect(report.findings.map(f => f.id)).toContain('TRUST_BOUNDARY');
    expect(report.scanned).toContain(join(project, 'package.json'));
  });

  it('scan-config.mjs prints a report from a path containing a space', () => {
    const r = run('scan-config.mjs', [join(project, 'mcp.json')]);
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout)).toHaveProperty('findings');
  });

  it('scan-unicode.mjs prints a report from a path containing a space', () => {
    const r = run('scan-unicode.mjs', [join(project, 'index.js')]);
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout)).toHaveProperty('findings');
  });

  it('rejects an unrecognized flag instead of silently going online', () => {
    const r = run('scan-lockfile.mjs', [project, '--ofline']);
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).toMatch(/--ofline/);
  });

  it('rejects a missing project directory argument', () => {
    const r = run('scan-lockfile.mjs', ['--offline']);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/usage/i);
  });

  it('rejects a directory that does not exist', () => {
    const r = run('scan-lockfile.mjs', [join(project, 'nope'), '--offline']);
    expect(r.status).toBe(2);
  });

  it('collects direct dependencies for a Python project with no npm manifest', () => {
    const py = tmp('aisec py-');
    writeFileSync(join(py, 'pyproject.toml'), '[project]\ndependencies = ["mcp>=1.0"]\n');
    const r = run('scan-lockfile.mjs', [py, '--offline']);
    expect(r.status).toBe(0);
    const report = JSON.parse(r.stdout);
    // Offline, so the checks cannot run — but they must be named as skipped, not omitted.
    expect(report.skipped.join(' ')).toMatch(/registry metadata checks skipped for 1/);
  });
});
