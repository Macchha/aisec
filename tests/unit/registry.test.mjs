import { describe, it, expect, vi, afterEach } from 'vitest';
import { validatePkgName, lookupPackage } from '../../plugin/scripts/lib/registry.mjs';

const ok = (body) => ({ ok: true, status: 200, json: async () => body });
const notFound = { ok: false, status: 404, json: async () => ({}) };

afterEach(() => vi.restoreAllMocks());

describe('validatePkgName', () => {
  it('accepts valid npm and PyPI names', () => {
    expect(validatePkgName('@scope/pkg', 'npm')).toBe(true);
    expect(validatePkgName('requests', 'PyPI')).toBe(true);
  });

  it('rejects traversal, spaces, overlong names and unknown ecosystems', () => {
    expect(validatePkgName('../etc/passwd', 'npm')).toBe(false);
    expect(validatePkgName('has space', 'npm')).toBe(false);
    expect(validatePkgName('a'.repeat(215), 'npm')).toBe(false);
    expect(validatePkgName('ok', 'Maven')).toBe(false);
  });
});

describe('lookupPackage', () => {
  it('normalizes npm metadata including install scripts and deprecation', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url) => {
      if (String(url).includes('api.npmjs.org')) return ok({ downloads: 4200 });
      return ok({
        'dist-tags': { latest: '2.0.0' },
        versions: { '2.0.0': { deprecated: 'use something else', scripts: { postinstall: 'node x.js' } } },
        time: { created: '2020-01-01T00:00:00Z', modified: '2026-01-01T00:00:00Z' },
        repository: { url: 'git+https://github.com/a/b.git' },
        description: 'a package',
      });
    }));
    const m = await lookupPackage('lodash', 'npm');
    expect(m.found).toBe(true);
    expect(m.deprecated).toBe(true);
    expect(m.hasInstallScripts).toBe(true);
    expect(m.weeklyDownloads).toBe(4200);
    expect(m.repoUrl).toBe('https://github.com/a/b');
    expect(m.latestVersion).toBe('2.0.0');
  });

  it('reports a 404 as not found without a lookup error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => notFound));
    const m = await lookupPackage('nope-not-real', 'npm');
    expect(m.found).toBe(false);
    expect(m.lookupError).toBe(false);
  });

  it('sets lookupError when the registry misbehaves', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 500, json: async () => ({}) })));
    const m = await lookupPackage('lodash', 'npm');
    expect(m.lookupError).toBe(true);
    expect(m.found).toBe(false);
  });

  it('refuses an invalid name before making any request', async () => {
    const spy = vi.fn();
    vi.stubGlobal('fetch', spy);
    const m = await lookupPackage('../evil', 'npm');
    expect(m.lookupError).toBe(true);
    expect(spy).not.toHaveBeenCalled();
  });

  // The URL template is the security control in this file: validatePkgName gates it, and
  // nothing else pins the exact string that gets constructed. These tests pin it.
  it('constructs the exact npm registry and downloads URLs for a scoped name', async () => {
    const spy = vi.fn(async (url) => {
      if (String(url).includes('api.npmjs.org')) return ok({ downloads: 1 });
      return ok({ 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': {} } });
    });
    vi.stubGlobal('fetch', spy);
    await lookupPackage('@scope/pkg', 'npm');
    expect(spy.mock.calls.map(c => c[0])).toEqual([
      'https://registry.npmjs.org/@scope/pkg',
      'https://api.npmjs.org/downloads/point/last-week/@scope/pkg',
    ]);
  });

  it('constructs the exact PyPI URL', async () => {
    const spy = vi.fn(async () => ok({ info: {}, releases: {} }));
    vi.stubGlobal('fetch', spy);
    await lookupPackage('requests', 'PyPI');
    expect(spy.mock.calls[0][0]).toBe('https://pypi.org/pypi/requests/json');
  });

  it('sets an abort timeout on every request', async () => {
    const spy = vi.fn(async (url) => {
      if (String(url).includes('api.npmjs.org')) return ok({ downloads: 1 });
      return ok({ 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': {} } });
    });
    vi.stubGlobal('fetch', spy);
    await lookupPackage('lodash', 'npm');
    expect(spy.mock.calls.length).toBe(2);
    for (const [, init] of spy.mock.calls) {
      expect(init?.signal).toBeInstanceOf(AbortSignal);
    }
    const pypiSpy = vi.fn(async () => ok({ info: {}, releases: {} }));
    vi.stubGlobal('fetch', pypiSpy);
    await lookupPackage('requests', 'PyPI');
    expect(pypiSpy.mock.calls[0][1]?.signal).toBeInstanceOf(AbortSignal);
  });

  it('derives PyPI publish dates from release upload times', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ok({
      info: { version: '2.0.0', summary: 'x', project_urls: { Source: 'https://github.com/a/b' } },
      releases: {
        '1.0.0': [{ upload_time_iso_8601: '2020-01-01T00:00:00Z' }],
        '2.0.0': [{ upload_time_iso_8601: '2026-01-01T00:00:00Z' }],
      },
    })));
    const m = await lookupPackage('requests', 'PyPI');
    expect(m.publishedFirst.startsWith('2020-01-01')).toBe(true);
    expect(m.publishedLast.startsWith('2026-01-01')).toBe(true);
  });
});
