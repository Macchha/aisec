import { describe, it, expect, vi, afterEach } from 'vitest';
import { queryBatch, fetchVulnDetail, depKey, cvssV3BaseScore } from '../../plugin/scripts/lib/osv.mjs';

const ok = (body) => ({ ok: true, status: 200, json: async () => body });

afterEach(() => vi.restoreAllMocks());

describe('queryBatch', () => {
  it('maps results positionally and treats {} as clean', async () => {
    const deps = [
      { ecosystem: 'npm', name: 'lodash', version: '4.17.15' },
      { ecosystem: 'npm', name: 'safe-pkg', version: '1.0.0' },
    ];
    vi.stubGlobal('fetch', vi.fn(async () => ok({
      results: [{ vulns: [{ id: 'GHSA-aaa', modified: 'x' }, { id: 'GHSA-bbb', modified: 'y' }] }, {}],
    })));

    const { map, unknown } = await queryBatch(deps);
    expect(map.get('npm/lodash@4.17.15')).toEqual(['GHSA-aaa', 'GHSA-bbb']);
    expect(map.get('npm/safe-pkg@1.0.0')).toEqual([]);
    expect(unknown.size).toBe(0);
  });

  it('sends the documented request body', async () => {
    const spy = vi.fn(async () => ok({ results: [{}] }));
    vi.stubGlobal('fetch', spy);
    await queryBatch([{ ecosystem: 'PyPI', name: 'requests', version: '2.31.0' }]);
    const [url, init] = spy.mock.calls[0];
    expect(url).toBe('https://api.osv.dev/v1/querybatch');
    expect(JSON.parse(init.body)).toEqual({
      queries: [{ package: { name: 'requests', ecosystem: 'PyPI' }, version: '2.31.0' }],
    });
  });

  it('sets an abort timeout on the request', async () => {
    const spy = vi.fn(async () => ok({ results: [{}] }));
    vi.stubGlobal('fetch', spy);
    await queryBatch([{ ecosystem: 'npm', name: 'a', version: '1.0.0' }]);
    expect(spy.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal);
  });

  it('chunks requests at 1000 queries', async () => {
    const deps = Array.from({ length: 1500 }, (_, i) => ({ ecosystem: 'npm', name: `p${i}`, version: '1.0.0' }));
    const spy = vi.fn(async (_u, init) => ok({ results: JSON.parse(init.body).queries.map(() => ({})) }));
    vi.stubGlobal('fetch', spy);
    const { map, unknown } = await queryBatch(deps);
    expect(spy).toHaveBeenCalledTimes(2);
    expect(map.size).toBe(1500);
    expect(unknown.size).toBe(0);
  });

  it('returns an empty map for an empty dep list without calling fetch', async () => {
    const spy = vi.fn();
    vi.stubGlobal('fetch', spy);
    const { map, unknown } = await queryBatch([]);
    expect(map.size).toBe(0);
    expect(unknown.size).toBe(0);
    expect(spy).not.toHaveBeenCalled();
  });

  // Finding 1: a short or missing results array must never read as "clean".
  describe('incomplete API responses are unknown, not clean', () => {
    const dep = { ecosystem: 'npm', name: 'lodash', version: '4.17.15' };

    it('treats a missing results field as unknown', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => ok({})));
      const { map, unknown } = await queryBatch([dep]);
      expect(map.size).toBe(0);
      expect(unknown.has('npm/lodash@4.17.15')).toBe(true);
    });

    it('treats a non-array results field as unknown', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => ok({ results: { 0: {} } })));
      const { map, unknown } = await queryBatch([dep]);
      expect(map.size).toBe(0);
      expect(unknown.has('npm/lodash@4.17.15')).toBe(true);
    });

    it('treats a results array shorter than the queries as all unknown', async () => {
      const deps = [dep, { ecosystem: 'npm', name: 'other', version: '2.0.0' }];
      vi.stubGlobal('fetch', vi.fn(async () => ok({ results: [{}] })));
      const { map, unknown } = await queryBatch(deps);
      expect(map.size).toBe(0);
      expect(unknown.has('npm/lodash@4.17.15')).toBe(true);
      expect(unknown.has('npm/other@2.0.0')).toBe(true);
    });

    it('treats a null entry inside a correctly sized results array as unknown', async () => {
      const deps = [dep, { ecosystem: 'npm', name: 'other', version: '2.0.0' }];
      vi.stubGlobal('fetch', vi.fn(async () => ok({ results: [{}, null] })));
      const { map, unknown } = await queryBatch(deps);
      expect(map.get('npm/lodash@4.17.15')).toEqual([]);
      expect(map.has('npm/other@2.0.0')).toBe(false);
      expect(unknown.has('npm/other@2.0.0')).toBe(true);
    });
  });

  // Finding 2: one chunk failing must not discard the others.
  describe('per-chunk failure isolation', () => {
    it('keeps earlier chunk results when a later chunk fails', async () => {
      const deps = Array.from({ length: 1500 }, (_, i) => ({ ecosystem: 'npm', name: `p${i}`, version: '1.0.0' }));
      let call = 0;
      vi.stubGlobal('fetch', vi.fn(async (_u, init) => {
        call += 1;
        if (call === 2) return { ok: false, status: 503, json: async () => ({}) };
        return ok({ results: JSON.parse(init.body).queries.map(() => ({})) });
      }));
      const { map, unknown, errors } = await queryBatch(deps);
      expect(map.size).toBe(1000);
      expect(unknown.size).toBe(500);
      expect(map.has('npm/p0@1.0.0')).toBe(true);
      expect(unknown.has('npm/p1000@1.0.0')).toBe(true);
      expect(errors.join(' ')).toMatch(/503/);
    });

    // Replaces the plan's "throws when the API returns an error status" test. Finding 2
    // requires a non-ok status to degrade that chunk to unknown, not to reject.
    it('records a non-ok status as unknown rather than throwing', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 503, json: async () => ({}) })));
      const { map, unknown, errors } = await queryBatch([{ ecosystem: 'npm', name: 'a', version: '1.0.0' }]);
      expect(map.size).toBe(0);
      expect(unknown.has('npm/a@1.0.0')).toBe(true);
      expect(errors.join(' ')).toMatch(/503/);
    });

    it('records a thrown network error as unknown rather than throwing', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('socket hang up'); }));
      const { map, unknown, errors } = await queryBatch([{ ecosystem: 'npm', name: 'a', version: '1.0.0' }]);
      expect(map.size).toBe(0);
      expect(unknown.has('npm/a@1.0.0')).toBe(true);
      expect(errors.join(' ')).toMatch(/socket hang up/);
    });
  });

  // Finding 4: a vuln entry with no usable id must be dropped, not stringified.
  describe('vuln id hygiene', () => {
    it('drops entries with a missing id instead of recording "undefined"', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => ok({
        results: [{ vulns: [{ modified: 'x' }, { id: 'GHSA-real' }] }],
      })));
      const { map } = await queryBatch([{ ecosystem: 'npm', name: 'a', version: '1.0.0' }]);
      expect(map.get('npm/a@1.0.0')).toEqual(['GHSA-real']);
    });

    it('survives a null entry inside vulns', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => ok({
        results: [{ vulns: [null, { id: 'GHSA-real' }] }],
      })));
      const { map } = await queryBatch([{ ecosystem: 'npm', name: 'a', version: '1.0.0' }]);
      expect(map.get('npm/a@1.0.0')).toEqual(['GHSA-real']);
    });

    it('treats a non-array vulns field as clean', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => ok({ results: [{ vulns: 'nope' }] })));
      const { map, unknown } = await queryBatch([{ ecosystem: 'npm', name: 'a', version: '1.0.0' }]);
      expect(map.get('npm/a@1.0.0')).toEqual([]);
      expect(unknown.size).toBe(0);
    });
  });

  // Finding 5: an unusable version must never be sent as a package-wide query.
  describe('dep validation before chunking', () => {
    it('never sends a dep with an undefined version', async () => {
      const spy = vi.fn();
      vi.stubGlobal('fetch', spy);
      const { map, unknown } = await queryBatch([{ ecosystem: 'npm', name: 'lodash', version: undefined }]);
      expect(spy).not.toHaveBeenCalled();
      expect(map.size).toBe(0);
      expect(unknown.has('npm/lodash@undefined')).toBe(true);
    });

    it('rejects empty-string and non-string versions, names and ecosystems', async () => {
      const spy = vi.fn();
      vi.stubGlobal('fetch', spy);
      const { unknown } = await queryBatch([
        { ecosystem: 'npm', name: 'a', version: '' },
        { ecosystem: 'npm', name: '', version: '1.0.0' },
        { ecosystem: '', name: 'c', version: '1.0.0' },
        { ecosystem: 'npm', name: 'd', version: 1 },
      ]);
      expect(spy).not.toHaveBeenCalled();
      expect(unknown.size).toBe(4);
    });

    it('still queries the valid deps alongside invalid ones', async () => {
      const spy = vi.fn(async (_u, init) => ok({ results: JSON.parse(init.body).queries.map(() => ({})) }));
      vi.stubGlobal('fetch', spy);
      const { map, unknown } = await queryBatch([
        { ecosystem: 'npm', name: 'bad', version: undefined },
        { ecosystem: 'npm', name: 'good', version: '1.0.0' },
      ]);
      expect(JSON.parse(spy.mock.calls[0][1].body).queries).toHaveLength(1);
      expect(map.get('npm/good@1.0.0')).toEqual([]);
      expect(unknown.has('npm/bad@undefined')).toBe(true);
    });
  });

  // Finding 11: duplicates waste chunk budget and duplicate downstream findings.
  it('deduplicates deps on depKey before chunking', async () => {
    const spy = vi.fn(async (_u, init) => ok({ results: JSON.parse(init.body).queries.map(() => ({})) }));
    vi.stubGlobal('fetch', spy);
    const dep = { ecosystem: 'npm', name: 'lodash', version: '4.17.15' };
    const { map } = await queryBatch([dep, { ...dep }, dep]);
    expect(JSON.parse(spy.mock.calls[0][1].body).queries).toHaveLength(1);
    expect(map.size).toBe(1);
  });

  // Finding 10: a paginated result is an incomplete answer.
  it('keeps the ids it got but marks a paginated result unknown', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ok({
      results: [{ vulns: [{ id: 'GHSA-aaa' }], next_page_token: 'tok' }],
    })));
    const { map, unknown } = await queryBatch([{ ecosystem: 'npm', name: 'a', version: '1.0.0' }]);
    expect(map.get('npm/a@1.0.0')).toEqual(['GHSA-aaa']);
    expect(unknown.has('npm/a@1.0.0')).toBe(true);
  });
});

describe('fetchVulnDetail', () => {
  it('prefers database_specific.severity and surfaces the CVE alias', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ok({
      id: 'GHSA-35jh-r3h4-6jhm',
      summary: 'Command Injection in lodash',
      aliases: ['CVE-2021-23337', 'GHSA-other'],
      database_specific: { severity: 'HIGH' },
    })));
    expect(await fetchVulnDetail('GHSA-35jh-r3h4-6jhm')).toEqual({
      id: 'GHSA-35jh-r3h4-6jhm', cveId: 'CVE-2021-23337',
      severity: 'HIGH', summary: 'Command Injection in lodash',
    });
  });

  it('degrades to UNKNOWN severity rather than failing', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ok({ id: 'OSV-1', details: 'long text' })));
    const d = await fetchVulnDetail('OSV-1');
    expect(d.severity).toBe('UNKNOWN');
    expect(d.cveId).toBe(null);
    expect(d.summary).toBe('long text');
  });

  it('falls back to ecosystem_specific.severity', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ok({ id: 'OSV-2', ecosystem_specific: { severity: 'CRITICAL' } })));
    expect((await fetchVulnDetail('OSV-2')).severity).toBe('CRITICAL');
  });

  it('accepts both MODERATE and MEDIUM, normalizing to MODERATE', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ok({ id: 'OSV-3', database_specific: { severity: 'MODERATE' } })));
    expect((await fetchVulnDetail('OSV-3')).severity).toBe('MODERATE');
    vi.stubGlobal('fetch', vi.fn(async () => ok({ id: 'OSV-4', database_specific: { severity: 'medium' } })));
    expect((await fetchVulnDetail('OSV-4')).severity).toBe('MODERATE');
  });

  it('sets an abort timeout on the request', async () => {
    const spy = vi.fn(async () => ok({ id: 'OSV-1' }));
    vi.stubGlobal('fetch', spy);
    await fetchVulnDetail('OSV-1');
    expect(spy.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal);
  });

  it('throws when the vuln lookup returns an error status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 500, json: async () => ({}) })));
    await expect(fetchVulnDetail('OSV-1')).rejects.toThrow(/500/);
  });

  // Finding 12: aliases entries are untrusted.
  it('survives a non-string alias entry', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => ok({ id: 'OSV-1', aliases: [null, 42, 'CVE-2020-0001'] })));
    expect((await fetchVulnDetail('OSV-1')).cveId).toBe('CVE-2020-0001');
  });

  // Finding 3: malware advisories must not degrade to LOW.
  describe('severity floors and CVSS fallback', () => {
    it('floors a MAL- advisory at CRITICAL even with no severity data', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => ok({ id: 'MAL-2024-1234', summary: 'malicious package' })));
      expect((await fetchVulnDetail('MAL-2024-1234')).severity).toBe('CRITICAL');
    });

    it('floors a MAL- advisory at CRITICAL even when the feed claims LOW', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => ok({
        id: 'MAL-2024-1234', database_specific: { severity: 'LOW' },
      })));
      expect((await fetchVulnDetail('MAL-2024-1234')).severity).toBe('CRITICAL');
    });

    it('derives severity from the top-level CVSS_V3 vector when no keyed severity exists', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => ok({
        id: 'OSV-5',
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      })));
      expect((await fetchVulnDetail('OSV-5')).severity).toBe('CRITICAL');
    });

    it('maps a mid-range CVSS vector to MODERATE', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => ok({
        id: 'OSV-6',
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N' }],
      })));
      expect((await fetchVulnDetail('OSV-6')).severity).toBe('MODERATE');
    });

    it('stays UNKNOWN when the CVSS vector will not parse', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => ok({
        id: 'OSV-7', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:X/nonsense' }],
      })));
      expect((await fetchVulnDetail('OSV-7')).severity).toBe('UNKNOWN');
    });

    it('ignores a CVSS v2 vector rather than misreading it', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => ok({
        id: 'OSV-8', severity: [{ type: 'CVSS_V2', score: 'AV:N/AC:L/Au:N/C:P/I:P/A:P' }],
      })));
      expect((await fetchVulnDetail('OSV-8')).severity).toBe('UNKNOWN');
    });

    it('prefers a keyed severity over the CVSS vector', async () => {
      vi.stubGlobal('fetch', vi.fn(async () => ok({
        id: 'OSV-9',
        database_specific: { severity: 'LOW' },
        severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      })));
      expect((await fetchVulnDetail('OSV-9')).severity).toBe('LOW');
    });
  });
});

describe('cvssV3BaseScore', () => {
  it('scores the canonical worst-case vector at 9.8', () => {
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
  });

  it('applies the user-interaction weight', () => {
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H')).toBe(8.8);
  });

  it('scores a single-impact vector at 6.5', () => {
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N')).toBe(6.5);
  });

  it('scores a hard-to-exploit low-impact vector at 1.8', () => {
    expect(cvssV3BaseScore('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N')).toBe(1.8);
  });

  it('caps a scope-changed vector at 10.0', () => {
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBe(10);
  });

  it('uses the scope-changed privileges-required weights', () => {
    // 9.9 with the changed-scope PR:L weight of 0.68; 9.6 if the unchanged 0.62 leaked in.
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H')).toBe(9.9);
  });

  it('accepts a 3.0 vector', () => {
    expect(cvssV3BaseScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8);
  });

  it('returns null for a missing metric, a v2 vector and junk', () => {
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H')).toBe(null);
    expect(cvssV3BaseScore('AV:N/AC:L/Au:N/C:P/I:P/A:P')).toBe(null);
    expect(cvssV3BaseScore('nonsense')).toBe(null);
    expect(cvssV3BaseScore(null)).toBe(null);
  });

  it('returns 0 for a no-impact vector', () => {
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')).toBe(0);
  });
});

describe('depKey', () => {
  it('builds a stable lookup key', () => {
    expect(depKey({ ecosystem: 'npm', name: '@a/b', version: '1.0.0' })).toBe('npm/@a/b@1.0.0');
  });
});
