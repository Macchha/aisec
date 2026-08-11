const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN = 'https://api.osv.dev/v1/vulns';
const CHUNK = 1000;
const TIMEOUT_MS = 10_000;

export const depKey = (d) => `${d.ecosystem}/${d.name}@${d.version}`;

// Null-safe key for deps that failed validation; never throws, always identifiable.
const keyOf = (d) => depKey({ ecosystem: d?.ecosystem, name: d?.name, version: d?.version });

const nonEmptyString = (v) => typeof v === 'string' && v.length > 0;

// A dep missing any of these cannot be queried safely. Sending a query with no `version`
// makes OSV answer package-wide, returning every advisory ever filed against the package
// — which would report a fully patched install as vulnerable.
const queryable = (d) =>
  nonEmptyString(d?.name) && nonEmptyString(d?.ecosystem) && nonEmptyString(d?.version);

/**
 * Look up known vulnerabilities for a list of dependencies.
 *
 * Returns `{ map, unknown, errors }`:
 * - `map`     — depKey → array of advisory ids, ONLY for deps we got a real answer for.
 *               An empty array here means "OSV says clean".
 * - `unknown` — depKeys we could not resolve: unqueryable deps, failed chunks, malformed
 *               or short responses, and truncated (paginated) results. Callers must report
 *               these as unchecked, never as clean. A depKey may appear in both `map` and
 *               `unknown` when the answer was partial (pagination).
 * - `errors`  — human-readable reasons, for surfacing in the report's `skipped[]`.
 */
export async function queryBatch(deps) {
  const map = new Map();
  const unknown = new Set();
  const errors = [];

  // Validate and deduplicate before chunking: invalid deps are never sent, and a lockfile
  // listing the same name@version twice must not burn chunk budget or duplicate findings.
  const pending = [];
  const seen = new Set();
  for (const dep of deps ?? []) {
    if (!queryable(dep)) {
      unknown.add(keyOf(dep));
      errors.push(`skipped unqueryable dependency ${keyOf(dep)}: name, ecosystem and version are all required`);
      continue;
    }
    const key = depKey(dep);
    if (seen.has(key)) continue;
    seen.add(key);
    pending.push(dep);
  }

  for (let i = 0; i < pending.length; i += CHUNK) {
    const chunk = pending.slice(i, i + CHUNK);
    try {
      const res = await fetch(OSV_BATCH, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          queries: chunk.map(d => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })),
        }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const results = data?.results;
      // Results are positionally aligned with queries. A response that is not an array of
      // exactly the right length tells us nothing about any dep in this chunk — treating a
      // missing entry as {} would silently mark every one of them clean.
      if (!Array.isArray(results)) throw new Error('results field is not an array');
      if (results.length !== chunk.length) {
        throw new Error(`results length ${results.length} does not match ${chunk.length} queries`);
      }
      chunk.forEach((dep, j) => {
        const key = depKey(dep);
        const r = results[j];
        if (r === null || typeof r !== 'object') {
          unknown.add(key);
          return;
        }
        const vulns = Array.isArray(r.vulns) ? r.vulns : [];
        map.set(key, vulns.map(v => String(v?.id ?? '')).filter(Boolean));
        // A paginated result is truncated: keep what we got, but the answer is incomplete.
        if (r.next_page_token) unknown.add(key);
      });
    } catch (err) {
      // One chunk failing must not discard the answers we already have for other chunks.
      for (const dep of chunk) unknown.add(depKey(dep));
      errors.push(`OSV querybatch failed for ${chunk.length} dependencies: ${err?.message ?? String(err)}`);
    }
  }

  return { map, unknown, errors };
}

const SEVERITY_ALIASES = new Map([
  ['CRITICAL', 'CRITICAL'],
  ['HIGH', 'HIGH'],
  ['MODERATE', 'MODERATE'],
  ['MEDIUM', 'MODERATE'],
  ['LOW', 'LOW'],
]);

// CVSS v3.1 base metric weights (spec section 7.1).
const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC = { L: 0.77, H: 0.44 };
const PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 };
const UI = { N: 0.85, R: 0.62 };
const CIA = { H: 0.56, L: 0.22, N: 0 };

// CVSS v3.1 Appendix A roundup: round up to one decimal, avoiding float representation error.
function roundup(input) {
  const i = Math.round(input * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

/**
 * Compute a CVSS v3.0/v3.1 base score from a vector string.
 * Returns the score, or `null` if the vector is not a parseable v3 base vector —
 * we never guess a severity we could not derive.
 */
export function cvssV3BaseScore(vector) {
  if (typeof vector !== 'string' || !/^CVSS:3\.[01]\//.test(vector)) return null;
  const m = {};
  for (const part of vector.split('/').slice(1)) {
    const [k, v] = part.split(':');
    if (k && v) m[k] = v;
  }
  if (m.S !== 'C' && m.S !== 'U') return null;
  const scopeChanged = m.S === 'C';
  const pr = scopeChanged ? PR_CHANGED : PR_UNCHANGED;
  const av = AV[m.AV], ac = AC[m.AC], prW = pr[m.PR], ui = UI[m.UI];
  const c = CIA[m.C], integrity = CIA[m.I], a = CIA[m.A];
  if ([av, ac, prW, ui, c, integrity, a].some(x => x === undefined)) return null;

  const iss = 1 - (1 - c) * (1 - integrity) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * prW * ui;
  const base = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return roundup(base);
}

function severityFromScore(score) {
  if (score === null) return null;
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MODERATE';
  if (score > 0) return 'LOW';
  return null; // CVSS "None" has no equivalent on our scale; stay UNKNOWN rather than guess.
}

function resolveSeverity(v, id) {
  // OSV MAL- records are confirmed malware and carry no severity key. Without a floor they
  // degrade to UNKNOWN and get reported as the least urgent thing in the scan.
  if (String(id ?? '').startsWith('MAL-') || String(v?.id ?? '').startsWith('MAL-')) return 'CRITICAL';

  const keyed = String(v?.database_specific?.severity ?? v?.ecosystem_specific?.severity ?? '').toUpperCase();
  if (SEVERITY_ALIASES.has(keyed)) return SEVERITY_ALIASES.get(keyed);

  // Fall back to OSV's canonical top-level severity array.
  const entries = Array.isArray(v?.severity) ? v.severity : [];
  for (const e of entries) {
    if (!String(e?.type ?? '').startsWith('CVSS_V3')) continue;
    const mapped = severityFromScore(cvssV3BaseScore(e?.score));
    if (mapped) return mapped;
  }
  return 'UNKNOWN';
}

export async function fetchVulnDetail(id) {
  const res = await fetch(`${OSV_VULN}/${encodeURIComponent(id)}`, {
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`OSV vuln lookup failed for ${id}: HTTP ${res.status}`);
  const v = await res.json();
  const aliases = Array.isArray(v?.aliases) ? v.aliases : [];
  return {
    id: String(v?.id ?? id),
    cveId: aliases.find(a => typeof a === 'string' && a.startsWith('CVE-')) ?? null,
    severity: resolveSeverity(v, id),
    summary: String(v?.summary ?? v?.details ?? '').slice(0, 200),
  };
}
