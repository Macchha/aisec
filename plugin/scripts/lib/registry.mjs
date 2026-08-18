// Ported from vulnrable/src/lib/mcpregistry.ts. Two deliberate changes:
//   1. lookupPackage no longer calls fetchOsvVulns — vulnerability data now comes from the
//      version-aware queryBatch in osv.mjs. `vulns: []` stays on the returned object so the
//      shape is unchanged for callers.
//   2. The defense-in-depth name check is preserved verbatim: validatePkgName runs before any
//      URL is constructed, so no unvalidated name can reach a fetch URL.

// Registry calls run inside an interactive /aisec-review, and Task 7 makes them serially.
// A degraded network must not stall the scan indefinitely.
const TIMEOUT_MS = 10_000;
const timeout = () => ({ signal: AbortSignal.timeout(TIMEOUT_MS) });

const NPM_NAME_RE = /^(@[a-z0-9~][a-z0-9-._~]*\/)?[a-z0-9~][a-z0-9-._~]*$/;
const PYPI_NAME_RE = /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/;

export function validatePkgName(name, ecosystem) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 214) return false;
  if (ecosystem === 'npm') return NPM_NAME_RE.test(name);
  if (ecosystem === 'PyPI') return PYPI_NAME_RE.test(name);
  return false;
}

// `hasInstallScripts` and `weeklyDownloads` are tri-state: true/false/number means the
// registry answered, `null` means nobody looked. They default to null so a registry that
// does not expose the data cannot pass for a registry that reported nothing wrong —
// callers must branch on null and record a skip.
const empty = (name, ecosystem) => ({
  name, ecosystem, found: false, lookupError: false,
  description: null, latestVersion: null, publishedFirst: null, publishedLast: null,
  repoUrl: null, deprecated: false, hasInstallScripts: null, weeklyDownloads: null, vulns: [],
});

function cleanRepoUrl(raw) {
  if (typeof raw !== 'string' || !raw) return null;
  const u = raw.replace(/^git\+/, '').replace(/\.git$/, '');
  return /^https?:\/\//.test(u) ? u : null;
}

export function normalizeNpmMeta(name, doc, weeklyDownloads) {
  const latest = doc?.['dist-tags']?.latest ?? null;
  const ver = latest ? doc?.versions?.[latest] : null;
  const scripts = ver?.scripts ?? {};
  // No version manifest means the install-script question was never asked. `false` here
  // would claim we looked and found none.
  const hasInstallScripts = ver
    ? Boolean(scripts.preinstall || scripts.postinstall || scripts.install)
    : null;
  return {
    ...empty(name, 'npm'),
    found: true,
    description: typeof doc?.description === 'string' ? doc.description.slice(0, 300) : null,
    latestVersion: latest,
    publishedFirst: doc?.time?.created ?? null,
    publishedLast: doc?.time?.modified ?? null,
    repoUrl: cleanRepoUrl(doc?.repository?.url ?? doc?.repository),
    deprecated: Boolean(ver?.deprecated),
    hasInstallScripts,
    weeklyDownloads,
  };
}

// PyPI's JSON API exposes neither download counts nor install-time hooks: download stats
// live in a separate BigQuery-backed service, and `setup.py` execution is only visible by
// downloading and unpacking an sdist. Both fields therefore stay null — PKG_LOWDL and
// INSTALL_SCRIPTS do not run for PyPI, and the caller reports them as skipped. Leaving
// them at a falsy default would silently pass every Python package.
export function normalizePyPIMeta(name, doc) {
  const info = doc?.info ?? {};
  const urls = info.project_urls ?? {};
  const repo = cleanRepoUrl(urls.Source ?? urls.Repository ?? urls.Homepage ?? info.home_page);
  const times = [];
  for (const files of Object.values(doc?.releases ?? {})) {
    for (const f of files ?? []) {
      const t = Date.parse(f?.upload_time_iso_8601 ?? '');
      if (!isNaN(t)) times.push(t);
    }
  }
  return {
    ...empty(name, 'PyPI'),
    found: true,
    description: typeof info.summary === 'string' ? info.summary.slice(0, 300) : null,
    latestVersion: info.version ?? null,
    publishedFirst: times.length ? new Date(Math.min(...times)).toISOString().replace(/\.000Z$/, 'Z') : null,
    publishedLast: times.length ? new Date(Math.max(...times)).toISOString().replace(/\.000Z$/, 'Z') : null,
    repoUrl: repo,
    deprecated: /deprecated/i.test(String(info.summary ?? '')) || Boolean(info.yanked),
  };
}

export async function lookupPackage(name, ecosystem) {
  // Defense-in-depth: callers validate too, but no invalid name may ever reach a fetch URL.
  if (!validatePkgName(name, ecosystem)) return { ...empty(name, ecosystem), lookupError: true };
  try {
    let meta;
    if (ecosystem === 'npm') {
      const res = await fetch(`https://registry.npmjs.org/${name}`, timeout());
      if (res.status === 404) return { ...empty(name, ecosystem) };
      if (!res.ok) throw new Error('npm registry failed');
      const doc = await res.json();
      let dl = null;
      try {
        const d = await fetch(`https://api.npmjs.org/downloads/point/last-week/${name}`, timeout());
        if (d.ok) dl = (await d.json()).downloads ?? null;
      } catch { /* downloads are best-effort */ }
      meta = normalizeNpmMeta(name, doc, dl);
    } else {
      const res = await fetch(`https://pypi.org/pypi/${name}/json`, timeout());
      if (res.status === 404) return { ...empty(name, ecosystem) };
      if (!res.ok) throw new Error('pypi failed');
      meta = normalizePyPIMeta(name, await res.json());
    }
    return meta;
  } catch {
    return { ...empty(name, ecosystem), lookupError: true };
  }
}
