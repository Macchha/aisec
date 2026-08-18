# Dependency rules (VULN_KNOWN … TRUST_BOUNDARY)

These nine rules are implemented deterministically in
`scripts/scan-lockfile.mjs`, using `lockparse.mjs` for the tree, OSV for
vulnerability data, and the npm/PyPI registries for metadata. The model must not
duplicate their findings.

The whole dependency tree matters, not just direct dependencies: every package in
a lockfile runs with the same privileges as the MCP server, which runs with the
agent's privileges. There is no sandbox between a transitive dependency's
install script and the user's credentials.

Registry metadata rules are applied only to **direct** dependencies, capped at 25
lookups; the remainder is recorded in `skipped[]`.

## VULN_KNOWN — Package version has a known advisory

**What it is**: A package in the dependency tree matches a published OSV
advisory at its pinned version.

**Why it matters**: This is conventional SCA, and it applies with more force here
than in a typical web service. A prototype-pollution or RCE bug in a transitive
dependency of an MCP server is reachable by anything that can steer the model,
and the process it compromises is holding the user's credentials.

**Vulnerable example**:

```json
{ "packages": { "node_modules/lodash": { "version": "4.17.15" } } }
```

**Safe example**:

```json
{ "packages": { "node_modules/lodash": { "version": "4.17.21" } } }
```

**Detection**: Batch every parsed `{ecosystem, name, version}` to
`POST https://api.osv.dev/v1/querybatch`, 1000 queries per request, then fetch
each advisory's detail. Severity maps to the report scale as: `CRITICAL` and
`HIGH` → **HIGH**; `MODERATE` and `MEDIUM` → **MED**; `LOW` → **LOW**; and
`UNKNOWN` → **MED**.

That last mapping is deliberate and was changed after review. An advisory we
could not rank is *unranked*, not harmless — and OSV's `MAL-` records, which
denote confirmed malware, carry no severity field at all. Mapping unknown down to
LOW buried confirmed-malicious packages beneath cosmetic findings. `MAL-`
advisories are additionally floored at CRITICAL, and where no keyed severity
exists the top-level CVSS vector is parsed for a base score.

A dependency OSV did not answer for is recorded in `skipped[]`, never treated as
clean. "We could not check" and "we checked and it was clean" must stay
distinguishable.

**False positives**: An advisory may not be reachable in the way the package is
used — a ReDoS in a parser never fed untrusted input, for instance. Reachability
analysis is out of scope for V1, so treat these as "present and worth triaging"
rather than "exploitable". Version ranges in advisories occasionally over-match
a patched fork.

## DEPRECATED — Direct dependency is marked deprecated

**What it is**: The registry reports the package as deprecated.

**Why it matters**: A deprecated package receives no security fixes. Whatever is
found in it later stays unfixed, and the migration cost only grows. Deprecation
is also frequently how maintainers signal a package was taken over or should no
longer be trusted.

**Vulnerable example**:

```json
{ "dependencies": { "request": "^2.88.2" } }
```

**Safe example**:

```json
{ "dependencies": { "undici": "^6.0.0" } }
```

**Detection**: Read the deprecation flag from the npm registry document for the
package's latest version, or PyPI's yanked flag and summary text. **Reported at
HIGH severity**, applied to direct dependencies only, like every other registry
metadata rule. **Known limitation**: the flag is read from the *latest* version,
so a project pinning a deprecated `1.x` while a current `2.x` exists will not
fire this rule. That is version-blind in a way the vulnerability path is not.

**False positives**: Some maintainers use the deprecation field for
announcements ("moved to @scope/name") rather than to signal abandonment. Read
the message before treating it as a defect. HIGH is a deliberately strong
default for a rule whose commonest cause is a rename, so when the deprecation
message is purely an announcement, say so in the report rather than leaving the
severity to speak for itself.

## PKG_UNKNOWN — Direct dependency does not resolve on the registry

**What it is**: The registry returns 404 for a declared direct dependency.

**Why it matters**: Three possibilities, and they need distinguishing: a typo
(a typosquat waiting to be registered), a package that was removed — often
because it was found to be malicious — or a private package resolved from an
internal registry. The first two are serious.

**Vulnerable example**:

```json
{ "dependencies": { "lodahs": "^4.17.21" } }
```

**Safe example**:

```json
{ "dependencies": { "lodash": "^4.17.21" } }
```

**Detection**: A 404 from the registry maps to `found: false` with
`lookupError: false` — genuinely not published, as opposed to a 500 which means
we do not know and lands in `skipped[]`. Reported at HIGH severity. Confidence
is HIGH for a bare name and MED for a scoped one (`@scope/…`), where an internal
package on a private registry is the likelier explanation than malware.

**False positives**: **This is the rule most likely to be noisy in practice.**
npm returns 404 for private scoped packages when the request is unauthenticated,
so a team with `@company/*` internal packages will get a HIGH finding per package
on a completely clean tree. Check whether the name is scoped to an organization
before treating it as an attack, and consider the finding advisory in that case.

## PKG_NEW — Direct dependency was first published very recently

**What it is**: The package's earliest release is less than 30 days old.

**Why it matters**: Newly-published packages carry elevated supply-chain risk.
Typosquats and dependency-confusion packages are new by construction, and a
package with no history has no track record of responsible maintenance to weigh.

**Vulnerable example**:

```json
{ "dependencies": { "mcp-helper-utils": "^0.0.1" } }
```

**Safe example**:

```json
{ "dependencies": { "zod": "^3.23.8" } }
```

**Detection**: Compare the registry's earliest publish timestamp — npm
`time.created`, or the minimum release upload time on PyPI — against a 30-day
threshold. Reported at MED.

**False positives**: Every package is new once, and depending on a brand-new
package from a maintainer you trust is a normal choice. Genuine first-party
packages published days ago will fire this. It is a prompt to look, not a defect.

## PKG_LOWDL — Direct dependency has very low download volume

**What it is**: Fewer than 100 weekly downloads.

**Why it matters**: Download volume is a rough proxy for how many people would
notice something wrong. A package almost nobody uses has had almost nobody read
it, and a malicious release can sit unreported for a long time. Combined with
PKG_NEW it is a strong typosquat signal.

**Vulnerable example**:

```json
{ "dependencies": { "leftpad-utils-fork": "^1.0.0" } }
```

**Safe example**:

```json
{ "dependencies": { "express": "^4.18.0" } }
```

**Detection**: Read weekly downloads from
`https://api.npmjs.org/downloads/point/last-week/<name>` and report below 100.
Reported at LOW. **Scope**: this figure is npm-only, and the downloads API is
best-effort even for npm. When no count comes back — every PyPI package, plus any
npm package whose lookup failed or was rate-limited — the rule does not run, and
the packages it could not check are named in `skipped[]`. It never reports an
unchecked package as clean.

**False positives**: Internal, niche, and recently-renamed packages all have low
counts legitimately. A package that is popular but consumed mainly through a
mirror or a monorepo will under-report. Weak signal alone; meaningful in
combination.

## INSTALL_SCRIPTS — Direct dependency runs install scripts

**What it is**: The package declares `preinstall`, `install`, or `postinstall`
scripts.

**Why it matters**: Install scripts execute arbitrary code on the developer's
machine at install time, before any code review, and before the package is ever
imported. This is the most-used supply-chain execution vector in the npm
ecosystem — compromising a package with install scripts means compromising every
machine that installs it.

**Vulnerable example**:

```json
{ "name": "some-tool", "scripts": { "postinstall": "node ./scripts/setup.js" } }
```

**Safe example**:

```json
{ "name": "some-tool", "scripts": { "build": "tsc -p ." } }
```

**Detection**: Read the `scripts` object of the package's latest version from the
registry and report the presence of any of `preinstall`, `install`,
`postinstall`. Reported at MED. **Scope**: npm-only, same as PKG_LOWDL. PyPI's
equivalent — `setup.py` executing at install time — is not detectable from the
PyPI JSON API, which exposes no sdist contents, so the rule does not run for
Python packages and names each one in `skipped[]`. Treat a Python dependency as
un-assessed for install-time execution, not as free of it.

**False positives**: Native modules legitimately need install-time compilation,
and many well-known packages have benign postinstall steps. The finding says
"this package can run code at install time", which is true and worth knowing; it
does not say the code is malicious.

## NO_REPO — Direct dependency has no linked source repository

**What it is**: The registry entry declares no repository URL.

**Why it matters**: Without a linked repo there is no way to read what the
published artifact was built from, no issue tracker, and no history. The
published tarball is the only artifact, and it cannot be compared against source.
Malicious packages routinely omit the field.

**Vulnerable example**:

```json
{ "name": "mystery-pkg", "version": "1.0.0" }
```

**Safe example**:

```json
{ "name": "zod", "version": "3.23.8", "repository": "https://github.com/colinhacks/zod" }
```

**Detection**: Read `repository.url` (npm) or the `Source`/`Repository`/`Homepage`
project URLs (PyPI), strip a `git+` prefix and `.git` suffix, and require an
`http`/`https` result. Reported at LOW.

**False positives**: Plenty of old but perfectly good packages predate the
convention. A repo link is also not proof — it can point anywhere, and the
published artifact need not match it. Weak signal on its own.

## STALE — Direct dependency has not been updated in over 18 months

**What it is**: The most recent release is more than 548 days old.

**Why it matters**: A long-unmaintained dependency will not receive a fix when a
vulnerability is found in it. That is the whole concern — not that old code is
bad, but that there is nobody to respond.

**Vulnerable example**:

```json
{ "dependencies": { "abandoned-parser": "^0.4.1" } }
```

**Safe example**:

```json
{ "dependencies": { "zod": "^3.23.8" } }
```

**Detection**: Compare the registry's latest-modification timestamp against a
548-day threshold. Reported at LOW.

**False positives**: Small, complete, single-purpose packages are often finished
rather than abandoned, and a stable package with no releases may be a sign of
quality. Weigh it against whether the package has open unaddressed security
issues, not against release frequency alone.

## TRUST_BOUNDARY — Informational count of the dependency tree

**What it is**: An informational finding stating how many packages the lockfile
places inside the trust boundary.

**Why it matters**: It makes the actual size of the attack surface visible. Users
consistently underestimate it — a server with six direct dependencies routinely
carries several hundred transitively, and every one of them runs with the
agent's privileges. The number is the point.

**Vulnerable example**:

```
TRUST_BOUNDARY  /p/package-lock.json  [rule]
  1,417 packages in the trust boundary (npm package-lock)
```

**Safe example**:

```
TRUST_BOUNDARY  /p/package-lock.json  [rule]
  12 packages in the trust boundary (npm package-lock)
```

**Detection**: Emitted once per successfully parsed lockfile at LOW severity,
carrying the parsed count and the format label. It is not a defect and should
never be presented as one.

Two things make the count a floor rather than a total. Prebuilt binaries and
vendored code do not appear in a lockfile at all, so a tree heavy in native
modules understates its real surface considerably. And parsing caps at
`MAX_DEPS` (2000); when the cap is hit, the overflow is recorded in `skipped[]`
with the true total, so a large monorepo can never read as fully scanned.

**False positives**: Not applicable in the usual sense — the finding is a
measurement. The failure mode to watch for is a count that looks implausibly low,
which usually means a parser gap rather than a small project.
