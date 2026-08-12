# aisec

Security scanning for MCP servers and agent applications, as a Claude Code
plugin.

Conventional SAST tools do not read tool descriptions, because to a parser a
description is an inert string literal. To an agent it is instructions, loaded
into context before the user asks for anything. aisec exists to close that gap —
and to cover the config and dependency surfaces around it.

## What it is, and what it is not

**It is** an automated scan of an MCP server's metadata, handler dataflow,
transport configuration, agent config, and dependency tree.

**It is not a code audit and not a guarantee.** It finds the classes of problem
it knows about. A clean report means those rules found nothing, not that the
server is safe.

## Install

```
/plugin marketplace add Macchha/aisec      # or a local path to this checkout
/plugin install aisec
```

## Usage

```
/aisec-review                              # scan the current directory
/aisec-review path/to/mcp-server           # scan a specific target
/aisec-review --json path/to/mcp-server    # also write aisec-report.json
```

Installed from a marketplace, the command may be addressed as
`/aisec:aisec-review` if another plugin also defines `aisec-review`.

### If you are editing the rules

An install is a **snapshot**, not a live link to this repository, and there are
two layers of staleness. Both bite silently — the scan still runs, just with the
rules you had earlier.

| Layer | What refreshes it |
|---|---|
| The plugin cache on disk | `claude plugin install aisec` — editing `plugin/` does nothing on its own |
| A skill already loaded in a running session | A **new session**. Reinstalling will not refresh it |

So after changing anything under `plugin/skills/` or `plugin/scripts/`:
reinstall, **then start a fresh session**. Verified the hard way — a scan run
during development silently used a superseded version of a rule that had been
corrected on disk minutes earlier.

## How findings are produced

Two layers, and the report always says which produced a finding.

**Deterministic scripts** (`source: rule`) own the checks with exact answers —
secret patterns and Shannon entropy, Levenshtein typosquat distance, invisible
codepoints, lockfile parsing and OSV lookups. They run **before** any source is
read, so their findings are fixed in the report before a hostile file can reach
the model.

**Model judgment** (`source: model`) owns what needs reading comprehension —
whether a description is issuing orders, whether a parameter reaches a sink,
whether a path check actually contains.

The split is the point. A reader can always tell which findings are reproducible
and which are judgment, and a server that talks the model into a different
conclusion cannot retract what the scripts already found.

### Never silently narrow

A check that could not run appears in `skipped[]` with a reason. It is never
omitted and never reported as a pass. "We could not check this" and "we checked
and it was clean" are different results and the tool keeps them different.

## Rules

### Tool metadata — `references/rules-metadata.md`

| ID | Severity | What it catches |
|----|----------|-----------------|
| MCP001 | HIGH | Model-directed instructions in a tool description |
| MCP002 | HIGH | Invisible or bidi Unicode hiding text from the reviewer |
| MCP003 | HIGH | Description redirecting calls to another server's tools |
| MCP004 | MED | Tool metadata computed at runtime — the rug-pull primitive |
| MCP005 | MED | Tool name colliding with a well-known tool |

### Handler dataflow — `references/rules-dataflow.md`

| ID | Severity | What it catches |
|----|----------|-----------------|
| MCP010 | HIGH | Parameter reaches shell execution |
| MCP011 | HIGH | Parameter reaches `eval` |
| MCP012 | HIGH | Parameter reaches a filesystem path with no containment check |
| MCP013 | MED | Parameter controls an outbound request URL (SSRF, exfil) |
| MCP014 | HIGH | Parameter concatenated into SQL |
| MCP015 | HIGH | Secret flows into an outbound request or tool output |

### Transport and contract — `references/rules-transport.md`

| ID | Severity | What it catches |
|----|----------|-----------------|
| MCP020 | MED | No input schema, or a permissive one |
| MCP021 | HIGH | HTTP/SSE transport with no Origin validation (DNS rebinding) |
| MCP022 | HIGH | Server binds all interfaces |
| MCP023 | MED | Wildcard or reflected CORS |
| MCP024 | MED | Fetched content returned to the model undemarcated |
| MCP025 | LOW | Raw exceptions or stack traces in tool output |

### Agent config — `references/rules-config.md` (deterministic)

| ID | Severity | What it catches |
|----|----------|-----------------|
| SECRET_INLINE | HIGH | Plaintext credential in a config `env` block |
| TYPOSQUAT | HIGH | Server package name a near-miss of a well-known one |
| VERSION_UNPINNED | MED | Package launched without an exact version |
| FS_BROAD | HIGH | Filesystem server rooted at `~`, `/`, or a drive root |
| EXEC_SERVER | MED | Server can execute commands or drive a browser |
| REMOTE_HTTP | HIGH | Remote server over plaintext HTTP |
| REMOTE_NOAUTH | MED | Remote server with no auth header |
| TRIFECTA | WARN | Private data + untrusted content + an outbound channel |

`TRIFECTA` is the one no single-server review produces. Each server is
individually defensible; together they compose into an exfiltration pipeline,
and no server's own code is at fault.

### Dependencies — `references/rules-sca.md` (deterministic)

| ID | Severity | What it catches |
|----|----------|-----------------|
| VULN_KNOWN | mapped | Package version matches a published OSV advisory |
| DEPRECATED | HIGH | Direct dependency marked deprecated |
| PKG_UNKNOWN | HIGH | Direct dependency does not resolve on the registry |
| PKG_NEW | MED | First published less than 30 days ago |
| PKG_LOWDL | LOW | Under 100 weekly downloads |
| INSTALL_SCRIPTS | MED | Runs pre/post-install scripts |
| NO_REPO | LOW | No linked source repository |
| STALE | LOW | No release in over 18 months |
| TRUST_BOUNDARY | LOW | Informational count of the dependency tree |

OSV severity maps as `CRITICAL`/`HIGH` → HIGH, `MODERATE`/`MEDIUM` → MED,
`LOW` → LOW, and `UNKNOWN` → **MED**. Unknown maps up rather than down on
purpose: an advisory we could not rank is unranked, not harmless, and OSV's
`MAL-` malware records carry no severity field at all. Those floor at CRITICAL
internally — though see Known limitations for why that does not survive into the
report's severity column.

## Known limitations

Documented rather than hidden — each rule's reference page carries its own.

**Scanning sends data off your machine.** The parsed dependency tree — including
the names and versions of private, scoped packages — goes to `api.osv.dev`, and
each direct dependency is looked up on `registry.npmjs.org` or `pypi.org`. Pass
`--offline` to the dependency scanner to suppress all of it; the checks that
cannot run then appear in `skipped[]` rather than silently passing.

- **`PKG_UNKNOWN` is noisy for private registries.** npm returns 404 for
  `@company/*` when unauthenticated, so a clean tree can produce a finding per
  internal package. Scoped names are reported at MED confidence for this reason;
  bare names stay HIGH.
- **Registry metadata rules are npm-first.** `PKG_LOWDL` and `INSTALL_SCRIPTS`
  are npm-only and never fire for PyPI. Python direct dependencies are collected
  from `pyproject.toml` `[project].dependencies` and `requirements.txt` only —
  Poetry's `[tool.poetry.dependencies]` and `[project.optional-dependencies]`
  are not read, and what is skipped is named in `skipped[]`.
- **`devDependencies` and `peerDependencies` are not scanned.** Install scripts
  run for devDependencies too, so this is a real gap, not a scoping choice. It
  is recorded in `skipped[]` on every scan.
- **Registry lookups cap at 25 direct dependencies.** The remainder is counted
  in `skipped[]`.
- `DEPRECATED` reads the flag from the package's *latest* version, so a project
  pinning a deprecated `1.x` under a current `2.x` will not trigger it.
- `TRUST_BOUNDARY`'s count is a floor. Prebuilt binaries and vendored code never
  appear in a lockfile, and parsing caps at 2000 packages — the overflow is
  reported in `skipped[]`.
- Vulnerability findings are not reachability-analysed. An advisory present in
  the tree may not be exploitable in the way the package is used.
- **Confirmed malware is not visually distinct.** OSV `MAL-` records are floored
  at CRITICAL internally, but the report scale has no CRITICAL level, so they
  render as HIGH alongside ordinary advisories. The `MAL-` id in the message is
  the only signal.
- Rules are pattern- and judgment-based, not a proof. A server can be written to
  evade them, and the model layer is nondeterministic — two scans of the same
  target can differ. The `rule`-sourced findings are the reproducible half.

## SARIF output

Any scanner's JSON converts to SARIF 2.1.0, for GitHub code scanning or any
other SARIF consumer:

```bash
node plugin/scripts/scan-lockfile.mjs . | node plugin/scripts/to-sarif.mjs > aisec.sarif
node plugin/scripts/to-sarif.mjs aisec-report.json > aisec.sarif   # or from a file
```

Severities map `HIGH → error`, `MED → warning`, `LOW → note`, and
`WARN → warning` — `WARN` is `TRIFECTA`, a risk posture rather than something
less severe than `LOW`, so it does not sort below it. Each rule also carries
`security-severity`, which is what GitHub actually ranks on.

**Skipped checks appear twice, on purpose.** SARIF has no first-class way to say
"this check could not run", and the one place it does provide —
`toolExecutionNotifications` — is ignored by most consumers including GitHub, so
a skip put only there becomes invisible. That would silently recreate the exact
failure this tool exists to prevent. Every skip is therefore emitted as a
`result` under the `AISEC_SKIPPED` rule *and* as a notification.
`run.properties` carries `findingCount` and `skippedCount` separately, so the
two never blur.

Findings about a package rather than a file — the SCA rules — use
`logicalLocations` with `kind: "package"`, not a fabricated file path. Each
result carries a stable `partialFingerprints.aisecFinding` so a CI consumer can
track it across runs.

## Not in V1

CI gating and a standalone CLI are V1.1. V1 is the plugin.

## Requirements

Node 20 or newer. **Zero runtime dependencies** — the only devDependency is
vitest. Nothing in a scanned project is ever installed, resolved, or executed.

## Repository layout

```
plugin/                     ← everything an install carries
  .claude-plugin/plugin.json
  commands/aisec-review.md
  skills/scanning-mcp-servers/   SKILL.md + references/
  scripts/                       the deterministic scanners
tests/                      ← not shipped
  fixtures/                      including a deliberately-exploitable server
docs/                       ← not shipped
```

The split is deliberate. `tests/fixtures/vulnerable-server/` contains a live
prompt-injection payload and a fake credential; shipping it into every
installer's plugin directory would trip their own secret scanners and EDR, so
the marketplace manifest points at `plugin/` rather than the repository root.

## Credits

The config and dependency rules are ported from
[vulnrable.com](https://vulnrable.com), with rule IDs preserved so findings
cross-reference between the two.

## Licence

MIT.
