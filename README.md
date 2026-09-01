# aisec

Security scanning for MCP servers and agent applications — a Claude Code plugin
for the full rule set, and a CLI for the deterministic half.

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

**As a Claude Code plugin** — the full tool, all 37 rules:

```
/plugin marketplace add Macchha/aisec      # or a local path to this checkout
/plugin install aisec
```

**As a CLI** — the deterministic half, for CI and scripting:

```bash
npx github:Macchha/aisec scan ./my-mcp-server
```

Or from a checkout — no install step, since aisec has no runtime dependencies:

```bash
git clone https://github.com/Macchha/aisec && cd aisec
node bin/aisec.mjs scan ./my-mcp-server
```

The two are not equivalent, and the difference is the point below.

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

## The CLI covers half the rules, on purpose

The CLI runs the **deterministic scripts only**. Nineteen of the thirty-seven
rules need reading comprehension — whether a description is issuing orders,
whether a parameter reaches a sink, whether a path check actually contains — and
a CLI has no model to do that with.

| | Plugin (`/aisec-review`) | CLI (`aisec scan`) |
|---|---|---|
| Config, unicode, dependencies | yes | yes |
| MCP001, MCP003–MCP008 | yes | **no** |
| MCP010–MCP015, MCP020–MCP025 | yes | **no** |

**Every CLI report names the rules it did not run**, in `skipped[]`, every time —
including on a report with no findings at all. A tool that quietly applies half
its rule set while its own documentation advertises the whole set is the
"unknown reads as clean" failure promoted to product level, and this project has
hit that failure often enough to refuse it here.

So the CLI never prints "clean". A run where every check completed and found
nothing says *every check ran and found nothing*; anything less says what was
missed.

```
aisec scan ./server                          # text, gate on HIGH
aisec scan ./server --format sarif -o s.sarif
aisec scan ./server --offline --fail-on med
aisec scan ./server --write-baseline .aisec-baseline.json
aisec scan ./server --baseline .aisec-baseline.json
```

Exit `0` gate passed, `1` gate failed, `2` aisec itself failed — in every
format, so `--format sarif` stays usable in CI. All the gate flags from the
[CI gating](#ci-gating) section apply.

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

## CI gating

```bash
node plugin/scripts/scan-lockfile.mjs . | node plugin/scripts/gate.mjs
```

Exit `0` if the gate passes, `1` if it fails, `2` if the tool itself errored —
so a broken scan never reads as a green build.

| Flag | Default | |
|---|---|---|
| `--fail-on high\|med\|low\|none` | `high` | `med` also catches `WARN`, since `TRIFECTA` is a risk posture rather than something milder than `LOW` |
| `--fail-on-skipped` | off | Fail when any check could not run |
| `--baseline b.json` | — | Suppress findings already recorded |
| `--write-baseline b.json` | — | Record current findings and exit 0 |

**A skipped check never fails the build by default, and never reads as clean.**
Those are two different things. Failing on every skip would make an offline or
air-gapped run impossible; letting a skip pass silently would mean a green build
while a hundred packages went unchecked. So the gate prints the unchecked work
either way, and only a fully-checked tree with nothing found gets the words
"every check ran and found nothing". `--fail-on-skipped` turns the warning into
an error when you want the stronger guarantee.

**Baselines record findings, never skips.** Suppressing a skip would hide that a
check stopped running. A skip you have accepted is expressed by *not* passing
`--fail-on-skipped`, which is visible in your CI config, rather than buried in a
file nobody rereads. Baseline entries carry the rule, file, line and message, so
the suppression list can be reviewed by hand — a file of bare hashes is a file
nobody audits. Entries that no longer match anything are reported so they can be
pruned, and a finding that *moved* counts as new, because it is a row worth
reading again.

### GitHub Actions

```yaml
- name: Scan
  run: npx github:Macchha/aisec scan . --format sarif -o aisec.sarif --baseline .aisec-baseline.json
  # A failing gate should still publish its findings — they matter most in the
  # run that failed. The exit code comes from the step after the upload.
  continue-on-error: true

- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: aisec.sarif }

- name: Gate
  run: npx github:Macchha/aisec scan . --baseline .aisec-baseline.json --fail-on high
```

Use `aisec scan`, not an individual script under `plugin/scripts/`. Each script
covers one input — configs, invisible characters, or dependencies — so running
one alone produces a report that looks complete and is not. `scan` runs all
three and merges what each of them could not check.

Generate the baseline once, commit it, and the gate then fails only on findings
newer than it:

```bash
npx github:Macchha/aisec scan . --write-baseline .aisec-baseline.json
```

Keep that file small and reviewed. Regenerating it to turn a red build green
absorbs every new finding along with the old, which is the failure this tool
exists to prevent. Prune stale entries instead — the gate lists them.

aisec's own CI does exactly this; see `.github/workflows/ci.yml`.

## Requirements

Node 20 or newer. **Zero runtime dependencies.** The devDependencies are vitest
and ajv (which validates the SARIF output against the official 2.1.0 schema in
the test suite); none of them ship. Nothing in a scanned project is ever
installed, resolved, or executed.

## Repository layout

```
bin/aisec.mjs               ← the CLI entry point
plugin/                     ← everything an install carries
  .claude-plugin/plugin.json
  commands/aisec-review.md
  skills/scanning-mcp-servers/   SKILL.md + references/
  scripts/                       the deterministic scanners, shared by both
.aisec-baseline.json        ← aisec's own two accepted findings
.github/workflows/ci.yml    ← tests on Node 20/22/24, plus aisec scanning aisec
tests/                      ← not shipped
  fixtures/                      including a deliberately-exploitable server
docs/                       ← not shipped
```

The CLI and the plugin run the same scripts under `plugin/scripts/` rather than
two implementations, so the two cannot drift on severities, rule IDs, or exit
codes.

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
