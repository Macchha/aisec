# Agent config rules (SECRET_INLINE … TRIFECTA)

These eight rules are implemented deterministically in
`scripts/scan-config.mjs`, which runs **before** any source is read. The model
must not duplicate their findings — they are already fixed in the report, and
restating them as model judgment weakens the `rule` / `model` distinction that
tells a reader which findings are reproducible.

They operate on `.mcp.json`, `claude_desktop_config.json`, and equivalents. Note
that config is where cross-server composition becomes visible, which is why
`TRIFECTA` lives here rather than in the source rules.

## SECRET_INLINE — Credential stored in plaintext in the config

**What it is** (HIGH): A server's `env` block contains a literal credential
rather than a reference resolved at launch.

**Why it matters**: Agent configs are routinely committed, synced between
machines, pasted into issues, and shared while debugging. A key in `.mcp.json`
is a key in git history. Because the file is not code, it escapes the secret
scanning that most teams apply to source.

**Vulnerable example**:

```json
{ "mcpServers": { "files": {
  "command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/srv"],
  "env": { "TOKEN": "sk-ant-api03-N0tA5ecr3tJustAF4keK3yF0rD0cs99" } } } }
```

**Safe example**:

```json
{ "mcpServers": { "files": {
  "command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/srv"],
  "env": { "TOKEN": "${ANTHROPIC_API_KEY}" } } } }
```

**Detection**: Only `env` values are examined, and only for servers the config
declares. Two paths. First, known-prefix patterns anchored end to end:
`sk-ant-`, `sk-`, `ghp_`/`gho_`/`ghu_`/`ghs_`, `github_pat_`, `AKIA`, `xox[baprs]-`,
`AIza`. Second, a generic high-entropy fallback, applied only when no prefix
pattern matched, for values with **length ≥ 24, no space character, and Shannon
entropy ≥ 4.2**. The space guard is what keeps prose out of the fallback; it
also means a secret embedded in a longer sentence (`"token is …"`) is missed by
the fallback, though a prefixed key in that position is missed too, since the
prefix patterns are anchored with `^`/`$` against the whole value.

Values matching the placeholder pattern are excluded before either path: a
leading `$` or `<`, or the value containing `YOUR`, `CHANGE`, `EXAMPLE` or
`XXXX` **anywhere, case-insensitively**. That last part is broader than it
looks — `sk-ant-…examplekey…` and `…UNCHANGED…` are both skipped as
placeholders. When writing fixtures or documentation, a "fake" key built out of
the word `EXAMPLE` will silently not fire; make it high-entropy and obviously
synthetic by its wording instead, and verify by running the scanner rather than
by eye.

**Every reported value is masked** to its first four characters, then `…(<n>
chars)` — the scanner never prints a secret, and neither may the model.

**False positives**: A `${VAR}` reference is the intended fix and is excluded by
the placeholder rule. Long non-secret values — a base64 icon, a UUID list, a
connection string with no credential — can clear the entropy bar; check whether
the value bears authority before reporting. Documentation examples inside a
fixture directory are deliberate. Note the converse risk too: because the
placeholder exclusion is a case-insensitive substring test, a real credential
that happens to contain `example` (a key for `example.com`, say) is skipped, so
absence of this finding is not evidence of absence of secrets.

## TYPOSQUAT — Server package name is a near-miss of a well-known package

**What it is** (HIGH): The package a server launches is one or two edits away
from a widely-used MCP server's name.

**Why it matters**: The config is the install instruction. A user who copies a
snippet with `server-filesysten` in it installs an attacker's package with the
full privileges the real one would have had, and the config looks correct at a
glance. This is the supply-chain attack that needs no compromise of any real
package.

**Vulnerable example**:

```json
{ "mcpServers": { "squatted": {
  "command": "npx", "args": ["@modelcontextprotocol/server-filesysten@1.0.0"] } } }
```

**Safe example**:

```json
{ "mcpServers": { "files": {
  "command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0"] } } }
```

**Detection**: Implemented in `scripts/scan-config.mjs` against the
`KNOWN_SERVERS` table. Compute Levenshtein distance between the configured
package name and each known name; report when **distance ≤ 2, the length
difference is ≤ 2, and the two entries are in the same ecosystem**
(`npm` vs `PyPI`), and the name is not an exact match in that ecosystem. The
length guard stops short names from matching everything; the ecosystem guard
means a PyPI package is never compared against an npm one, so a PyPI name
shadowing an npm server (or the reverse) is not detected by this rule — flag it
in prose if you see it. Only the first near-match found is reported. Exact
matches are never reported.

**False positives**: A legitimate fork or a scoped republish (`@myorg/server-filesystem`)
is close by edit distance but intentional — check the scope. Genuinely distinct
packages with similar names in a crowded namespace exist; weigh whether the
near-match is to a package the config would plausibly want.

## VERSION_UNPINNED — Server package runs without an exact version

**What it is** (MED): The package spec carries no version, or a range rather than
an exact pin.

**Why it matters**: `npx @scope/server` resolves to whatever is newest at launch,
every launch. A package that was audited last week can ship a different payload
today with no action by the user — the rug-pull attack at the dependency layer
rather than the metadata layer. It also means the thing you scanned is not
necessarily the thing that runs.

**Vulnerable example**:

```json
{ "mcpServers": { "files": {
  "command": "npx", "args": ["@modelcontextprotocol/server-filesystem"] } } }
```

**Safe example**:

```json
{ "mcpServers": { "files": {
  "command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0"] } } }
```

**Detection**: Parse the package spec from the runner's first positional
argument (`npx`, `bunx`, `pnpx`, `uvx`, or `python -m`). The implementation
reports when **no version follows the name**, or when the version is exactly
`latest`, or when it **starts with `^` or `~`**. An exact semver is the only
clean state.

That list is narrower than the rule's intent, and the gap is worth knowing
because it covers the two most dangerous specs. **`@next`, `@*`, `@1.x`,
`@>=1.0.0`, `@beta` and `@canary` are all currently missed** — `@next` and `@*`
in particular are exactly what this rule exists to catch, since both resolve to
whatever the registry serves at launch. The check should be inverted to *accept
only an exact semver* rather than enumerating range syntaxes, and until it is,
read the version yourself: any spec that is not a bare `X.Y.Z` (optionally with
a prerelease suffix) is unpinned in fact whether or not the script fired. If you
find one the script missed, report it as a model finding and say the script did
not fire; do not restate a `VERSION_UNPINNED` the script already emitted.

**False positives**: A server launched from a local path or a lockfile-backed
workspace is already pinned by other means. A `@latest` on a package the user
themselves publishes is a deliberate choice, though still worth surfacing at LOW.

## FS_BROAD — Filesystem server rooted at a broad path

**What it is** (HIGH): A filesystem-capable server is configured with a root of
`/`, `~`, `$HOME`, `/Users`, `/home`, or a drive root.

**Why it matters**: The root is the entire authorization boundary for a
filesystem server. Rooted at `~`, it exposes SSH keys, browser profiles, cloud
credentials, and every private document — to any prompt that reaches the model.
Users pick a broad root for convenience during setup and never narrow it.

**Vulnerable example**:

```json
{ "mcpServers": { "files": {
  "command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "~"] } } }
```

**Safe example**:

```json
{ "mcpServers": { "files": {
  "command": "npx",
  "args": ["@modelcontextprotocol/server-filesystem@1.0.0", "/Users/me/projects/thisapp"] } } }
```

**Detection**: For servers whose capabilities include `fs`, examine the path
arguments and report any that is an **exact string match** for a member of the
broad set: `/`, `~`, `$HOME`, `/Users`, `/home`, `C:\`, `C:/`. Capability is
determined from the `KNOWN_SERVERS` table (falling back to a keyword guess from
the package name, server key and URL for unknown packages) rather than guessed
from the name alone. No normalisation is performed: the argument is compared
literally, before any tilde or variable expansion.

Exact matching is a real gap, not a subtlety. **`~/`, `$HOME/`, `${HOME}`,
`/Users/me`, `/home/me`, `/Users/me/`, `C:\Users\me` and `.` are all missed**,
and every one of them is a home directory or worse. `~/` differs from `~` by a
single character and is the form a shell user is most likely to type. The check
should normalise (expand `~` and `$HOME`, strip trailing separators) and then
test whether the path is a home directory, a filesystem root, or a direct parent
of one, rather than comparing strings. Until it does, **read the path arguments
yourself** on every `fs`-capable server; if the root is a home directory or
broader and the script did not fire, report it as a model finding at HIGH and
note that the deterministic check missed it.

**False positives**: A read-only server rooted broadly is still a disclosure
risk, so the rule stands, though severity can be discussed. A path that starts
with `/Users` but names a specific project directory —
`/Users/me/projects/thisapp` — is genuinely narrow and is not a finding. That is
the only case the exact-match behaviour gets right for the right reason; do not
generalise from it to `/Users/me`, which is a home directory and is a finding
whether or not the script emitted one.

## EXEC_SERVER — Server can execute commands or drive a browser

**What it is** (MED): A configured server has command-execution or
browser-automation capability.

**Why it matters**: These servers convert model output into actions on the host.
That is often exactly what the user wants, so this is an awareness finding rather
than a defect — but it is the capability that turns every other finding into
something worse, and it is the `exec` leg of the trifecta below.

**Vulnerable example**:

```json
{ "mcpServers": { "shell": {
  "command": "npx", "args": ["some-shell-server@1.0.0"] } } }
```

**Safe example**:

```json
{ "mcpServers": { "docs": {
  "command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0", "/srv/docs"] } } }
```

**Detection**: Look up each server in `KNOWN_SERVERS` and report when its
capability set includes `exec`. For unknown packages, infer from the name only
with low confidence — the deterministic rule covers the known set, and guessing
beyond it produces noise.

**False positives**: Not a vulnerability on its own. Report it, but do not
present it as a defect when the user's whole purpose is a shell or browser
server. Its real weight comes from composition — see TRIFECTA.

## REMOTE_HTTP — Remote server reached over plaintext HTTP

**What it is** (HIGH): A remote server URL uses `http://` to a non-local host.

**Why it matters**: Everything on that channel is readable and modifiable in
transit: the tool results the model will act on, and any credentials in headers.
An attacker on the path can rewrite a tool response, which is prompt injection
with no need to compromise either endpoint.

**Vulnerable example**:

```json
{ "mcpServers": { "remote": { "url": "http://insecure.example/mcp" } } }
```

**Safe example**:

```json
{ "mcpServers": { "remote": { "url": "https://secure.example/mcp",
  "headers": { "Authorization": "Bearer ${MCP_TOKEN}" } } } }
```

**Detection**: Report any `url` with an `http://` scheme whose host is not
loopback. The loopback set is exactly `localhost`, `127.0.0.1` and `::1` —
plaintext to loopback does not cross a network. The host is taken from a parsed
`URL`; if the URL does not parse, the host is empty, which is not in the
loopback set, so an unparseable `http://…` value is still reported. Other
loopback spellings (`127.0.0.2`, `0.0.0.0`, `[::1]` written unbracketed, a
`.localhost` subdomain) are not in the set and will be reported.

**False positives**: A development server on a trusted, isolated network is a
real case, but "trusted network" is an assumption worth stating out loud rather
than silently accepting. Loopback is already excluded, so the remaining matches
genuinely traverse something.

## REMOTE_NOAUTH — Remote server configured without an auth header

**What it is** (MED): A remote server entry carries no `Authorization` or
API-key header.

**Why it matters**: Either the endpoint is unauthenticated — in which case
anyone who learns the URL has the same access the agent has — or authentication
happens somewhere invisible to the config, which is worth confirming rather than
assuming. Unauthenticated remote MCP endpoints are a standing invitation.

**Vulnerable example**:

```json
{ "mcpServers": { "remote": { "url": "https://api.example/mcp" } } }
```

**Safe example**:

```json
{ "mcpServers": { "remote": { "url": "https://api.example/mcp",
  "headers": { "Authorization": "Bearer ${MCP_TOKEN}" } } } }
```

**Detection**: For entries with a `url`, check the `headers` object for a key
matching `/auth/i` or exactly `x-api-key` (case-insensitive). Absence is the
finding — **except for loopback URLs**, which are excluded using the same
`localhost` / `127.0.0.1` / `::1` set as REMOTE_HTTP. A local server reached
over loopback is authenticated by the machine boundary, so an unauthenticated
loopback entry is deliberately not reported here; MCP021 and MCP022 are the
rules that cover what can reach it.

**False positives**: Authentication may be carried by a cookie, mTLS, a signed
URL, or a network boundary — none visible in the config. Treat this as "unable
to confirm authentication" rather than "definitely unauthenticated", and say so
in the report.

## TRIFECTA — Config combines private data, untrusted content, and an exfil path

**What it is** (WARN): Across all configured servers, the agent holds all three
of: access to private data, exposure to untrusted content, and an outbound
channel.

**Why it matters**: This is the lethal trifecta, and it is the finding no
single-server review can produce. Each server is individually defensible. Held
together by one agent, they compose into a pipeline: read something private,
pull in attacker-controlled instructions, send the private thing out. No
server's own code is at fault, which is precisely why it goes unnoticed.

**Vulnerable example**:

```json
{ "mcpServers": {
  "files":  { "command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0", "~"] },
  "search": { "command": "npx", "args": ["@modelcontextprotocol/server-brave-search@1.0.0"] },
  "shell":  { "command": "npx", "args": ["some-shell-server@1.0.0"] } } }
```

**Safe example**:

```json
{ "mcpServers": {
  "files": { "command": "npx",
    "args": ["@modelcontextprotocol/server-filesystem@1.0.0", "/Users/me/projects/thisapp"] } } }
```

**Detection**: Union the capability sets of every configured server via
`KNOWN_SERVERS` (with the keyword fallback for unknown packages). Report when
the union contains all three of:

| Leg | Capabilities |
| --- | --- |
| private data | `fs`, `data`, **or `msg`** |
| untrusted content | `fetch` |
| outbound channel | `fetch`, `exec`, or `msg` |

`msg` counts on both the private-data and outbound legs, and omitting it from
the private-data leg would miss a canonical case: `server-slack` carries exactly
`['msg']` and nothing else, so a Slack server plus any `fetch` server is a
complete trifecta with no `fs` or `data` server present at all. A messaging
server both holds private conversation history and can send it somewhere.

Note that `fetch` alone satisfies two legs, so any single server with `fetch`
plus any server with `fs`/`data`/`msg` is a report. Emitted once per config, not
per server, with `line: null` and the config path in `file` — it is a property
of the combination, so it has no source line to point at.

**False positives**: The trifecta is a risk posture, not a bug, which is why it
is reported at `WARN` rather than as a defect. Many legitimate setups need all
three. The value is in making the composition explicit so the user can decide —
narrow the filesystem root, drop a server, or accept it knowingly.
