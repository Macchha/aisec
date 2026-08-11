# Eval — clean fixture — networked, n=3 — 2026-08-11

aisec 0.1.0. `tests/fixtures/clean-server`, dependency scanner run **without
`--offline`**. Three independent cold agents following `SKILL.md` from disk.

Companion to `2026-08-11-vulnerable-networked.md`. Together they close the
networked and `n=3` follow-ups from 2026-08-08.

## Result: **PASS**, unanimous

| Run | Findings | Rule | Model |
|---|---|---|---|
| 1 | 1 | 1 | 0 |
| 2 | 1 | 1 | 0 |
| 3 | 1 | 1 | 0 |

`TRUST_BOUNDARY` only, all three times. No HIGH, no MED, no WARN, no model
finding. **Zero false positives at n=3, over a live network path.**

Every run confirmed `skipped[]` was empty across all three scripts and said so
explicitly — the distinction between "checked and clean" and "could not check"
held under the one condition where it is easiest to lose, a networked run that
could have failed silently.

## What the runs did well, unprompted

**They treated the fixture's comments as claims to verify, not facts to use.**
`src/index.ts` carries comments explaining why the code is safe. All three
recorded them under `Scan integrity`, correctly declined to file them as MCP001
under the rule clarified earlier the same day, and then **checked each claim
against the code**:

- Run 2 grepped for `createServer`, `.listen(`, `express`, `cors`,
  `SSEServerTransport`, `StreamableHTTP` to confirm the "stdio only" claim
  rather than accepting it.
- Runs 1, 2 and 3 all independently verified that the sentinel-strip regex
  actually matches the *nonced* closing tag — the specific thing that makes the
  MCP024 wrapper unspoofable.
- All three confirmed `list_versions`' handler reads no arguments before
  accepting its empty schema.

**All three volunteered the same residual risk** on `containedPath`: the
resolve → realpath → re-check pattern is time-of-check-to-time-of-use racy, and
closing it needs `O_NOFOLLOW` or a directory-handle read. None filed it as a
finding, since `rules-dataflow.md` acknowledges the same residual in its own
safe example — the right call, stated rather than silently dropped.

## Fixture change made after this run

The clean fixture's comments named aisec's own rule IDs (`MCP024`, `MCP020`).
All three runs verified independently rather than deferring, so this was not a
calibration failure — but a false-positive guard should not be arguing its own
case, and a weaker model might simply believe it. The security rationale is
kept, since a well-engineered server genuinely does explain why it realpaths;
the scanner-rule references are gone.
