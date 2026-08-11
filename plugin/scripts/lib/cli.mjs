import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

/**
 * True when `metaUrl` belongs to the module Node was launched with.
 *
 * The naive guard — `import.meta.url === \`file://${process.argv[1]}\`` — is wrong three
 * ways, and every one of them fails *open*: the CLI exits 0 having printed nothing, so a
 * caller reads success and parses empty stdout.
 *   - `import.meta.url` is percent-encoded, `process.argv[1]` is not, so any path
 *     containing a space (plugin install roots routinely do) never matches.
 *   - `import.meta.url` is resolved through symlinks, `process.argv[1]` is not, so
 *     launching via a symlinked path (macOS /tmp, homebrew, npm bin shims) never matches.
 *   - Windows paths never produce a `file://C:\…` URL, so it never matches at all.
 *
 * `argv1` is a parameter so the predicate is testable without spawning a process.
 */
export function isMainModule(metaUrl, argv1 = process.argv[1]) {
  if (!argv1) return false;
  try {
    return metaUrl === pathToFileURL(realpathSync(argv1)).href;
  } catch {
    // An argv[1] we cannot resolve is not this module; never guess it is.
    return false;
  }
}
