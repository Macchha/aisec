import { createHash } from 'node:crypto';

/**
 * Stable identity for a finding, shared by the SARIF converter and the CI gate.
 *
 * They must agree by construction: a baseline written from one and checked by the
 * other would silently suppress the wrong findings, or none, and a gate that
 * suppresses the wrong findings is worse than no gate.
 *
 * The line is part of the identity on purpose. A finding that moved is a row a
 * human should look at again, not one a baseline should keep hiding.
 */
export function fingerprint(f) {
  return createHash('sha256')
    .update([f.id, f.file ?? '', f.line ?? '', f.message ?? ''].join(' '))
    .digest('hex')
    .slice(0, 16);
}

/** Skips have no file or line, so their text is their identity. */
export function skipFingerprint(text) {
  return createHash('sha256').update(`AISEC_SKIPPED ${text}`).digest('hex').slice(0, 16);
}
