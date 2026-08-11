export const SEVERITIES = ['HIGH', 'MED', 'LOW', 'WARN'];
export const CONFIDENCES = ['HIGH', 'MED', 'LOW'];
export const SOURCES = ['rule', 'model'];

const SEV_RANK = { HIGH: 0, MED: 1, LOW: 2, WARN: 3 };
const CONF_RANK = { HIGH: 0, MED: 1, LOW: 2 };

export function finding({ id, severity, confidence = 'HIGH', source = 'rule', file, line = null, message, hint }) {
  if (!SEVERITIES.includes(severity)) throw new Error(`bad severity: ${severity}`);
  if (!CONFIDENCES.includes(confidence)) throw new Error(`bad confidence: ${confidence}`);
  if (!SOURCES.includes(source)) throw new Error(`bad source: ${source}`);
  return { id, severity, confidence, source, file, line, message, hint };
}

export function sortFindings(list) {
  return [...list].sort((a, b) =>
    SEV_RANK[a.severity] - SEV_RANK[b.severity] ||
    CONF_RANK[a.confidence] - CONF_RANK[b.confidence] ||
    a.id.localeCompare(b.id));
}

export function emptyReport() {
  return { findings: [], scanned: [], skipped: [] };
}

// Secrets must never be printed whole, not even in an error path.
export function mask(v) {
  const s = String(v);
  return s.length > 4 ? `${s.slice(0, 4)}…(${s.length} chars)` : `…(${s.length} chars)`;
}

export function lineOf(text, needle) {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) if (lines[i].includes(needle)) return i + 1;
  return null;
}

// Locates a JSON *property*, not just the quoted text. `lineOf(text, '"a"')` matches
// the first line containing `"a"` anywhere — including inside `"args"` — so short or
// generic server keys ("a", "db") were attributed to the wrong line.
export function lineOfKey(text, key) {
  const re = new RegExp(`"${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"\\s*:`);
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) if (re.test(lines[i])) return i + 1;
  return null;
}
