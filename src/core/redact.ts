/**
 * Redaction after NFKC normalization.
 * Strips absolute paths and credential-shaped tokens from user-visible strings.
 */

const ABS_PATH =
  /(?:\/(?:Users|home|tmp|var|private|System|Library|opt|usr)\/[^\s"'`]+)|(?:[A-Za-z]:\\[^\s"'`]+)|(?:\\\\[^\s"'`]+)/g;

const CREDENTIAL_SHAPES = [
  /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
  /\b(?:api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|password|passwd|secret|client[_-]?secret)\s*[:=]\s*\S+/gi,
  /\b(?:sk|pk|rk)-[A-Za-z0-9]{8,}\b/g,
  /\b(?:xox[baprs]-)[A-Za-z0-9-]{10,}\b/g,
  // Full-width underscore variants after NFKC still covered by above;
  // also catch API_KEY=value without word boundary issues.
  /\bAPI[_-]?KEY\s*[:=]\s*\S+/gi,
];

/** Full-width Latin letters/digits/punctuation → compatibility (NFKC). */
export function nfkc(input: string): string {
  return input.normalize("NFKC");
}

export function redactText(input: string): string {
  let s = nfkc(input);
  s = s.replace(ABS_PATH, "<redacted-path>");
  for (const re of CREDENTIAL_SHAPES) {
    s = s.replace(re, "<redacted-secret>");
  }
  // Full-width forms already NFKC'd; catch common leftover patterns.
  s = s.replace(
    /(?:api[_-]?key|token|password|secret)\s*[:=]\s*\S+/gi,
    "<redacted-secret>",
  );
  return s;
}

export function redactValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactText(value);
  }
  if (Array.isArray(value)) {
    return value.map(redactValue);
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactValue(v);
    }
    return out;
  }
  return value;
}

/** Ensure public payloads never contain absolute disposable clone paths. */
export function assertNoLeakPaths(text: string): string {
  const s = redactText(text);
  return s
    .replace(/\.grok-disposable\/[^\s"'`]+/g, "<redacted-path>")
    .replace(/grok-worker-[^\s"'`]+/g, "<redacted-id>");
}
