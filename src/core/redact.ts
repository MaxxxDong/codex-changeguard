/**
 * Redaction after NFKC normalization.
 * Strips absolute paths and credential-shaped tokens from user-visible strings.
 */

/**
 * Generic absolute-path shapes after NFKC:
 * - POSIX absolute paths (any root, not only /Users|/home|…)
 * - Windows drive paths
 * - Windows UNC paths
 *
 * Avoid leaking /etc, /root, /Applications, or arbitrary absolute roots.
 */
const ABS_PATH_POSIX =
  /(?:^|[\s"'`=(,:\[{])(\/(?:[^/\s"'`]+\/)*[^/\s"'`]+)/g;
const ABS_PATH_WIN_DRIVE = /(?:^|[\s"'`=(,:\[{])([A-Za-z]:\\(?:[^\s"'`\\]+\\)*[^\s"'`]*)/g;
const ABS_PATH_WIN_UNC = /(?:^|[\s"'`=(,:\[{])(\\\\[^\s"'`]+(?:\\[^\s"'`]*)*)/g;

/** Standalone absolute POSIX path at start of string or after delimiter. */
const ABS_PATH_POSIX_STANDALONE = /(?:^|[\s"'`=(,:\[{])(\/[^\s"'`]+)/g;

const CREDENTIAL_SHAPES = [
  /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
  /\b(?:api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|password|passwd|secret|client[_-]?secret)\s*[:=]\s*\S+/gi,
  /\b(?:sk|pk|rk)-[A-Za-z0-9]{8,}\b/g,
  /\b(?:xox[baprs]-)[A-Za-z0-9-]{10,}\b/g,
  // GitHub classic PATs (ghp_…) and fine-grained PATs (github_pat_…).
  // High-confidence shapes only — do not match bare "github" identifiers.
  /\bghp_[A-Za-z0-9]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\b(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g,
  /\bAPI[_-]?KEY\s*[:=]\s*\S+/gi,
  // Cookie / session shapes (including after NFKC of full-width forms).
  /\bSet-Cookie\s*[:=]\s*\S+/gi,
  /\bCookie\s*[:=]\s*\S+/gi,
  /\bsession[_-]?(?:id|token|key|cookie)\s*[:=]\s*\S+/gi,
  /\b(?:JSESSIONID|PHPSESSID|connect\.sid)\s*[:=]\s*\S+/gi,
  // OTP / one-time codes and session rollout export bodies (device-only material).
  /\b(?:one[_-]?time[_-]?code|otp)\s*[:=]\s*\S+/gi,
  /\bsession[_-]?rollout(?:_content)?\s*[:=]\s*\S+/gi,
];

/** Full-width Latin letters/digits/punctuation → compatibility (NFKC). */
export function nfkc(input: string): string {
  return input.normalize("NFKC");
}

function redactAbsolutePaths(s: string): string {
  // Replace generic absolute paths with a placeholder. Use a function replacer
  // that preserves the leading delimiter character.
  const replacePath = (full: string, pathPart: string): string => {
    const leadLen = full.length - pathPart.length;
    const lead = leadLen > 0 ? full.slice(0, leadLen) : "";
    return `${lead}<redacted-path>`;
  };
  let out = s.replace(ABS_PATH_POSIX_STANDALONE, replacePath);
  out = out.replace(ABS_PATH_POSIX, replacePath);
  out = out.replace(ABS_PATH_WIN_DRIVE, replacePath);
  out = out.replace(ABS_PATH_WIN_UNC, replacePath);
  // Also catch bare absolute paths that fill an entire field.
  if (/^\/[^\s]+$/.test(out) || /^[A-Za-z]:\\[^\s]+$/.test(out) || /^\\\\[^\s]+$/.test(out)) {
    out = "<redacted-path>";
  }
  return out;
}

export function redactText(input: string): string {
  let s = nfkc(input);
  s = redactAbsolutePaths(s);
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
