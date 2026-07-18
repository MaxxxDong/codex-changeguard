/**
 * Canonical openai/codex issue URL parsing — explicit subscriptions only.
 * No repository-wide crawl; refuse non-canonical hosts/repos/paths.
 */
import {
  CANONICAL_ISSUE_PATH_RE,
  MAX_ISSUE_NUMBER,
  OFFICIAL_HOST,
  OFFICIAL_REPOSITORY,
} from "./limits.js";
import type { CanonicalIssueRef } from "./types.js";

export class IssueUrlError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "IssueUrlError";
  }
}

function buildRef(issue_number: number): CanonicalIssueRef {
  return {
    host: OFFICIAL_HOST,
    repository: OFFICIAL_REPOSITORY,
    issue_number,
    canonical_url: `https://${OFFICIAL_HOST}/${OFFICIAL_REPOSITORY}/issues/${issue_number}`,
  };
}

/** Parse a bare positive issue number (1..MAX). */
export function parseIssueNumber(raw: unknown): number {
  if (typeof raw === "number" && Number.isInteger(raw) && raw >= 1 && raw <= MAX_ISSUE_NUMBER) {
    return raw;
  }
  if (typeof raw === "string") {
    const t = raw.trim();
    if (/^[1-9][0-9]{0,7}$/.test(t)) {
      const n = Number(t);
      if (n >= 1 && n <= MAX_ISSUE_NUMBER) return n;
    }
  }
  throw new IssueUrlError("INVALID_ISSUE", "Invalid issue number.");
}

/**
 * Accept only:
 * - bare issue number
 * - https://github.com/openai/codex/issues/N (optional trailing slash)
 * Refuse userinfo, non-default ports, other hosts/repos, query, fragment-as-authority.
 */
export function parseCanonicalIssue(input: string | number): CanonicalIssueRef {
  if (typeof input === "number") {
    return buildRef(parseIssueNumber(input));
  }
  if (typeof input !== "string" || input.length === 0 || input.length > 512) {
    throw new IssueUrlError("INVALID_ISSUE", "Invalid issue reference.");
  }
  const trimmed = input.trim();
  // Bare number
  if (/^[1-9][0-9]{0,7}$/.test(trimmed)) {
    return buildRef(parseIssueNumber(trimmed));
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new IssueUrlError("UNAUTHORIZED_ISSUE", "Non-canonical issue URL refused.");
  }

  if (url.protocol !== "https:") {
    throw new IssueUrlError("UNAUTHORIZED_ISSUE", "Non-HTTPS issue URL refused.");
  }
  if (url.username || url.password) {
    throw new IssueUrlError("UNAUTHORIZED_ISSUE", "Issue URL userinfo refused.");
  }
  if (url.port !== "") {
    throw new IssueUrlError("UNAUTHORIZED_ISSUE", "Issue URL non-default port refused.");
  }
  if (url.hostname.toLowerCase() !== OFFICIAL_HOST) {
    throw new IssueUrlError("UNAUTHORIZED_REPOSITORY", "Non-official host refused.");
  }
  // Query strings are not part of the resource identity; refuse rather than strip silently
  // when they look like tracking — but GitHub issue URLs with empty query are fine.
  // Fragments are stripped (client-only); path must match exactly.
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const m = path.match(CANONICAL_ISSUE_PATH_RE);
  if (!m) {
    // Wrong repo or path shape
    if (!path.startsWith(`/${OFFICIAL_REPOSITORY}/`) && !path.startsWith("/openai/codex/")) {
      throw new IssueUrlError("UNAUTHORIZED_REPOSITORY", "Non-openai/codex repository refused.");
    }
    throw new IssueUrlError("UNAUTHORIZED_ISSUE", "Non-canonical issue path refused.");
  }
  const n = Number(m[1]);
  if (!Number.isInteger(n) || n < 1 || n > MAX_ISSUE_NUMBER) {
    throw new IssueUrlError("INVALID_ISSUE", "Invalid issue number.");
  }
  return buildRef(n);
}

export function isCanonicalIssueUrl(url: string): boolean {
  try {
    parseCanonicalIssue(url);
    return true;
  } catch {
    return false;
  }
}
