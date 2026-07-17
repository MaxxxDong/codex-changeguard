import {
  EVIDENCE_KINDS,
  OFFICIAL_HOSTS,
  OFFICIAL_ORIGINS,
  OFFICIAL_REPOSITORIES,
} from "./limits.js";
import type { EvidenceKind } from "./types.js";

export class AllowlistError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "AllowlistError";
    this.code = code;
  }
}

export function isAllowedHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return (OFFICIAL_HOSTS as readonly string[]).includes(h);
}

export function isAllowedRepository(ownerRepo: string): boolean {
  return (OFFICIAL_REPOSITORIES as readonly string[]).includes(
    ownerRepo.toLowerCase(),
  );
}

export function isAllowedOrigin(origin: string): boolean {
  const o = origin.replace(/\/$/, "").toLowerCase();
  return (OFFICIAL_ORIGINS as readonly string[]).some(
    (allowed) => o === allowed.toLowerCase(),
  );
}

/**
 * Validate origin_allowlist: exact canonical official allowlist entries only
 * (full set or exact subset). Foreign values fail closed.
 */
export function assertOriginAllowlist(raw: unknown): string[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new AllowlistError(
      "ORIGIN_ALLOWLIST",
      "origin_allowlist must be a non-empty array of official origins.",
    );
  }
  const official = new Set(
    (OFFICIAL_ORIGINS as readonly string[]).map((o) => o.toLowerCase()),
  );
  const officialByLower = new Map(
    (OFFICIAL_ORIGINS as readonly string[]).map((o) => [o.toLowerCase(), o]),
  );
  const seen = new Set<string>();
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== "string" || entry.length === 0) {
      throw new AllowlistError(
        "ORIGIN_ALLOWLIST",
        "origin_allowlist entries must be non-empty strings.",
      );
    }
    const key = entry.replace(/\/$/, "").toLowerCase();
    if (!official.has(key)) {
      throw new AllowlistError(
        "ORIGIN_ALLOWLIST",
        "origin_allowlist contains a non-official origin.",
      );
    }
    if (seen.has(key)) {
      throw new AllowlistError(
        "ORIGIN_ALLOWLIST",
        "origin_allowlist contains duplicate origins.",
      );
    }
    seen.add(key);
    out.push(officialByLower.get(key)!);
  }
  return out;
}

function extractRepository(
  hostname: string,
  pathname: string,
): string {
  const path = pathname.replace(/\/+$/, "") || "/";
  // api.github.com/repos/{owner}/{repo}/...
  if (hostname === "api.github.com") {
    const m = path.match(/^\/repos\/([^/]+\/[^/]+)(?:\/|$)/);
    if (!m) {
      throw new AllowlistError(
        "REPO_PATH",
        "API evidence URL does not name /repos/{owner}/{repo}.",
      );
    }
    return m[1]!.toLowerCase();
  }
  // github.com/{owner}/{repo}/... and raw.githubusercontent.com/{owner}/{repo}/{ref}/...
  const m = path.match(/^\/([^/]+\/[^/]+)(?:\/|$)/);
  if (!m) {
    throw new AllowlistError(
      "REPO_PATH",
      "Evidence URL does not name an allowlisted repository path.",
    );
  }
  return m[1]!.toLowerCase();
}

/**
 * Parse and enforce official URL: host + openai/codex path for all three
 * official forms. Rejects userinfo, non-default ports, and drops fragments
 * and query strings (no secret retention).
 */
export function assertOfficialUrl(url: string): {
  canonical_url: string;
  origin: string;
  host: string;
  repository: string;
} {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new AllowlistError("URL_INVALID", "Evidence URL is not a valid URL.");
  }
  if (parsed.protocol !== "https:") {
    throw new AllowlistError("URL_PROTOCOL", "Evidence URL must use https.");
  }
  // Reject username/password (userinfo).
  if (parsed.username !== "" || parsed.password !== "") {
    throw new AllowlistError(
      "URL_USERINFO",
      "Evidence URL must not include username or password.",
    );
  }
  // Reject non-default ports (https default is 443; URL.port is "" when default).
  if (parsed.port !== "" && parsed.port !== "443") {
    throw new AllowlistError(
      "URL_PORT",
      "Evidence URL must not use a non-default port.",
    );
  }
  const host = parsed.hostname.toLowerCase();
  if (!isAllowedHost(host)) {
    throw new AllowlistError("HOST_REFUSED", "Evidence host is not allowlisted.");
  }
  const repository = extractRepository(host, parsed.pathname);
  if (!isAllowedRepository(repository)) {
    throw new AllowlistError(
      "REPO_REFUSED",
      "Evidence repository is not allowlisted.",
    );
  }
  // Derive origin from validated host+repo — never trust serialized origin.
  const origin =
    host === "api.github.com"
      ? `https://api.github.com/repos/${repository}`
      : host === "raw.githubusercontent.com"
        ? `https://raw.githubusercontent.com/${repository}`
        : `https://github.com/${repository}`;
  if (!isAllowedOrigin(origin)) {
    throw new AllowlistError("ORIGIN_REFUSED", "Evidence origin is not allowlisted.");
  }
  // Canonical resource URL: no fragment (URL already excludes hash), no query
  // (prefer resource URL without query to prevent secret retention).
  const path = parsed.pathname.replace(/\/+$/, "") || "/";
  const canonical_url =
    path === "/" ? `https://${host}` : `https://${host}${path}`;
  return {
    canonical_url,
    origin,
    host,
    repository,
  };
}

export function assertEvidenceKind(kind: string): EvidenceKind {
  if (!(EVIDENCE_KINDS as readonly string[]).includes(kind)) {
    throw new AllowlistError("KIND_REFUSED", "Evidence kind is not allowlisted.");
  }
  return kind as EvidenceKind;
}

export function officialAllowlists(): {
  hosts: readonly string[];
  repositories: readonly string[];
  origins: readonly string[];
  kinds: readonly EvidenceKind[];
} {
  return {
    hosts: OFFICIAL_HOSTS,
    repositories: OFFICIAL_REPOSITORIES,
    origins: OFFICIAL_ORIGINS,
    kinds: EVIDENCE_KINDS as readonly EvidenceKind[],
  };
}
