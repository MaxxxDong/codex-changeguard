/** Hard bounds for Ticket 04 official evidence and impact contracts. */

export const MAX_EVIDENCE_ITEMS = 256;
export const MAX_EVIDENCE_TITLE = 512;
export const MAX_EVIDENCE_BODY = 16_384;
export const MAX_STRUCTURED_KEYS = 64;
export const MAX_STRUCTURED_TOKEN = 128;
export const MAX_SUMMARY_TOKENS = 32;
export const MAX_GRAPH_EDGES = 512;
export const MAX_IMPACT_ITEMS = 256;
export const MAX_SNAPSHOT_BYTES = 512 * 1024;

/** Official host allowlist for evidence origins/URLs. */
export const OFFICIAL_HOSTS = Object.freeze([
  "github.com",
  "api.github.com",
  "raw.githubusercontent.com",
]);

/** Official repository allowlist (owner/name). */
export const OFFICIAL_REPOSITORIES = Object.freeze(["openai/codex"]);

/** Official origin prefixes (canonical). */
export const OFFICIAL_ORIGINS = Object.freeze([
  "https://github.com/openai/codex",
  "https://api.github.com/repos/openai/codex",
  "https://raw.githubusercontent.com/openai/codex",
]);

export const EVIDENCE_KINDS = Object.freeze([
  "doc",
  "release",
  "tag",
  "diff",
  "issue",
  "pr",
  "commit",
] as const);

/** Stale age thresholds (seconds). */
export const STALE_LOW_SECONDS = 6 * 60 * 60;
export const STALE_MEDIUM_SECONDS = 24 * 60 * 60;
export const STALE_HIGH_SECONDS = 7 * 24 * 60 * 60;

/** Max allowed future skew for transport fetched_at (seconds). */
export const MAX_FETCHED_AT_FUTURE_SKEW_SECONDS = 5 * 60;

/** Disclosure bounds for sendable local context. */
export const MAX_DISCLOSURE_TOKEN = 128;
export const MAX_DISCLOSURE_CONFIG_KEYS = 32;
export const MAX_DISCLOSURE_FEATURE_IDS = 32;
