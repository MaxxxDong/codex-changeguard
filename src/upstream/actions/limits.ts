/** Hard bounds for Ticket 11 confirmed upstream actions. */

export const MAX_ACTION_REQUEST_BYTES = 96 * 1024;
export const MAX_CONFIRMATION_BYTES = 48 * 1024;
export const MAX_BODY = 16_384;
export const MAX_COMMENT = 8_192;
export const MAX_TITLE = 256;
export const MAX_STRING = 2_048;
export const MAX_URL = 512;
export const MAX_ATTACHMENTS = 8;
export const MAX_ATTACHMENT_NAME = 128;
export const MAX_ATTACHMENT_BYTES = 256 * 1024;
export const MAX_MANIFEST_BYTES = 512 * 1024;

/** Confirmation default TTL (15 minutes). */
export const CONFIRMATION_TTL_MS = 15 * 60 * 1000;

/** Prefix for one-shot confirmation tokens (not secrets / not auth tokens). */
export const CONFIRMATION_TOKEN_PREFIX = "ua1.";

/** Forbidden privacy keys on action/confirm envelopes (never accepted). */
export const FORBIDDEN_ACTION_KEYS = Object.freeze([
  "cookie",
  "cookies",
  "token",
  "tokens",
  "access_token",
  "refresh_token",
  "authorization",
  "auth_header",
  "password",
  "passwd",
  "secret",
  "api_key",
  "session",
  "sessions",
  "session_rollout",
  "full_env",
  "environment",
  "env",
  "gh_token",
  "github_token",
  "bearer",
]);

/** Action kinds that may be separately previewed and confirmed. */
export const UPSTREAM_ACTION_KINDS = Object.freeze([
  "create_issue",
  "comment_with_delta",
  "react_upvote",
  "subscribe",
  "attachment_upload",
] as const);

/** Official repository hosts for canonical targets. */
export const OFFICIAL_CANONICAL_HOSTS = Object.freeze([
  "github.com",
  "api.github.com",
]);

export const OFFICIAL_REPOSITORY = "openai/codex";
