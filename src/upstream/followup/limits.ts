/** Hard bounds for Ticket 12 maintainer follow-up / upstream-fix closure. */

export const MAX_FOLLOWUP_REQUEST_BYTES = 64 * 1024;
export const MAX_STRING = 2_048;
export const MAX_TITLE = 256;
export const MAX_BODY = 8_192;
export const MAX_COMMENT = 4_096;
export const MAX_PROSE = 8_192;
export const MAX_SUBSCRIPTIONS = 64;
export const MAX_EVENTS_PER_ISSUE = 32;
export const MAX_LEDGER_BYTES = 256 * 1024;
export const MAX_ISSUE_NUMBER = 10_000_000;
export const MAX_PROBE_RESULTS = 16;
export const MAX_VERSION_LEN = 64;
export const MAX_RECIPE_ID_LEN = 128;

/** Low-frequency refresh: minimum interval between due checks (manual/SessionStart). */
export const REFRESH_MIN_INTERVAL_MS = 6 * 60 * 60 * 1000; // 6h

/** Local subscription / follow-up ledger (ChangeGuard-owned; not target project). */
export const FOLLOWUP_LEDGER_CAPACITY = 64;
export const FOLLOWUP_LEDGER_MAX_BYTES = MAX_LEDGER_BYTES;
export const FOLLOWUP_LEDGER_STATE_FILE = "followup-ledger.json";
export const FOLLOWUP_LEDGER_DIR_MODE = 0o700;
export const FOLLOWUP_LEDGER_FILE_MODE = 0o600;

export const OFFICIAL_HOST = "github.com";
export const OFFICIAL_REPOSITORY = "openai/codex";

/** Canonical issue URL path: /openai/codex/issues/<N> only. */
export const CANONICAL_ISSUE_PATH_RE =
  /^\/openai\/codex\/issues\/([1-9][0-9]{0,7})\/?$/;

/** Forbidden privacy keys on follow-up envelopes. */
export const FORBIDDEN_FOLLOWUP_KEYS = Object.freeze([
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

/** Closed maintainer-intent enum — only these map to registered probes. */
export const MAINTAINER_INTENTS = Object.freeze([
  "request_logs",
  "request_reproduction",
  "request_version",
  "request_platform",
  "request_config_probe",
  "request_core_health",
  "acknowledge_closure",
  "acknowledge_duplicate",
  "unknown_or_untrusted",
] as const);

/** Upstream disposition enum — never auto-reopen / cross-post / argue. */
export const UPSTREAM_DISPOSITIONS = Object.freeze([
  "needs_info",
  "cannot_reproduce",
  "by_design",
  "not_planned",
  "closed",
  "duplicate",
  "open_active",
] as const);

/** Registered probe ids allowlisted for follow-up evidence collection. */
export const REGISTERED_PROBE_IDS = Object.freeze([
  "core_health_readonly",
  "config_control_probe",
  "version_fingerprint_probe",
  "platform_identity_probe",
  "reproduction_window_probe",
  "log_redaction_probe",
] as const);

/** Path-free SessionStart hint when a subscription refresh is due (no fetch). */
export const REFRESH_DUE_HINT = "changeguard_followup_refresh_due";
