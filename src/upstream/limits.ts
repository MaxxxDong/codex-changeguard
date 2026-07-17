/** Hard bounds for Ticket 10 Upstream Submission Capsule (preview-only). */

export const MAX_UPSTREAM_REQUEST_BYTES = 64 * 1024;
export const MAX_DOCTOR_JSON_BYTES = 32 * 1024;
export const MAX_STRING = 2_048;
export const MAX_TITLE = 256;
export const MAX_BODY = 16_384;
export const MAX_COMMENT = 8_192;
export const MAX_FACTS = 64;
export const MAX_TECHNICAL_SIGNALS = 32;
export const MAX_DUPLICATE_CANDIDATES = 32;
export const MAX_DELTA_ITEMS = 32;
export const MAX_REPRO_STEPS = 32;
export const MAX_DOCTOR_KEYS = 64;
export const MAX_DOCTOR_STRING = 1_024;
export const MAX_INCLUSION_MANIFEST = 32;

/** Official openai/codex hosts only (same family as Ticket 04). */
export const OFFICIAL_HOSTS = Object.freeze([
  "github.com",
  "api.github.com",
  "raw.githubusercontent.com",
]);

export const OFFICIAL_REPOSITORY = "openai/codex";

/** Root live-verified official snapshot facts for 2026-07-18 (immutable test fixture). */
export const OFFICIAL_FORM_SNAPSHOT_ID = "official_issue_forms_2026-07-18";
export const OFFICIAL_FORM_SNAPSHOT_FETCHED_AT = "2026-07-18T00:00:00.000Z";
export const OFFICIAL_MAIN_COMMIT =
  "3a067484584861606ad842de5bc4ac735a865ddf";

/** Git blob SHAs for issue form YAML at the verified main commit (not content SHA-256). */
export const OFFICIAL_FORM_BLOB_SHAS = Object.freeze({
  "1-codex-app.yml": "6e294ee27bc924fc2c68b743bad26260297d13f9",
  "2-extension.yml": "599bc08b428d6328c712f526549350daf0aada79",
  "3-cli.yml": "cfd368c0ba798d4f513edd5548fd185d761ed15d",
  "4-bug-report.yml": "4de88414600e6100720fefa2a324ce41d759cd7f",
  "5-feature-request.yml": "745c347965c2e58f8e8e4437009f2c8ae0059878",
  "6-docs-issue.yml": "1957b6035a58950329d87d4c24e67faf98c00572",
});

/** Freshness window for form snapshot age labels (7 days). */
export const FORM_SNAPSHOT_FRESH_MS = 7 * 24 * 60 * 60 * 1000;

/** Forbidden privacy keys on request / doctor envelopes. */
export const FORBIDDEN_UPSTREAM_KEYS = Object.freeze([
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
]);

/** Allowed top-level keys on the upstream preview request envelope. */
export const ALLOWED_REQUEST_KEYS = Object.freeze([
  "schema_version",
  "case_kind",
  "surface",
  "platform",
  "codex_version",
  "version_unknown_reason",
  "actual_behavior",
  "technical_signals",
  "reproduction",
  "observed_facts",
  "user_reports",
  "hypotheses",
  "duplicate_search",
  "evidence_delta",
  "doctor_json",
  "privacy_review",
  "error_strings",
  "command_strings",
]);
