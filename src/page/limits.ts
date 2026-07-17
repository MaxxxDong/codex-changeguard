/** Hard bounds for Ticket 05 untrusted page-evidence analysis. */

export const MAX_PAGE_URL_LENGTH = 2_048;
export const MAX_PAGE_TITLE = 512;
export const MAX_PAGE_VISIBLE_TEXT = 32_768;
export const MAX_PAGE_METADATA_KEYS = 16;
export const MAX_PAGE_METADATA_TOKEN = 256;
export const MAX_PAGE_ENVELOPE_BYTES = 48_384;
export const MAX_EXTRACTION_ITEMS = 64;
export const MAX_EXTRACTION_TOKEN = 256;
export const MAX_COMMAND_CANDIDATES = 16;
export const MAX_COMPARISON_NOTES = 32;
export const MAX_CITED_SOURCES = 16;

/** Hosts treated as generic ChatGPT / account / session product surfaces. */
export const CHATGPT_OUT_OF_SCOPE_HOSTS = Object.freeze([
  "chat.openai.com",
  "chatgpt.com",
  "platform.openai.com",
  "auth.openai.com",
  "accounts.openai.com",
  "auth0.openai.com",
]);

/** Forbidden keys on page envelopes (logged-page privacy boundary). */
export const FORBIDDEN_PAGE_ENVELOPE_KEYS = Object.freeze([
  "cookie",
  "cookies",
  "storage",
  "local_storage",
  "session_storage",
  "localStorage",
  "sessionStorage",
  "token",
  "tokens",
  "access_token",
  "refresh_token",
  "auth_header",
  "authorization",
  "auth_headers",
  "request_body",
  "request_bodies",
  "request",
  "requests",
  "complete_request",
  "browser_request",
  "set_cookie",
  "password",
  "passwd",
  "secret",
  "api_key",
  "session",
  "sessions",
]);

/** Allowed top-level keys on a page-evidence envelope. */
export const ALLOWED_ENVELOPE_KEYS = Object.freeze([
  "schema_version",
  "url",
  "page_mode",
  "visible_title",
  "visible_text",
  "metadata",
]);

/** Allowed metadata keys (sanitized, non-secret). */
export const ALLOWED_METADATA_KEYS = Object.freeze([
  "host",
  "content_type",
  "language",
  "status_code",
  "source_label",
]);
