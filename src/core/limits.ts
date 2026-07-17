/** Hard bounds for Ticket 01 read-only diagnosis. */

export const MAX_INCIDENT_BYTES = 64 * 1024;
export const MAX_ARTIFACT_BYTES = 256 * 1024;
export const MAX_MCP_REQUEST_BYTES = 128 * 1024;
export const MAX_AST_SIGNATURE_ID_LENGTH = 128;
export const MAX_STACK_FRAMES = 64;
export const MAX_ARTIFACT_HASHES = 128;
export const MAX_AST_SIGNATURE_IDS = 128;
export const MAX_CONFIG_KEYS = 512;
export const MAX_FEATURE_IDS = 512;
export const MAX_STRING_FIELD = 2048;

/** Named candidates only — never recursive project crawl. */
export const INCIDENT_FILE_NAME = "incident.json";
export const PROTECTED_ARTIFACT_REL = "artifacts/browser-client.mjs";

export const PROTECTED_AST_SIGNATURE_ID =
  "js.global-process-shim-redefinition.v1";
