/** Hard bounds for Ticket 07 config/startup fault pack (read-only control files). */

/** Max bytes for a single Codex control config file. */
export const MAX_CONFIG_FILE_BYTES = 64 * 1024;

/** Max number of control files read per diagnosis (primary + override + managed). */
export const MAX_CONFIG_FILES = 4;

/** Max keys in a parsed control document. */
export const MAX_CONFIG_DOCUMENT_KEYS = 256;

/** Max nesting depth for tables. */
export const MAX_CONFIG_TABLE_DEPTH = 6;

/** Max string value length retained for validation (secrets still redacted). */
export const MAX_CONFIG_VALUE_CHARS = 512;

/** Registered control file relative paths under an isolated instance/config root. */
export const CONFIG_PRIMARY_REL = "config/config.toml";
export const CONFIG_OVERRIDE_REL = "config/config.override.toml";
export const CONFIG_MANAGED_POLICY_REL = "config/managed.policy.json";

/** Path aliases (never absolute paths). */
export const CONFIG_PRIMARY_ALIAS = "CODEX_CONFIG_PRIMARY";
export const CONFIG_OVERRIDE_ALIAS = "CODEX_CONFIG_OVERRIDE";
export const CONFIG_MANAGED_ALIAS = "CODEX_MANAGED_POLICY";

/** Measured fault classes — distinct Incident Fingerprint error.class values. */
export const CONFIG_FAULT_SYNTAX = "ConfigTomlSyntaxError";
export const CONFIG_FAULT_TYPE = "ConfigSchemaTypeError";
export const CONFIG_FAULT_OBSOLETE = "ConfigObsoleteKeyError";
export const CONFIG_FAULT_SOURCE_CONFLICT = "ConfigSourceConflictError";

export type ConfigFaultClass =
  | typeof CONFIG_FAULT_SYNTAX
  | typeof CONFIG_FAULT_TYPE
  | typeof CONFIG_FAULT_OBSOLETE
  | typeof CONFIG_FAULT_SOURCE_CONFLICT;
