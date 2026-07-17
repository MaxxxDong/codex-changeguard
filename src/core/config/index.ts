/** Ticket 07 config/startup fault pack — read-only probe + schema surface. */

export {
  CONFIG_FAULT_OBSOLETE,
  CONFIG_FAULT_SOURCE_CONFLICT,
  CONFIG_FAULT_SYNTAX,
  CONFIG_FAULT_TYPE,
  CONFIG_MANAGED_ALIAS,
  CONFIG_MANAGED_POLICY_REL,
  CONFIG_OVERRIDE_ALIAS,
  CONFIG_OVERRIDE_REL,
  CONFIG_PRIMARY_ALIAS,
  CONFIG_PRIMARY_REL,
  MAX_CONFIG_FILE_BYTES,
  type ConfigFaultClass,
} from "./limits.js";
export { probeConfigControlFiles, type ConfigProbeResult, type ManagedPolicyInfo } from "./probe.js";
export {
  detectSourceConflict,
  documentIsFullyValid,
  readValue,
  validateConfigText,
  type ConfigFault,
  type ConfigDocResult,
} from "./validate.js";
export {
  encodeNewValueForCapsule,
  redactedValueSummary,
  summarizeValueType,
} from "./redact-value.js";
export { parseTomlDocument, flattenTable, getDotted } from "./toml-parse.js";
export { OBSOLETE_CONFIG_KEYS, KNOWN_TOP_LEVEL_KEYS, isSecretConfigKey } from "./schema.js";
