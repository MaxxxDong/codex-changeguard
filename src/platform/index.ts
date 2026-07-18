/**
 * Platform support surface (Ticket 13+).
 * Capabilities, receipt validation, and namespaced adapters.
 */
export type {
  PlatformSupportLevel,
  PlatformCapabilities,
  PlatformSupportReceipt,
  PlatformPathAlias,
  PlatformSafetyConstraints,
  RegisteredOperation,
  PathRole,
  ScenarioOutcome,
  ScenarioStatus,
  IsolationProof,
  ReceiptAssertions,
  ReceiptValidationResult,
  CodexVersionProvenance,
  MacosRequiredScenarioId,
} from "./types.js";
export { MACOS_REQUIRED_SCENARIO_IDS } from "./types.js";
export {
  buildPlatformSupportReceipt,
  validatePlatformSupportReceipt,
  deriveSupportLevel,
  findReceiptLeaks,
  scenarioHashOf,
  receiptIdOf,
  scenariosDigestOf,
  type BuildReceiptInput,
} from "./receipt.js";
export {
  buildMacosCapabilities,
  enumerateMacosCandidates,
  readMacosCodexVersionProvenance,
  readCoarseOsVersion,
  assertDisposableTarget,
  isolationDigestOf,
  macosRegisteredAliases,
  isMacosOperationRegistered,
  type MacosAdapterCaps,
} from "./macos/index.js";
export {
  platformStatus,
  type PlatformStatusResult,
  type PlatformStatusOptions,
} from "./status.js";
