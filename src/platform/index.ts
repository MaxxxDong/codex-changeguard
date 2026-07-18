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
  hostCoarseFingerprintOf,
  sealLiveHarnessWitness,
  isLiveHarnessWitness,
  readLiveHarnessAttestation,
  type BuildReceiptInput,
  type LiveHarnessWitness,
  type LiveHarnessAttestation,
  type ValidateReceiptOptions,
} from "./receipt.js";
export {
  buildMacosCapabilities,
  enumerateMacosCandidates,
  readMacosCodexVersionProvenance,
  readCoarseOsVersion,
  assertDisposableTarget,
  assertHarnessOutputDir,
  captureActiveCodexHomeWitness,
  isolationDigestOf,
  listTrustedDisposableRoots,
  macosRegisteredAliases,
  isMacosOperationRegistered,
  PROTECTED_ROOTS,
  type MacosAdapterCaps,
  type DisposableTargetOptions,
} from "./macos/index.js";
export {
  platformStatus,
  type PlatformStatusResult,
  type PlatformStatusOptions,
} from "./status.js";
