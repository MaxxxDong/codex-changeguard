/**
 * Unified platform support surface (Tickets 13 + 14).
 *
 * macOS harness receipts (Ticket 13) and Windows 11 support receipts
 * (Ticket 14) are distinct contracts under one package API. They share
 * exported names only at the package boundary; internal modules never
 * overwrite each other.
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

// Ticket 14 — Windows 11 namespace (synthetic fixtures remain PREVIEW).
export type {
  WindowsPlatformSupportLevel,
  PlatformReceiptHostKind,
  PlatformReceiptPlatform,
  Windows11CriticalScenarioId,
  CriticalScenarioResult,
  PlatformOperatorAttestation,
  WindowsPlatformSupportReceipt,
  WindowsPlatformSupportGap,
  WindowsPlatformSupportStatus,
  RealMachineRunnerPlan,
  LoadReceiptResult,
} from "./windows/index.js";
export {
  WINDOWS11_CRITICAL_SCENARIOS,
  WINDOWS11_CRITICAL_SCENARIO_IDS,
  isCriticalScenarioId,
  parsePlatformSupportReceipt,
  receiptDigest,
  ReceiptValidationError,
  evaluatePlatformSupport,
  windows11SupportStatus,
  realMachineRunnerPlan,
  loadAndEvaluateReceiptFile,
} from "./windows/index.js";
