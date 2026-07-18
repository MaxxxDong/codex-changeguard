/**
 * Unified platform support surface (Tickets 13 + 14 + 15).
 *
 * macOS harness receipts (Ticket 13), Windows 11 support receipts (Ticket 14),
 * and Linux/WSL/enterprise capability matrix (Ticket 15) share one package API.
 * Internal modules never overwrite each other; SupportReceipt (T15 lightweight)
 * is distinct from PlatformSupportReceipt / WindowsPlatformSupportReceipt.
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
  // Ticket 15
  PlatformCapabilityStatus,
  AdapterId,
  RuntimeDomain,
  DiscoveryKind,
  DiscoveryObservation,
  PlatformGap,
  OfficialReference,
  SupportReceipt,
  PlatformCapabilityReport,
  NetworkCompareBranch,
  NetworkCompareObservation,
  NetworkCompareResult,
  ITHandoffMinimalEvidence,
  ITHandoff,
  WriteGateInput,
  WriteGateResult,
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

// Ticket 14 — Windows 11 namespace (external JSON alone remains PREVIEW).
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
  WindowsLiveHarnessAttestation,
  WindowsLiveHarnessWitness,
  EvaluatePlatformSupportOptions,
} from "./windows/index.js";
export {
  WINDOWS11_CRITICAL_SCENARIOS,
  WINDOWS11_CRITICAL_SCENARIO_IDS,
  isCriticalScenarioId,
  parsePlatformSupportReceipt,
  receiptDigest,
  criticalScenariosBindingOf,
  ReceiptValidationError,
  evaluatePlatformSupport,
  windows11SupportStatus,
  realMachineRunnerPlan,
  loadAndEvaluateReceiptFile,
  sealWindowsLiveHarnessWitness,
  isWindowsLiveHarnessWitness,
  readWindowsLiveHarnessAttestation,
  windowsLiveAttestationFromReceipt,
  windowsLiveWitnessMatchesReceipt,
} from "./windows/index.js";

// Ticket 15 — Linux / WSL / enterprise capability, discovery, IT handoff.
export {
  buildCapabilityReport,
  defaultCapabilityStatus,
  detectHostAdapter,
  evaluateWriteGate,
  INTERNAL_FIXTURE_SEAM_ENV,
  INTERNAL_FIXTURE_SEAM_VALUE,
  isolatedFixtureRepairCapabilityOptions,
  productionRepairCapabilityOptions,
  resolveEffectiveStatus,
  resolvePublicRepairCapability,
  runtimeDomainFor,
} from "./capability.js";
export type { PublicRepairCapabilityOptions } from "./capability.js";

export {
  discoverBoundedSurfaces,
  isHostMountPath,
} from "./discovery.js";

export {
  enumerateLinuxCliCandidates,
  linuxCapabilityReport,
  linuxCliPaths,
  LINUX_REGISTERED_CLI_PATHS,
} from "./linux-adapter.js";

export {
  assertNoIdentityCollapse,
  enumerateWslCliCandidates,
  wslCapabilityReport,
  wslCliPaths,
  WSL_REGISTERED_CLI_PATHS,
} from "./wsl-adapter.js";

export {
  assertSafeHandoffText,
  buildITHandoff,
} from "./it-handoff.js";

export { compareNetworkPaths } from "./network-compare.js";

export {
  syntheticLimitedReceipt,
  validateSupportReceipt,
} from "./support-receipt.js";
