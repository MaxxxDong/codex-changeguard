/**
 * Windows 11 platform support namespace (Ticket 14).
 *
 * Distinct from the macOS Scenario Harness receipt surface (Ticket 13).
 * FULL is never claimed from synthetic, cross-platform, or external JSON alone;
 * it requires a process-local live harness witness (unit/future harness seam only).
 */
export type {
  PlatformSupportLevel as WindowsPlatformSupportLevel,
  PlatformReceiptHostKind,
  PlatformReceiptPlatform,
  Windows11CriticalScenarioId,
  CriticalScenarioResult,
  PlatformOperatorAttestation,
  PlatformSupportReceipt as WindowsPlatformSupportReceipt,
  PlatformSupportGap as WindowsPlatformSupportGap,
  PlatformSupportStatus as WindowsPlatformSupportStatus,
} from "./types.js";
export {
  WINDOWS11_CRITICAL_SCENARIOS,
  WINDOWS11_CRITICAL_SCENARIO_IDS,
  isCriticalScenarioId,
} from "./critical-scenarios.js";
export {
  parsePlatformSupportReceipt,
  receiptDigest,
  criticalScenariosBindingOf,
  ReceiptValidationError,
  sealWindowsLiveHarnessWitness,
  isWindowsLiveHarnessWitness,
  readWindowsLiveHarnessAttestation,
  windowsLiveAttestationFromReceipt,
  windowsLiveWitnessMatchesReceipt,
  type WindowsLiveHarnessAttestation,
  type WindowsLiveHarnessWitness,
} from "./receipt.js";
export {
  evaluatePlatformSupport,
  windows11SupportStatus,
  type EvaluatePlatformSupportOptions,
} from "./status.js";
export {
  realMachineRunnerPlan,
  loadAndEvaluateReceiptFile,
  type RealMachineRunnerPlan,
  type LoadReceiptResult,
} from "./runner.js";
