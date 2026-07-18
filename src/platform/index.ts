export type {
  PlatformSupportLevel,
  PlatformReceiptHostKind,
  PlatformReceiptPlatform,
  Windows11CriticalScenarioId,
  CriticalScenarioResult,
  PlatformOperatorAttestation,
  PlatformSupportReceipt,
  PlatformSupportGap,
  PlatformSupportStatus,
} from "./types.js";
export {
  WINDOWS11_CRITICAL_SCENARIOS,
  WINDOWS11_CRITICAL_SCENARIO_IDS,
  isCriticalScenarioId,
} from "./critical-scenarios.js";
export {
  parsePlatformSupportReceipt,
  receiptDigest,
  ReceiptValidationError,
} from "./receipt.js";
export {
  evaluatePlatformSupport,
  windows11SupportStatus,
} from "./status.js";
export {
  realMachineRunnerPlan,
  loadAndEvaluateReceiptFile,
  type RealMachineRunnerPlan,
  type LoadReceiptResult,
} from "./runner.js";
