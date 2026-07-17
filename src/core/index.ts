export { diagnose } from "./diagnose.js";
export {
  classifyCrashFamily,
  shouldClassifyCrashFamily,
  CRASH_FAMILY_CATALOG,
  normalizeExceptionCode,
  normalizeOffsetBucket,
  normalizeModuleName,
} from "./crash-family.js";
export type {
  DiagnosisResult,
  DiagnosisState,
  IncidentFingerprint,
  DiagnoseOptions,
  UserResolutionStatus,
  CrashMetadata,
  CrashClassificationResult,
  RankedIssueCandidate,
  AxisAssessment,
} from "./types.js";
export {
  MAX_INCIDENT_BYTES,
  MAX_ARTIFACT_BYTES,
  MAX_MCP_REQUEST_BYTES,
  MAX_AST_SIGNATURE_ID_LENGTH,
} from "./limits.js";
export { redactText, nfkc, assertNoLeakPaths } from "./redact.js";
export { sha256Buffer, measureProtectedProcessAst } from "./measure.js";
export {
  previewRepair,
  applyRepair,
  verifyRepair,
  rollbackRepair,
} from "./recovery/index.js";
export type { RepairResult, RepairCapsule } from "./recovery/index.js";

// Ticket 03 re-exports (shared core surface for CLI/MCP consumers).
export { scanInstances, bindRepairTarget } from "../instances/index.js";
export type {
  ScanResult,
  ScanOptions,
  InstanceIdentity,
  RepairTargetBinding,
  RepairTargetRequest,
} from "../instances/types.js";
export { runSessionStart } from "../hooks/session-start.js";
