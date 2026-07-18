/** Public recovery surface — single engine for CLI and MCP. */

export {
  previewRepair,
  applyRepair,
  verifyRepair,
  rollbackRepair,
  measureArtifactSha,
} from "./engine.js";
export type {
  RepairCapsule,
  RepairResult,
  ApplyOptions,
  PreviewOptions,
  RepairHostContext,
  VerificationReport,
  BackupReceipt,
  AdminHandoff,
} from "./types.js";
export { INDUCE_VERIFY_FAIL_REL } from "./types.js";
export {
  evaluateWindowsWriteGate,
  resolveTrustedHostPlatform,
  isWindowsTrustedHost,
} from "./windows-write-gate.js";
export type {
  WindowsWriteGateContext,
  WindowsWriteGateResult,
} from "./windows-write-gate.js";
