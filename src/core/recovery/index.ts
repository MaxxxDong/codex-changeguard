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
  VerificationReport,
  BackupReceipt,
} from "./types.js";
export { INDUCE_VERIFY_FAIL_REL } from "./types.js";
