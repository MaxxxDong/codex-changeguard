export { scanInstances } from "./scan.js";
export { bindRepairTarget } from "./repair-binding.js";
export { loadInventory } from "./enumerate.js";
export { loadState, saveState, parseStateJson, stateFilePath } from "./state.js";
export { classifyTransitions, compareVersions } from "./compare.js";
export { resolveAffectedInstance } from "./resolve.js";
export {
  pathHashOf,
  instanceIdOf,
  instanceFingerprintOf,
  overallFingerprintOf,
} from "./identity.js";
export { readVersionEvidence } from "./version-evidence.js";
export { enumerateSystemCandidates } from "./system-adapter.js";
export {
  enumerateWindowsCandidates,
  resolveWindowsRepairScope,
  classifyWriteTarget,
  parseCrashMetadataWindow,
  isForbiddenSystemPath,
} from "./windows/index.js";
export type {
  InstanceIdentity,
  ScanResult,
  ScanOptions,
  TransitionClass,
  HookTrustState,
  RepairTargetRequest,
  RepairTargetBinding,
  VersionFingerprintState,
  DiscoveredCandidate,
  ObservedContext,
  HealthCheckResult,
  InstallSource,
  SystemEnumerateCaps,
  EnumerationSource,
} from "./types.js";
export type {
  WindowsEnumerateCaps,
  WindowsDiscoveryResult,
  WindowsWriteClassification,
  WindowsCrashMetadataWindow,
} from "./windows/index.js";
