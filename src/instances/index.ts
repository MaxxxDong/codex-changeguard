export { scanInstances } from "./scan.js";
export { bindRepairTarget } from "./repair-binding.js";
export { loadInventory } from "./enumerate.js";
export {
  loadState,
  saveState,
  parseStateJson,
  stateFilePath,
  priorArtifactBaselinesOrNull,
} from "./state.js";
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
  measureInstanceArtifactBaselines,
  measureNamedFile,
  namedArtifactTargetsForCandidate,
  artifactBaselineDigest,
  overallArtifactDigest,
} from "./artifacts.js";
export {
  classifyLocalArtifactDiff,
  unavailableLocalArtifactDiff,
} from "./artifact-diff.js";
export {
  enumerateWindowsCandidates,
  resolveWindowsRepairScope,
  classifyWriteTarget,
  parseCrashMetadataWindow,
  isForbiddenSystemPath,
  isSignedAppBinaryPath,
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
  HealthClassification,
  HealthClassificationReason,
  AffectedResolution,
  AffectedResolutionReason,
  InstallSource,
  SystemEnumerateCaps,
  EnumerationSource,
  LocalArtifactEntry,
  LocalArtifactDiff,
  LocalArtifactDiffEntry,
  LocalArtifactDiffStatus,
  LocalArtifactChangeClass,
  InstanceArtifactBaseline,
  ArtifactKind,
  ArtifactReadStatus,
} from "./types.js";
export type {
  WindowsEnumerateCaps,
  WindowsDiscoveryResult,
  WindowsWriteClassification,
  WindowsCrashMetadataWindow,
} from "./windows/index.js";
