export type {
  WindowsEnvironmentClass,
  WindowsWriteScope,
  WindowsInstallKind,
  WindowsEnumerateCaps,
  WindowsProfileSpec,
  WindowsWriteClassification,
  WindowsDiscoveryResult,
  WindowsCrashMetadataWindow,
} from "./types.js";
export {
  isForbiddenSystemPath,
  isMsixAliasPath,
  isSignedAppBinaryPath,
  isUnderUserOwnedMarkers,
  classifyWriteTarget,
  writeScopeToErrorCode,
} from "./policy.js";
export {
  parseCrashMetadataWindow,
  CrashMetadataError,
} from "./crash-metadata.js";
export {
  resolveWindowsRepairScope,
  type WindowsRepairScopeRequest,
  type WindowsRepairScopeResult,
} from "./repair-scope.js";
export { enumerateWindowsCandidates } from "./adapter.js";
