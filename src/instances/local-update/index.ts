export {
  compareLocalUpdate,
  type CompareLocalUpdateOptions,
} from "./compare.js";
export { formatLocalUpdateCompareMarkdown } from "./format.js";
export {
  parseAsarHeaderFile,
  parseAsarHeaderFromFd,
  buildSyntheticAsarBuffer,
} from "./asar-header.js";
export type { AsarHeaderParseResult, AsarFileEntry } from "./asar-header.js";
export {
  discoverStagedAndInstalled,
  validateAppBundle,
  type StagedDiscoveryCaps,
  type StagedDiscoveryResult,
  type ValidatedAppBundle,
} from "./discovery.js";
export {
  compareAsarComponents,
  classifyStablePathChange,
} from "./component-diff.js";
export {
  compareNativeModuleDirs,
  listNativeModuleBasenames,
} from "./native-module-diff.js";
export {
  parseValidatedIntegrity,
} from "./asar-header.js";
export {
  buildOfficialEvidenceSection,
  versionRangeBinds,
} from "./official.js";
export type {
  LocalUpdateCompareResult,
  LocalUpdateCompareStatus,
  OfficialEvidenceSection,
  LocalObservationsSection,
  InferenceAndUnknownsSection,
  NamedArtifactObservation,
  AsarComponentDiff,
  NativeModuleDiff,
  LocalUpdateAppIdentity,
} from "./types.js";
export {
  NAMED_STAGED_ARTIFACTS,
  ASAR_STABLE_PATH_ALLOWLIST,
  MAX_STAGED_SESSION_DIRS,
  MAX_STAGED_DOWNLOAD_DIRS,
  MAX_STAGED_CANDIDATES,
  MAX_ASAR_NODES,
  MAX_NATIVE_MODULE_BASENAMES,
  STAGED_BUNDLE_ID,
  STAGED_APP_BASENAME,
  SPARKLE_INSTALLATION_REL,
  DEFAULT_COMPARE_LOCAL_UPDATE_TIME_BUDGET_MS,
} from "./limits.js";
