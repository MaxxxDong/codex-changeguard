/** Public lifecycle surface — Ticket 06 KNOWN_GOOD / rollback / canary. */

export {
  lifecycleStatus,
  recordRepairBackup,
  recordSuccessfulStart,
  recordKnownGood,
  applyRetention,
  assessUpdateRegression,
  evaluateAB,
  rollbackSurface,
  previewCliVersionRollback,
  previewDesktopVersionRollback,
  runCanary,
  supersedeRecipe,
  isRecipeRecommendable,
} from "./engine.js";

export { dispatchLifecycle, isLifecycleOperation } from "./dispatch.js";
export type { LifecycleDispatchArgs } from "./dispatch.js";

export type {
  ControlSurface,
  VersionGuidance,
  LifecycleOperation,
  LifecycleResult,
  LifecycleLedger,
  RetentionReceipt,
  UpdateRegressionAssessment,
  CliVersionRollbackPreview,
  DesktopVersionRollbackPreview,
  CanaryResult,
  RecipeRecord,
  RecipeLifecycleStatus,
  ABObservation,
  ProvenanceTrust,
  CliInstallSource,
  TrustedProvenance,
} from "./types.js";

export {
  REPAIR_BACKUP_MIN_AGE_MS,
  REPAIR_BACKUP_MIN_STARTS,
  KNOWN_GOOD_RETAIN_COUNT,
  SURFACE_TARGET_REL,
  LIFECYCLE_LEDGER_REL,
  LIFECYCLE_DIR,
} from "./constants.js";

export {
  CONTROL_SURFACES,
  PROVENANCE_TRUST_VALUES,
  TRUSTED_PROVENANCE_ALLOWLIST,
  CLI_INSTALL_SOURCE_VALUES,
  OFFICIAL_CLI_INSTALL_SOURCES,
  isProvenanceTrust,
  isTrustedRollbackProvenance,
  isCliInstallSource,
  isOfficialCliInstallSource,
  parseProvenanceTrust,
  parseCliInstallSource,
  rawCliInstallSource,
} from "./types.js";
