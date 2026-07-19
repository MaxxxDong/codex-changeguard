/**
 * Ticket 17 demo core — shared product-local orchestrator for later CLI/MCP.
 * Not re-exported from src/core/index.ts so production boundary graph stays
 * free of demo temp mkdtemp/copy/cleanup surfaces.
 */

export {
  runDemo,
  proveMutationTargetDisposable,
  surfaceSecurityEvidence,
  finalizeSecurityEvidence,
} from "./run-demo.js";
export {
  createDemoTempRoot,
  assertCallerDemoRoot,
  copyAllowlistedFixture,
  assertSafeDemoTree,
  removeDemoTempRoot,
  hashRelativeFile,
  DemoIsolationError,
} from "./isolation.js";
export type {
  DemoReceipt,
  DemoStepId,
  DemoStepStatus,
  DemoStepRecord,
  DemoOverallStatus,
  DemoHashProof,
  DemoMainLifecycle,
  DemoModelRefusal,
  DemoCrashRefusal,
  DemoCleanup,
  DemoSecurityEvidence,
  DemoNetworkObservation,
  DemoDisposableRootProof,
  DemoLocalOnlyExecutionProof,
  RunDemoOptions,
  MutationTargetProofResult,
  DemoFixtureRel,
} from "./types.js";
export {
  DEMO_FIXTURE_ALLOWLIST,
  DEMO_TEMP_PREFIX,
  DEMO_DEFAULT_BUDGET_MS,
  DEMO_PROTECTED_ALIAS,
  DEMO_PROTECTED_ARTIFACT_REL,
  DEMO_STEP_ORDER,
  demoSkippedSteps,
  emptySecurityEvidence,
} from "./types.js";
