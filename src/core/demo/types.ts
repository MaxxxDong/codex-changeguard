/**
 * Ticket 17 demo-core contracts — stable JSON-serializable DemoReceipt.
 * Path aliases and digests only; never absolute paths, tokens, env values,
 * source bytes, or session text.
 */

/** Ordered demo step identifiers (stable for CLI/MCP later). */
export type DemoStepId =
  | "isolate"
  | "diagnose_main"
  | "explain_main"
  | "preview_main"
  | "apply_main"
  | "verify_main"
  | "rollback_main"
  | "model_refuse"
  | "crash_refuse"
  | "cleanup";

export type DemoStepStatus = "pass" | "fail" | "skip" | "refused";

export type DemoOverallStatus =
  | "completed"
  | "failed"
  | "refused"
  | "partial"
  | "budget_exceeded";

export interface DemoStepRecord {
  id: DemoStepId;
  status: DemoStepStatus;
  /** Stable machine reason; redacted human detail never embeds paths/tokens. */
  reason_code: string | null;
  duration_ms: number;
}

export interface DemoHashProof {
  path_alias: string;
  original_sha256: string;
  after_apply_sha256: string | null;
  after_rollback_sha256: string | null;
  restored: boolean;
}

export interface DemoMainLifecycle {
  diagnose_state: string | null;
  user_resolution_after_apply: string | null;
  user_resolution_after_verify: string | null;
  user_resolution_after_rollback: string | null;
  resolved_verified: boolean;
  repair_applied: boolean;
  auto_rolled_back: boolean;
  hash_proof: DemoHashProof | null;
}

export interface DemoModelRefusal {
  refused: boolean;
  reasons: string[];
  graph_unchanged: boolean;
  graph_sha256: string | null;
}

export interface DemoCrashRefusal {
  family_id: string | null;
  diagnosis_state: string | null;
  repair_authorization_eligible: boolean;
  preview_refused: boolean;
  refused_actions: string[];
  reason_codes: string[];
}

export interface DemoCleanup {
  attempted: boolean;
  completed: boolean;
  temp_removed: boolean;
}

/**
 * One observable `network_used` measurement from a demo seam
 * (diagnose / apply / impact / crash). Values are recorded at runtime —
 * not substituted as unconditional receipt constants.
 *
 * Fail-closed contract: `network_used` is the boolean interpretation only when
 * `value_valid` is true. Non-boolean / missing / malformed runtime values set
 * `value_valid: false` and must never yield `network_all_false` / `proven`.
 */
export interface DemoNetworkObservation {
  /** Stable seam id (no paths). */
  seam: string;
  /**
   * True only when the runtime value was strictly boolean `true`.
   * When `value_valid` is false this field is false and is not proof of offline.
   */
  network_used: boolean;
  /**
   * True only when the runtime observation was exactly boolean `true` or `false`.
   * `undefined`, `null`, strings, numbers, and other values set this to false.
   */
  value_valid: boolean;
}

/**
 * Disposable-root proof at a mutation or isolation boundary.
 * Uses product isolation proofs only — never hashes the live home/profile.
 */
export interface DemoDisposableRootProof {
  /** Number of successful disposable-root proofs at relevant boundaries. */
  proof_count: number;
  /** Stable proof reason codes (ordered, no paths). */
  reason_codes: string[];
}

/**
 * Explicit local-only / no-adapter execution proof for external_write:false.
 * Not a bare constant: records that the demo ran product-local cores only,
 * with no external write adapter available or invoked.
 */
export interface DemoLocalOnlyExecutionProof {
  mode: "local_only_no_adapter";
  no_external_adapter: true;
  /** True when all demo mutations stayed under a proven disposable root. */
  mutations_local_only: boolean;
}

/**
 * Runtime security-evidence contract for the three public security booleans.
 * `proven` must be true before a receipt may claim `ok: true` / `status: completed`.
 */
export interface DemoSecurityEvidence {
  schema_version: 1;
  /** Aggregated network_used results from diagnose/apply/impact/crash paths. */
  network_observations: DemoNetworkObservation[];
  /** True iff every observation is present and reports network_used === false. */
  network_all_false: boolean;
  disposable_root: DemoDisposableRootProof;
  local_only: DemoLocalOnlyExecutionProof;
  /**
   * Fail-closed completeness: required observations + disposable proofs +
   * local-only execution proof all hold. Missing/unproven evidence ⇒ false.
   */
  proven: boolean;
}

/**
 * Stable demo receipt — product-local, no network / external write / live profile.
 * `ok` is the surface success contract: true iff `status === "completed"`.
 * Fail / refuse / partial / budget receipts set `ok: false`.
 *
 * The three security booleans are literal-false types only after fail-closed
 * runtime checks; `security_evidence` records the measurements/proofs that
 * established them. Unproven evidence never yields `ok: true`.
 */
export interface DemoReceipt {
  schema_version: 1;
  /** Explicit surface success: always `status === "completed"`. */
  ok: boolean;
  status: DemoOverallStatus;
  duration_ms: number;
  steps: DemoStepRecord[];
  main: DemoMainLifecycle;
  model_refusal: DemoModelRefusal;
  crash_refusal: DemoCrashRefusal;
  network_used: false;
  external_write: false;
  live_profile_mutated: false;
  /** Runtime proofs/measurements establishing the three security booleans. */
  security_evidence: DemoSecurityEvidence;
  cleanup: DemoCleanup;
  error_code: string | null;
  error_message: string | null;
}

/**
 * Stable, path-free result of re-proving a mutation target immediately before
 * apply / rollback writes. Proof only — never mutates, never accepts callbacks.
 */
export type MutationTargetProofResult =
  | { ok: true; reason_code: "MUTATION_TARGET_DISPOSABLE" }
  | { ok: false; reason_code: "MUTATION_TARGET_NOT_DISPOSABLE" };

export interface RunDemoOptions {
  /**
   * Optional caller target. When set, must already exist and pass
   * proveIsolatedFixtureTarget (strict disposable child). Live ~/.codex and
   * non-disposable paths are refused. When omitted, demo creates
   * `cg-demo-*` under OS temp.
   */
  targetRoot?: string;
  /**
   * When true, plant the recovery induce-verify-fail sentinel after preview so
   * apply fails closed with auto-rollback. Never claims RESOLVED_VERIFIED.
   */
  induce_verify_failure?: boolean;
  /** Total wall-clock budget in ms (default 120_000). Fail closed on exceed. */
  budget_ms?: number;
  /** Deterministic clock for impact snapshot staleness (tests). */
  now_ms?: number;
  /** Optional home override for active-profile isolation checks (tests). */
  homeDir?: string | null;
}

/** Allowlisted synthetic fixture relative paths (repo-root relative). */
export const DEMO_FIXTURE_ALLOWLIST = [
  "fixtures/protected-process",
  "fixtures/crash-family/access-violation-crbrowser",
  "fixtures/impact-local",
] as const;

export type DemoFixtureRel = (typeof DEMO_FIXTURE_ALLOWLIST)[number];

export const DEMO_TEMP_PREFIX = "cg-demo-";
export const DEMO_DEFAULT_BUDGET_MS = 120_000;
export const DEMO_PROTECTED_ALIAS = "BROWSER_CLIENT_COPY_A";
export const DEMO_PROTECTED_ARTIFACT_REL = "artifacts/browser-client.mjs";

/** Canonical ordered demo step ids (schema minItems/maxItems = 10). */
export const DEMO_STEP_ORDER: readonly DemoStepId[] = [
  "isolate",
  "diagnose_main",
  "explain_main",
  "preview_main",
  "apply_main",
  "verify_main",
  "rollback_main",
  "model_refuse",
  "crash_refuse",
  "cleanup",
] as const;

/**
 * Build the canonical 10 ordered step records for surface-level refusals
 * (e.g. INVALID_ARGS) so every public DemoReceipt is schema-valid.
 */
export function demoSkippedSteps(
  reason_code: string,
  status: DemoStepStatus = "skip",
): DemoStepRecord[] {
  return DEMO_STEP_ORDER.map((id) => ({
    id,
    status,
    reason_code,
    duration_ms: 0,
  }));
}

/** Empty / unproven security evidence (never allows ok:true alone). */
export function emptySecurityEvidence(
  overrides: Partial<DemoSecurityEvidence> = {},
): DemoSecurityEvidence {
  return {
    schema_version: 1,
    network_observations: overrides.network_observations ?? [],
    network_all_false: overrides.network_all_false ?? false,
    disposable_root: overrides.disposable_root ?? {
      proof_count: 0,
      reason_codes: [],
    },
    local_only: overrides.local_only ?? {
      mode: "local_only_no_adapter",
      no_external_adapter: true,
      mutations_local_only: false,
    },
    proven: overrides.proven ?? false,
  };
}
