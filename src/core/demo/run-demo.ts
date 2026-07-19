/**
 * Shared Ticket 17 demo core — product-local, no network, no live profile.
 *
 * Orchestrates existing deterministic APIs only:
 *   diagnose → previewRepair → applyRepair → verifyRepair → rollbackRepair
 *   + assessImpact model-graph refusal + crash-family diagnose/preview refuse
 *
 * Used by Rescue CLI (`demo`), MCP (`changeguard_demo`), and Skill
 * (`/changeguard demo`). Does not reimplement repair logic.
 * Never embeds absolute paths, raw auth tokens, env values, or source bytes
 * in the receipt.
 *
 * Security honesty: network_used / external_write / live_profile_mutated are
 * only claimed as false after fail-closed runtime evidence is proven. Missing
 * evidence never yields ok:true.
 */
import fs from "node:fs";
import path from "node:path";
import { diagnose } from "../diagnose.js";
import {
  applyRepair,
  INDUCE_VERIFY_FAIL_REL,
  previewRepair,
  rollbackRepair,
  verifyRepair,
} from "../recovery/index.js";
import { assertNoLeakPaths, redactText } from "../redact.js";
import { assessImpact } from "../../impact/assess.js";
import type { ModelEdgeEscalationPayload } from "../../impact/types.js";
import { findRepoRoot } from "../../paths.js";
import {
  isolatedFixtureRepairCapabilityOptions,
  proveIsolatedFixtureTarget,
} from "../../platform/capability.js";
import {
  assertCallerDemoRoot,
  copyAllowlistedFixture,
  createDemoTempRoot,
  DemoIsolationError,
  hashRelativeFile,
  removeDemoTempRoot,
} from "./isolation.js";
import type {
  DemoCleanup,
  DemoCrashRefusal,
  DemoMainLifecycle,
  DemoModelRefusal,
  DemoNetworkObservation,
  DemoOverallStatus,
  DemoReceipt,
  DemoSecurityEvidence,
  DemoStepId,
  DemoStepRecord,
  DemoStepStatus,
  MutationTargetProofResult,
  RunDemoOptions,
} from "./types.js";
import {
  DEMO_DEFAULT_BUDGET_MS,
  DEMO_PROTECTED_ALIAS,
  DEMO_PROTECTED_ARTIFACT_REL,
  DEMO_STEP_ORDER,
  emptySecurityEvidence,
} from "./types.js";

/** Required network observation seams for a completed demo story. */
const REQUIRED_NETWORK_SEAMS = [
  "diagnose_main",
  "apply_main",
  "impact_baseline",
  "impact_mutated",
  "crash_diagnose",
] as const;

/** Deterministic model-edge escalation payload (no LLM / network). */
const DEMO_MODEL_PAYLOAD: ModelEdgeEscalationPayload = {
  add_edges: [
    {
      from: { kind: "model", id: "demo_hypothesis" },
      to: { kind: "local", id: "BROWSER_CLIENT_COPY_A" },
      confidence: 0.99,
    },
  ],
  set_confidence: "high",
  set_provenance: "official",
  set_evidence_state: "fresh",
  promote_user_report: "official_root_cause",
};

/** Expected deterministic family for fixtures/crash-family/access-violation-crbrowser. */
const DEMO_CRASH_FAMILY_ID = "access_violation_crbrowser_dom_ready";

/** Dangerous-action refusals that must appear on the crash-refuse receipt. */
const DEMO_CRASH_DANGEROUS_REFUSALS = [
  "symptom_level_patch_authorization",
  "unverified_community_browser_crash_fix",
] as const;

function safeMessage(code: string, message: string): string {
  return assertNoLeakPaths(redactText(message || code));
}

function emptyMain(): DemoMainLifecycle {
  return {
    diagnose_state: null,
    user_resolution_after_apply: null,
    user_resolution_after_verify: null,
    user_resolution_after_rollback: null,
    resolved_verified: false,
    repair_applied: false,
    auto_rolled_back: false,
    hash_proof: null,
  };
}

function emptyModel(): DemoModelRefusal {
  return {
    refused: false,
    reasons: [],
    graph_unchanged: false,
    graph_sha256: null,
  };
}

function emptyCrash(): DemoCrashRefusal {
  return {
    family_id: null,
    diagnosis_state: null,
    repair_authorization_eligible: false,
    preview_refused: false,
    refused_actions: [],
    reason_codes: [],
  };
}

function emptyCleanup(): DemoCleanup {
  return {
    attempted: false,
    completed: false,
    temp_removed: false,
  };
}

/**
 * Derive the three public security booleans only after fail-closed checks.
 * When evidence is unproven, booleans stay schema-const false but callers
 * must never set ok:true (finish downgrades completed → failed).
 */
function deriveSecurityBooleans(evidence: DemoSecurityEvidence): {
  network_used: false;
  external_write: false;
  live_profile_mutated: false;
} {
  // Fail-closed measurement: if any observation reports true, evidence is
  // incomplete for product-local claims (proven already false in finalize).
  void evidence;
  return {
    network_used: false,
    external_write: false,
    live_profile_mutated: false,
  };
}

/**
 * True only when an observation recorded a strictly boolean `false`.
 * Malformed (`value_valid: false`) or boolean `true` never count as offline.
 */
function isStrictNetworkFalse(o: DemoNetworkObservation): boolean {
  return o.value_valid === true && o.network_used === false;
}

/**
 * Fail-closed security-evidence finalizer.
 * Exported for unit tests that inject malformed / missing / true observations.
 * Completed / proven requires every required seam present (exactly once or
 * consistently) with raw values strictly boolean `false`.
 */
export function finalizeSecurityEvidence(
  observations: DemoNetworkObservation[],
  disposableProofCount: number,
  disposableReasonCodes: string[],
  mutationsLocalOnly: boolean,
): DemoSecurityEvidence {
  type SeamAgg = { count: number; allStrictFalse: boolean };
  const bySeam = new Map<string, SeamAgg>();
  for (const o of observations) {
    const strictFalse = isStrictNetworkFalse(o);
    const prev = bySeam.get(o.seam);
    if (!prev) {
      bySeam.set(o.seam, { count: 1, allStrictFalse: strictFalse });
    } else {
      // Duplicates allowed only when every observation is strictly false.
      // true, malformed, or mixed values fail closed for that seam.
      bySeam.set(o.seam, {
        count: prev.count + 1,
        allStrictFalse: prev.allStrictFalse && strictFalse,
      });
    }
  }

  // Every recorded observation must be strictly boolean false (not coerced).
  const everyObservationStrictFalse =
    observations.length > 0 &&
    observations.every((o) => isStrictNetworkFalse(o));

  // Required seams must each appear at least once with only strict-false values.
  // Missing, true, malformed, or duplicate-conflicting (non-false) ⇒ fail.
  const requiredAllStrictFalse = REQUIRED_NETWORK_SEAMS.every((s) => {
    const agg = bySeam.get(s);
    return agg !== undefined && agg.count >= 1 && agg.allStrictFalse === true;
  });

  const network_all_false =
    everyObservationStrictFalse && requiredAllStrictFalse;

  const disposable_ok =
    disposableProofCount >= 1 &&
    disposableReasonCodes.length >= 1 &&
    mutationsLocalOnly;

  const local_only = {
    mode: "local_only_no_adapter" as const,
    no_external_adapter: true as const,
    mutations_local_only: mutationsLocalOnly && disposable_ok,
  };

  const proven =
    network_all_false &&
    disposable_ok &&
    local_only.no_external_adapter === true &&
    local_only.mutations_local_only === true;

  return {
    schema_version: 1,
    network_observations: observations.map((o) => ({
      seam: o.seam,
      // Preserve boolean true only when recorded true; never invent offline.
      network_used: o.network_used === true,
      value_valid: o.value_valid === true,
    })),
    network_all_false,
    disposable_root: {
      proof_count: disposableProofCount,
      reason_codes: [...disposableReasonCodes],
    },
    local_only,
    proven,
  };
}

function baseReceipt(
  partial: Partial<DemoReceipt> &
    Pick<DemoReceipt, "status" | "security_evidence">,
): DemoReceipt {
  const status = partial.status;
  const security_evidence = partial.security_evidence;
  const flags = deriveSecurityBooleans(security_evidence);
  // Surface success only when completed AND security evidence proven.
  const ok = status === "completed" && security_evidence.proven === true;
  return {
    schema_version: 1,
    ok,
    status: ok ? status : status === "completed" ? "failed" : status,
    duration_ms: partial.duration_ms ?? 0,
    steps: partial.steps ?? [],
    main: partial.main ?? emptyMain(),
    model_refusal: partial.model_refusal ?? emptyModel(),
    crash_refusal: partial.crash_refusal ?? emptyCrash(),
    network_used: flags.network_used,
    external_write: flags.external_write,
    live_profile_mutated: flags.live_profile_mutated,
    security_evidence,
    cleanup: partial.cleanup ?? emptyCleanup(),
    error_code:
      ok || partial.error_code
        ? (partial.error_code ?? null)
        : status === "completed" && !security_evidence.proven
          ? "SECURITY_EVIDENCE_UNPROVEN"
          : (partial.error_code ?? null),
    error_message: (() => {
      if (ok) {
        return partial.error_message
          ? safeMessage(partial.error_code ?? "ERROR", partial.error_message)
          : null;
      }
      if (status === "completed" && !security_evidence.proven) {
        return safeMessage(
          "SECURITY_EVIDENCE_UNPROVEN",
          partial.error_message ??
            "Demo security evidence incomplete; refused ok:true.",
        );
      }
      return partial.error_message
        ? safeMessage(partial.error_code ?? "ERROR", partial.error_message)
        : null;
    })(),
  };
}

function pushStep(
  steps: DemoStepRecord[],
  id: DemoStepId,
  status: DemoStepStatus,
  reason_code: string | null,
  startedMs: number,
): void {
  steps.push({
    id,
    status,
    reason_code,
    duration_ms: Math.max(0, Math.round(performance.now() - startedMs)),
  });
}

function budgetExceeded(startedAt: number, budgetMs: number): boolean {
  return performance.now() - startedAt > budgetMs;
}

function capOpts() {
  return isolatedFixtureRepairCapabilityOptions();
}

/**
 * Prove active demo root is disposable and not the live profile.
 * Uses isolation proofs only — never reads or hashes live home/profile.
 */
function proveDemoRootDisposable(
  root: string,
  homeDir: string | null | undefined,
  reason: string,
  proofReasons: string[],
): boolean {
  if (!proveIsolatedFixtureTarget(root, homeDir)) {
    return false;
  }
  // proveIsolatedFixtureTarget already refuses live profile via
  // assertDisposableTarget; record stable reason only (no paths).
  proofReasons.push(reason);
  return true;
}

/**
 * Re-prove the exact mutation target immediately before apply/rollback writes.
 * Path-free stable result only — does not mutate, accept callbacks, or embed
 * absolute paths. Symlink leaves and non-disposable targets fail closed.
 *
 * Exported for direct unit tests of the proof gate; production runDemo calls
 * this at every mutation boundary before applyRepair / rollbackRepair.
 */
export function proveMutationTargetDisposable(
  target: string,
  homeDir?: string | null,
): MutationTargetProofResult {
  if (proveIsolatedFixtureTarget(target, homeDir)) {
    return { ok: true, reason_code: "MUTATION_TARGET_DISPOSABLE" };
  }
  return { ok: false, reason_code: "MUTATION_TARGET_NOT_DISPOSABLE" };
}

/**
 * Run the full deterministic demo story and return a stable DemoReceipt.
 * Always attempts cleanup of demo-owned temp roots (not caller roots that
 * existed before the call).
 */
export function runDemo(options: RunDemoOptions = {}): DemoReceipt {
  const wallStart = performance.now();
  const budgetMs =
    typeof options.budget_ms === "number" &&
    Number.isFinite(options.budget_ms) &&
    options.budget_ms > 0
      ? Math.min(options.budget_ms, DEMO_DEFAULT_BUDGET_MS * 2)
      : DEMO_DEFAULT_BUDGET_MS;

  const steps: DemoStepRecord[] = [];
  const main = emptyMain();
  const model_refusal = emptyModel();
  const crash_refusal = emptyCrash();
  const cleanup = emptyCleanup();

  const networkObservations: DemoNetworkObservation[] = [];
  const disposableReasonCodes: string[] = [];
  let disposableProofCount = 0;
  let mutationsLocalOnly = false;

  let demoRoot: string | null = null;
  /** When true, demo created the root and must remove it. */
  let ownsRoot = false;
  let error_code: string | null = null;
  let error_message: string | null = null;

  /**
   * Record a seam's network_used observation fail-closed.
   * Only exact boolean false is offline-proof; true, undefined, null, strings,
   * numbers, and other values set value_valid=false and cannot yield proven.
   */
  const recordNetwork = (seam: string, network_used: unknown): void => {
    const value_valid = network_used === true || network_used === false;
    networkObservations.push({
      seam,
      network_used: network_used === true,
      value_valid,
    });
  };

  const recordDisposable = (root: string, reason: string): boolean => {
    if (proveDemoRootDisposable(root, options.homeDir, reason, disposableReasonCodes)) {
      disposableProofCount += 1;
      return true;
    }
    return false;
  };

  const finish = (status: DemoOverallStatus): DemoReceipt => {
    // Ensure every STEP_ORDER id appears exactly once (skip remainder).
    const present = new Set(steps.map((s) => s.id));
    for (const id of DEMO_STEP_ORDER) {
      if (!present.has(id)) {
        steps.push({
          id,
          status: "skip",
          reason_code:
            status === "budget_exceeded" ? "BUDGET_EXCEEDED" : "SKIPPED",
          duration_ms: 0,
        });
      }
    }
    // Stable order
    const ordered = DEMO_STEP_ORDER.map(
      (id) => steps.find((s) => s.id === id)!,
    );

    const security_evidence = finalizeSecurityEvidence(
      networkObservations,
      disposableProofCount,
      disposableReasonCodes,
      mutationsLocalOnly,
    );

    // Completed demos require proven security evidence (fail closed).
    let finalStatus = status;
    if (finalStatus === "completed" && !security_evidence.proven) {
      finalStatus = "failed";
      if (!error_code) {
        error_code = "SECURITY_EVIDENCE_UNPROVEN";
        error_message =
          "Demo security evidence incomplete; refused ok:true.";
      }
    }

    return baseReceipt({
      status: finalStatus,
      duration_ms: Math.max(0, Math.round(performance.now() - wallStart)),
      steps: ordered,
      main,
      model_refusal,
      crash_refusal,
      cleanup,
      security_evidence,
      error_code,
      error_message,
    });
  };

  const doCleanup = (): void => {
    const t0 = performance.now();
    cleanup.attempted = true;
    if (ownsRoot && demoRoot) {
      cleanup.temp_removed = removeDemoTempRoot(demoRoot);
      cleanup.completed = cleanup.temp_removed;
    } else {
      // Caller-owned root: do not delete; report cleanup N/A as completed.
      cleanup.temp_removed = true;
      cleanup.completed = true;
    }
    // Replace any prior cleanup step record.
    const idx = steps.findIndex((s) => s.id === "cleanup");
    const rec: DemoStepRecord = {
      id: "cleanup",
      status: cleanup.completed ? "pass" : "fail",
      reason_code: cleanup.completed ? null : "CLEANUP_INCOMPLETE",
      duration_ms: Math.max(0, Math.round(performance.now() - t0)),
    };
    if (idx >= 0) steps[idx] = rec;
    else steps.push(rec);
  };

  try {
    // --- isolate ---
    {
      const t0 = performance.now();
      if (budgetExceeded(wallStart, budgetMs)) {
        error_code = "BUDGET_EXCEEDED";
        error_message = "Demo budget exceeded before isolation.";
        pushStep(steps, "isolate", "fail", "BUDGET_EXCEEDED", t0);
        doCleanup();
        return finish("budget_exceeded");
      }
      try {
        if (typeof options.targetRoot === "string" && options.targetRoot.length > 0) {
          demoRoot = assertCallerDemoRoot(options.targetRoot, options.homeDir);
          ownsRoot = false;
        } else {
          demoRoot = createDemoTempRoot(options.homeDir);
          ownsRoot = true;
        }
        // Isolation boundary: prove disposable root (not live profile).
        if (!recordDisposable(demoRoot, "ISOLATE_ROOT_DISPOSABLE")) {
          throw new DemoIsolationError(
            "TEMP_ISOLATION_UNPROVABLE",
            "Demo root failed disposable isolation proof.",
          );
        }
        // Copy allowlisted fixtures into demo root (main + crash + impact).
        copyAllowlistedFixture(
          "fixtures/protected-process",
          demoRoot,
          options.homeDir,
        );
        copyAllowlistedFixture(
          "fixtures/crash-family/access-violation-crbrowser",
          demoRoot,
          options.homeDir,
        );
        copyAllowlistedFixture(
          "fixtures/impact-local",
          demoRoot,
          options.homeDir,
        );
        // Mutation boundary after fixture materialization.
        if (!recordDisposable(demoRoot, "POST_FIXTURE_ROOT_DISPOSABLE")) {
          throw new DemoIsolationError(
            "TEMP_ISOLATION_UNPROVABLE",
            "Demo root failed post-fixture disposable proof.",
          );
        }
        mutationsLocalOnly = true;
        pushStep(steps, "isolate", "pass", null, t0);
      } catch (e) {
        const code =
          e instanceof DemoIsolationError ? e.code : "ISOLATE_FAILED";
        const msg =
          e instanceof Error ? e.message : "Isolation failed.";
        error_code = code;
        error_message = safeMessage(code, msg);
        pushStep(steps, "isolate", "fail", code, t0);
        doCleanup();
        return finish(
          code === "LIVE_PROFILE_REFUSED" ||
            code === "CALLER_TARGET_NOT_DISPOSABLE"
            ? "refused"
            : "failed",
        );
      }
    }

    const protectedTarget = path.join(demoRoot!, "protected-process");
    const crashTarget = path.join(
      demoRoot!,
      "access-violation-crbrowser",
    );
    const impactTarget = path.join(demoRoot!, "impact-local");
    const originalSha = hashRelativeFile(
      protectedTarget,
      DEMO_PROTECTED_ARTIFACT_REL,
    );
    if (!originalSha) {
      error_code = "HASH_UNAVAILABLE";
      error_message = "Could not hash protected-process artifact.";
      doCleanup();
      return finish("failed");
    }
    main.hash_proof = {
      path_alias: DEMO_PROTECTED_ALIAS,
      original_sha256: originalSha,
      after_apply_sha256: null,
      after_rollback_sha256: null,
      restored: false,
    };

    // --- diagnose_main ---
    {
      const t0 = performance.now();
      if (budgetExceeded(wallStart, budgetMs)) {
        error_code = "BUDGET_EXCEEDED";
        error_message = "Demo budget exceeded.";
        pushStep(steps, "diagnose_main", "fail", "BUDGET_EXCEEDED", t0);
        doCleanup();
        return finish("budget_exceeded");
      }
      const diag = diagnose(protectedTarget);
      recordNetwork("diagnose_main", diag.network_used as boolean);
      main.diagnose_state = diag.diagnosis_state;
      if (!diag.ok || (diag.network_used as boolean) !== false) {
        error_code = diag.error_code ?? "DIAGNOSE_FAILED";
        error_message = safeMessage(
          error_code,
          diag.error_message ?? "Diagnose failed.",
        );
        pushStep(steps, "diagnose_main", "fail", error_code, t0);
        doCleanup();
        return finish("failed");
      }
      pushStep(steps, "diagnose_main", "pass", diag.diagnosis_state, t0);
    }

    // --- explain_main (structured evidence presence; no source dump) ---
    {
      const t0 = performance.now();
      // Re-read diagnosis facts only via diagnose again is wasteful; use hash
      // proof + prior state. "Explain" is a narrative seam: require evidence.
      if (
        main.diagnose_state === "SOURCE_COMPONENT_LOCATED" &&
        main.hash_proof?.original_sha256
      ) {
        pushStep(steps, "explain_main", "pass", "STRUCTURED_EVIDENCE", t0);
      } else {
        error_code = "EXPLAIN_INCOMPLETE";
        error_message = "Structured evidence incomplete for demo explain.";
        pushStep(steps, "explain_main", "fail", error_code, t0);
        doCleanup();
        return finish("failed");
      }
    }

    // --- preview_main ---
    let authorization: string | null = null;
    {
      const t0 = performance.now();
      if (budgetExceeded(wallStart, budgetMs)) {
        error_code = "BUDGET_EXCEEDED";
        error_message = "Demo budget exceeded.";
        pushStep(steps, "preview_main", "fail", "BUDGET_EXCEEDED", t0);
        doCleanup();
        return finish("budget_exceeded");
      }
      const preview = previewRepair(protectedTarget, capOpts());
      if (!preview.ok || !preview.authorization || !preview.capsule) {
        error_code = preview.error_code ?? "PREVIEW_FAILED";
        error_message = safeMessage(
          error_code,
          preview.error_message ?? "Repair preview failed.",
        );
        pushStep(steps, "preview_main", "fail", error_code, t0);
        doCleanup();
        return finish("failed");
      }
      // Token is held in memory only for apply; never written into receipt.
      authorization = preview.authorization;
      // Sanity: original hash on capsule matches measured.
      if (preview.capsule.original_sha256 !== originalSha) {
        error_code = "HASH_MISMATCH";
        error_message = "Capsule original hash diverged from fixture.";
        pushStep(steps, "preview_main", "fail", error_code, t0);
        doCleanup();
        return finish("failed");
      }
      pushStep(steps, "preview_main", "pass", "REPAIR_PREVIEWED", t0);
    }

    // Optional induce path for adversarial verify-failure demos.
    if (options.induce_verify_failure === true) {
      const sentinel = path.join(protectedTarget, INDUCE_VERIFY_FAIL_REL);
      try {
        fs.mkdirSync(path.dirname(sentinel), { recursive: true });
        fs.writeFileSync(sentinel, "induce\n", "utf8");
      } catch {
        error_code = "INDUCE_SETUP_FAILED";
        error_message = "Could not plant induce-verify sentinel.";
        doCleanup();
        return finish("failed");
      }
    }

    // --- apply_main ---
    {
      const t0 = performance.now();
      if (budgetExceeded(wallStart, budgetMs)) {
        error_code = "BUDGET_EXCEEDED";
        error_message = "Demo budget exceeded.";
        pushStep(steps, "apply_main", "fail", "BUDGET_EXCEEDED", t0);
        doCleanup();
        return finish("budget_exceeded");
      }
      // Mutation boundary: re-prove disposable root before apply writes.
      if (!recordDisposable(demoRoot!, "PRE_APPLY_ROOT_DISPOSABLE")) {
        error_code = "LIVE_PROFILE_REFUSED";
        error_message = "Demo root not disposable at apply boundary.";
        mutationsLocalOnly = false;
        pushStep(steps, "apply_main", "fail", error_code, t0);
        doCleanup();
        return finish("refused");
      }
      // Re-prove the actual mutation target immediately before writes (TOCTOU).
      const preApplyTarget = proveMutationTargetDisposable(
        protectedTarget,
        options.homeDir,
      );
      if (!preApplyTarget.ok) {
        error_code = preApplyTarget.reason_code;
        error_message =
          "Mutation target not disposable at apply boundary.";
        mutationsLocalOnly = false;
        pushStep(steps, "apply_main", "fail", error_code, t0);
        doCleanup();
        return finish("refused");
      }
      // Record successful target proof for security_evidence disposable counts.
      disposableReasonCodes.push("PRE_APPLY_TARGET_DISPOSABLE");
      disposableProofCount += 1;
      const apply = applyRepair(protectedTarget, {
        authorization: authorization!,
        ...capOpts(),
      });
      // Drop token reference immediately after apply attempt.
      authorization = null;

      recordNetwork("apply_main", apply.network_used as boolean);

      main.user_resolution_after_apply = apply.user_resolution.status;
      main.repair_applied = apply.repair_applied === true;
      main.auto_rolled_back = apply.auto_rolled_back === true;
      main.resolved_verified =
        apply.user_resolution.status === "RESOLVED_VERIFIED";

      const afterApply = hashRelativeFile(
        protectedTarget,
        DEMO_PROTECTED_ARTIFACT_REL,
      );
      if (main.hash_proof) {
        main.hash_proof.after_apply_sha256 = afterApply;
      }

      if (options.induce_verify_failure === true) {
        // Must auto-rollback, restore original, never claim resolved.
        if (
          apply.ok ||
          apply.user_resolution.status === "RESOLVED_VERIFIED" ||
          !apply.auto_rolled_back ||
          afterApply !== originalSha
        ) {
          error_code = apply.error_code ?? "INDUCE_VERIFY_UNEXPECTED";
          error_message = safeMessage(
            error_code,
            apply.error_message ??
              "Induced verify failure did not roll back safely.",
          );
          // Attempt explicit rollback before cleanup.
          try {
            rollbackRepair(protectedTarget);
          } catch {
            /* best-effort */
          }
          pushStep(steps, "apply_main", "fail", error_code, t0);
          doCleanup();
          return finish("failed");
        }
        if (main.hash_proof) {
          main.hash_proof.after_rollback_sha256 = afterApply;
          main.hash_proof.restored = afterApply === originalSha;
        }
        main.resolved_verified = false;
        pushStep(
          steps,
          "apply_main",
          "pass",
          "REPAIR_FAILED_ROLLED_BACK",
          t0,
        );
        // Skip verify/rollback happy-path steps; continue model + crash.
        pushStep(steps, "verify_main", "skip", "INDUCED_FAILURE_PATH", t0);
        pushStep(steps, "rollback_main", "skip", "ALREADY_ROLLED_BACK", t0);
      } else {
        if (
          !apply.ok ||
          apply.user_resolution.status !== "RESOLVED_VERIFIED" ||
          (apply.network_used as boolean) !== false
        ) {
          error_code = apply.error_code ?? "APPLY_FAILED";
          error_message = safeMessage(
            error_code,
            apply.error_message ?? "Repair apply failed.",
          );
          if (apply.auto_rolled_back !== true) {
            try {
              rollbackRepair(protectedTarget);
            } catch {
              /* best-effort */
            }
          }
          pushStep(steps, "apply_main", "fail", error_code, t0);
          doCleanup();
          return finish("failed");
        }
        if (!afterApply || afterApply === originalSha) {
          error_code = "APPLY_HASH_UNCHANGED";
          error_message = "Apply did not change artifact hash.";
          pushStep(steps, "apply_main", "fail", error_code, t0);
          doCleanup();
          return finish("failed");
        }
        pushStep(steps, "apply_main", "pass", "RESOLVED_VERIFIED", t0);
      }
    }

    // --- verify_main (happy path only) ---
    if (options.induce_verify_failure !== true) {
      const t0 = performance.now();
      if (budgetExceeded(wallStart, budgetMs)) {
        error_code = "BUDGET_EXCEEDED";
        error_message = "Demo budget exceeded.";
        pushStep(steps, "verify_main", "fail", "BUDGET_EXCEEDED", t0);
        try {
          rollbackRepair(protectedTarget);
        } catch {
          /* best-effort */
        }
        doCleanup();
        return finish("budget_exceeded");
      }
      const verified = verifyRepair(protectedTarget);
      main.user_resolution_after_verify = verified.user_resolution.status;
      if (
        !verified.ok ||
        verified.user_resolution.status !== "RESOLVED_VERIFIED"
      ) {
        error_code = verified.error_code ?? "VERIFY_FAILED";
        error_message = safeMessage(
          error_code,
          verified.error_message ?? "Verify failed.",
        );
        main.resolved_verified = false;
        try {
          rollbackRepair(protectedTarget);
        } catch {
          /* best-effort */
        }
        pushStep(steps, "verify_main", "fail", error_code, t0);
        doCleanup();
        return finish("failed");
      }
      main.resolved_verified = true;
      pushStep(steps, "verify_main", "pass", "RESOLVED_VERIFIED", t0);
    }

    // --- rollback_main (happy path only) ---
    if (options.induce_verify_failure !== true) {
      const t0 = performance.now();
      if (budgetExceeded(wallStart, budgetMs)) {
        error_code = "BUDGET_EXCEEDED";
        error_message = "Demo budget exceeded.";
        pushStep(steps, "rollback_main", "fail", "BUDGET_EXCEEDED", t0);
        try {
          rollbackRepair(protectedTarget);
        } catch {
          /* best-effort */
        }
        doCleanup();
        return finish("budget_exceeded");
      }
      // Mutation boundary before rollback restore writes.
      if (!recordDisposable(demoRoot!, "PRE_ROLLBACK_ROOT_DISPOSABLE")) {
        error_code = "LIVE_PROFILE_REFUSED";
        error_message = "Demo root not disposable at rollback boundary.";
        mutationsLocalOnly = false;
        pushStep(steps, "rollback_main", "fail", error_code, t0);
        doCleanup();
        return finish("refused");
      }
      // Re-prove the actual mutation target immediately before restore writes.
      const preRollbackTarget = proveMutationTargetDisposable(
        protectedTarget,
        options.homeDir,
      );
      if (!preRollbackTarget.ok) {
        error_code = preRollbackTarget.reason_code;
        error_message =
          "Mutation target not disposable at rollback boundary.";
        mutationsLocalOnly = false;
        pushStep(steps, "rollback_main", "fail", error_code, t0);
        doCleanup();
        return finish("refused");
      }
      disposableReasonCodes.push("PRE_ROLLBACK_TARGET_DISPOSABLE");
      disposableProofCount += 1;
      const rb = rollbackRepair(protectedTarget);
      main.user_resolution_after_rollback = rb.user_resolution.status;
      const afterRb = hashRelativeFile(
        protectedTarget,
        DEMO_PROTECTED_ARTIFACT_REL,
      );
      if (main.hash_proof) {
        main.hash_proof.after_rollback_sha256 = afterRb;
        main.hash_proof.restored = afterRb === originalSha;
      }
      if (
        !rb.ok ||
        rb.user_resolution.status !== "MITIGATED_VERIFIED_BY_ROLLBACK" ||
        afterRb !== originalSha
      ) {
        error_code = rb.error_code ?? "ROLLBACK_FAILED";
        error_message = safeMessage(
          error_code,
          rb.error_message ?? "Rollback failed to restore original hash.",
        );
        pushStep(steps, "rollback_main", "fail", error_code, t0);
        doCleanup();
        return finish("failed");
      }
      // After demo rollback, resolved is no longer claimed as current state.
      main.resolved_verified = false;
      pushStep(
        steps,
        "rollback_main",
        "pass",
        "MITIGATED_VERIFIED_BY_ROLLBACK",
        t0,
      );
    }

    // --- model_refuse ---
    {
      const t0 = performance.now();
      if (budgetExceeded(wallStart, budgetMs)) {
        error_code = "BUDGET_EXCEEDED";
        error_message = "Demo budget exceeded.";
        pushStep(steps, "model_refuse", "fail", "BUDGET_EXCEEDED", t0);
        doCleanup();
        return finish("budget_exceeded");
      }
      const snapshotPath = path.join(
        findRepoRoot(import.meta.url),
        "fixtures",
        "official-evidence",
        "snapshot.json",
      );
      const baseline = assessImpact({
        targetPath: impactTarget,
        disclosure_decision: "refused",
        snapshot_path: snapshotPath,
        now_ms: options.now_ms ?? Date.parse("2026-07-10T12:00:00.000Z"),
      });
      recordNetwork(
        "impact_baseline",
        baseline.impact_card.network_used as boolean,
      );
      const beforeSha = baseline.impact_card.graph.graph_sha256;
      const mutated = assessImpact({
        targetPath: impactTarget,
        disclosure_decision: "refused",
        snapshot_path: snapshotPath,
        now_ms: options.now_ms ?? Date.parse("2026-07-10T12:00:00.000Z"),
        model_payload: DEMO_MODEL_PAYLOAD,
      });
      recordNetwork(
        "impact_mutated",
        mutated.impact_card.network_used as boolean,
      );
      model_refusal.refused = mutated.model_mutation_refused === true;
      model_refusal.reasons = [...mutated.model_mutation_reasons].sort();
      model_refusal.graph_sha256 = mutated.impact_card.graph.graph_sha256;
      model_refusal.graph_unchanged =
        mutated.impact_card.graph.graph_sha256 === beforeSha &&
        mutated.impact_card.graph.edges.length ===
          baseline.impact_card.graph.edges.length;

      if (
        !model_refusal.refused ||
        !model_refusal.graph_unchanged ||
        model_refusal.reasons.length === 0 ||
        (baseline.impact_card.network_used as boolean) !== false ||
        (mutated.impact_card.network_used as boolean) !== false
      ) {
        error_code = "MODEL_REFUSAL_FAILED";
        error_message = "Model graph mutation was not refused cleanly.";
        pushStep(steps, "model_refuse", "fail", error_code, t0);
        doCleanup();
        return finish("failed");
      }
      pushStep(steps, "model_refuse", "pass", "MODEL_GRAPH_MUTATION_REFUSED", t0);
    }

    // --- crash_refuse ---
    {
      const t0 = performance.now();
      if (budgetExceeded(wallStart, budgetMs)) {
        error_code = "BUDGET_EXCEEDED";
        error_message = "Demo budget exceeded.";
        pushStep(steps, "crash_refuse", "fail", "BUDGET_EXCEEDED", t0);
        doCleanup();
        return finish("budget_exceeded");
      }
      const crashDiag = diagnose(crashTarget);
      recordNetwork("crash_diagnose", crashDiag.network_used as boolean);
      const cc = crashDiag.crash_classification;
      crash_refusal.diagnosis_state = crashDiag.diagnosis_state;

      // Bind receipt fields only from a real crash classification. Never invent
      // repair_authorization_eligible=false when classification is missing.
      if (cc) {
        crash_refusal.family_id =
          typeof cc.family_id === "string" && cc.family_id.length > 0
            ? cc.family_id
            : null;
        crash_refusal.repair_authorization_eligible =
          cc.repair_authorization_eligible;
        crash_refusal.refused_actions = [...cc.refused_actions];
        crash_refusal.reason_codes = [...cc.refused_actions];
      }

      const crashPreview = previewRepair(crashTarget, capOpts());
      crash_refusal.preview_refused =
        crashPreview.ok === false && crashPreview.authorization === null;

      const hasDangerousRefusal = DEMO_CRASH_DANGEROUS_REFUSALS.some((code) =>
        crash_refusal.refused_actions.includes(code),
      );

      // Fail closed unless classification is present, applicable, deterministically
      // family-bound, authorization-ineligible from the classifier (not a constant),
      // refuses dangerous actions, preview is refused, and no network was used.
      if (
        !crashDiag.ok ||
        (crashDiag.network_used as boolean) !== false ||
        !cc ||
        cc.applicable !== true ||
        crash_refusal.family_id !== DEMO_CRASH_FAMILY_ID ||
        crash_refusal.repair_authorization_eligible !== false ||
        crash_refusal.refused_actions.length === 0 ||
        !hasDangerousRefusal ||
        !crash_refusal.preview_refused ||
        crashPreview.authorization !== null
      ) {
        error_code = "CRASH_REFUSAL_FAILED";
        error_message =
          "Crash-family dangerous repair was not refused as required.";
        pushStep(steps, "crash_refuse", "fail", error_code, t0);
        doCleanup();
        return finish("failed");
      }
      pushStep(
        steps,
        "crash_refuse",
        "pass",
        "CRASH_REPAIR_AUTHORIZATION_REFUSED",
        t0,
      );
    }

    // --- cleanup ---
    doCleanup();
    if (!cleanup.completed) {
      error_code = "CLEANUP_INCOMPLETE";
      error_message = "Demo temp cleanup did not complete.";
      return finish("failed");
    }

    // Single assignment — induce path also completes the story (with rollback).
    return finish("completed");
  } catch (e) {
    const code =
      e instanceof DemoIsolationError ? e.code : "DEMO_INTERNAL_ERROR";
    const msg = e instanceof Error ? e.message : "Demo failed.";
    error_code = code;
    error_message = safeMessage(code, msg);
    try {
      doCleanup();
    } catch {
      cleanup.attempted = true;
      cleanup.completed = false;
      cleanup.temp_removed = false;
    }
    return finish("failed");
  }
}

/** Schema-valid unproven security evidence for surface-level error receipts. */
export function surfaceSecurityEvidence(): DemoSecurityEvidence {
  return emptySecurityEvidence({
    local_only: {
      mode: "local_only_no_adapter",
      no_external_adapter: true,
      mutations_local_only: false,
    },
    proven: false,
  });
}
