/**
 * Recovery engine — preview, authorize-bound apply, verify, rollback.
 * Ticket 02: isolated protected-process fixture.
 * Ticket 07: isolated config set/remove pack.
 * Ticket 08: isolated plugin-cache / version-skew / reconciliation pack.
 * Diagnosis modules remain read-only; only this recovery surface mutates.
 *
 * Preview is completely read-only over the entire target tree (no .changeguard).
 * Apply receives a self-contained authorization token; backup paths come only
 * from registered constants — never from mutable token/session path fields.
 */
import path from "node:path";
import { MAX_ARTIFACT_BYTES } from "../limits.js";
import { measureProtectedProcessAst, sha256Buffer } from "../measure.js";
import { isPluginCacheTarget } from "../plugin-cache/index.js";
import { PLUGIN_CACHE_CAPSULE_ID } from "../plugin-cache/limits.js";
import {
  PathSafetyError,
  resolveTargetDirectory,
} from "../path-safety.js";
import { assertNoLeakPaths, redactText } from "../redact.js";
import type { MeasuredEvidence } from "../types.js";
import {
  AuthTokenError,
  decodeAuthorizationToken,
  encodeAuthorizationToken,
} from "./auth-token.js";
import {
  atomicReplaceFile,
  createVerifiedBackup,
  openTargetFile,
  readSessionState,
  restoreFromBackup,
  scopeDigestForTarget,
  writeSessionState,
} from "./atomic-write.js";
import { digestObject, receiptId } from "./canonical.js";
import {
  artifactRel,
  artifactPathAlias,
  authorizationBinding,
  coreHealthChecks,
  defaultExpiryIso,
  invalidationMaterial,
  isExpired,
  mintNonce,
  operationDigest,
  preHandshakeFailureStillPresent,
  PROTECTED_PROCESS_OP,
  removeProtectedProcessBlock,
} from "./protected-process.js";
import {
  buildLiveConfigPlan,
  configStartupVerification,
  isConfigCapsuleId,
  planConfigRepair,
  relForConfigAlias,
  type ConfigRepairPlan,
} from "./config-repair.js";
import {
  applyPluginCacheRepair,
  backupPluginCachePair,
  buildPluginCacheCapsule,
  isPluginCacheCapsuleId,
  planPluginCacheRepair,
  pluginCacheArtifactRel,
  pluginCacheBackupRel,
  pluginCacheManifestBackupRel,
  pluginCacheManifestRel,
  recomputePluginCacheLiveBinding,
  runPluginCacheVerification,
} from "./plugin-cache.js";
import type {
  AdminHandoff,
  ApplyOptions,
  BackupReceipt,
  PreviewOptions,
  RepairCapsule,
  RepairResult,
  VerificationReport,
} from "./types.js";
import {
  INDUCE_VERIFY_FAIL_REL,
  registeredBackupRel,
  RECOVERY_SESSION_REL,
} from "./types.js";
import {
  evaluateWindowsWriteGate,
  type WindowsWriteGateContext,
} from "./windows-write-gate.js";

const CAPSULE_ID = "protected-process-shim-experimental-v1";
/** Upper bound on authorization token string length (base64url envelope). */
const MAX_AUTH_TOKEN_LEN = 48 * 1024;

function userReceipt(
  status: RepairResult["user_resolution"]["status"],
  summary: string,
): RepairResult["user_resolution"] {
  return { status, summary, receipt_id: receiptId("user") };
}

function upstreamReceipt(
  status: RepairResult["upstream_contribution"]["status"],
  summary: string,
  issue_candidates: string[] = [],
): RepairResult["upstream_contribution"] {
  return {
    status,
    summary,
    issue_candidates,
    receipt_id: receiptId("upstream"),
  };
}

function baseResult(
  partial: Partial<RepairResult> &
    Pick<RepairResult, "ok" | "operation" | "user_resolution" | "upstream_contribution">,
): RepairResult {
  return {
    schema_version: 1,
    ok: partial.ok,
    operation: partial.operation,
    capsule: partial.capsule ?? null,
    authorization: partial.authorization ?? null,
    user_resolution: partial.user_resolution,
    upstream_contribution: partial.upstream_contribution,
    evidence: partial.evidence ?? [],
    error_code: partial.error_code ?? null,
    error_message: partial.error_message
      ? assertNoLeakPaths(redactText(partial.error_message))
      : null,
    network_used: false,
    target_mutated: partial.target_mutated ?? false,
    repair_applied: partial.repair_applied ?? false,
    auto_rolled_back: partial.auto_rolled_back ?? false,
    verification: partial.verification ?? null,
    backup: partial.backup ?? null,
    resulting_sha256: partial.resulting_sha256 ?? null,
    contribution_claim: "none",
    admin_handoff: partial.admin_handoff ?? null,
  };
}

function fail(
  operation: RepairResult["operation"],
  code: string,
  message: string,
  extra: Partial<RepairResult> = {},
): RepairResult {
  return baseResult({
    ok: false,
    operation,
    user_resolution: userReceipt(
      code === "ADMIN_ACTION_REQUIRED"
        ? "ADMIN_ACTION_REQUIRED"
        : code === "AUTH_INVALID" ||
            code === "AUTH_EXPIRED" ||
            code === "AUTH_MALFORMED" ||
            code === "AUTH_REPLAY" ||
            code === "NOT_APPLICABLE"
          ? "REPAIR_REFUSED"
          : "INCONCLUSIVE",
      code === "ADMIN_ACTION_REQUIRED"
        ? "Administrator action required; no local bypass offered."
        : "Repair operation refused or could not complete safely.",
    ),
    upstream_contribution: upstreamReceipt(
      "NONE",
      "No upstream contribution; local recovery only.",
      [],
    ),
    error_code: code,
    error_message: message,
    ...extra,
  });
}

function buildCapsule(input: {
  scope_digest: string;
  original_sha256: string;
  pattern_count: number;
  expected_result_sha256: string;
  op_digest: string;
}): RepairCapsule {
  const expires_at = defaultExpiryIso();
  const nonce = mintNonce();
  const backup_rel = registeredBackupRel(PROTECTED_PROCESS_OP.target_path_alias);
  const invalidation_digest = invalidationMaterial({
    original_sha256: input.original_sha256,
    expected_pattern_count: input.pattern_count,
    scope_digest: input.scope_digest,
    operation_digest: input.op_digest,
    expected_result_sha256: input.expected_result_sha256,
    backup_rel,
    capsule_id: CAPSULE_ID,
    mode: "apply_authorized",
    authorization_tier: "experimental_one_shot",
  });
  const binding = authorizationBinding({
    capsule_id: CAPSULE_ID,
    scope_digest: input.scope_digest,
    original_sha256: input.original_sha256,
    expected_pattern_count: input.pattern_count,
    operation_digest: input.op_digest,
    expected_result_sha256: input.expected_result_sha256,
    backup_rel,
    invalidation_digest,
    trust_tier: "T1_community",
    authorization_tier: "experimental_one_shot",
    mode: "apply_authorized",
    target_path_alias: PROTECTED_PROCESS_OP.target_path_alias,
    expires_at,
    nonce,
  });

  return {
    schema_version: 1,
    capsule_id: CAPSULE_ID,
    trust_tier: "T1_community",
    mode: "apply_authorized",
    authorization_tier: "experimental_one_shot",
    risk: "moderate",
    target_path_alias: PROTECTED_PROCESS_OP.target_path_alias,
    scope_digest: input.scope_digest,
    original_sha256: input.original_sha256,
    expected_pattern_count: input.pattern_count,
    operation: {
      kind: "exact_block_removal",
      target_path_alias: PROTECTED_PROCESS_OP.target_path_alias,
      expected_pattern_count: input.pattern_count,
      operation_digest: input.op_digest,
      expected_result_sha256: input.expected_result_sha256,
      config_key: null,
      old_value_type: null,
      old_value_summary: null,
      new_value: null,
    },
    applicability: {
      version_match: false,
      platform_match: true,
      target_hash_match: true,
      pattern_count_match: input.pattern_count === 1,
    },
    backup: {
      required: true,
      original_sha256: input.original_sha256,
      backup_rel,
      verified: false,
      receipt_id: null,
    },
    verification: {
      checks: [
        "pattern-count-zero-after-repair",
        "original-failure-not-reproduced",
        "core-health-marker-export",
        "core-health-size-and-delimiters",
        "result-hash-matches-expected",
      ],
      original_failure_must_not_reproduce: true,
      core_health_required: true,
    },
    rollback: {
      recipe: [
        "Restore exact original bytes from verified backup under the isolated target.",
        "Re-verify original SHA-256.",
        "Clear applied-repair session state.",
      ],
      restores_original_sha256: input.original_sha256,
    },
    dry_run_checks: [
      "pattern-count-equals-one",
      "target-hash-matches",
      "scope-isolated",
      "authorization-binding-fresh",
    ],
    expires_at,
    invalidation_digest,
    authorization_binding: binding,
    disclosure: {
      fields_leaving_device: [],
      includes_source_bytes: false,
      includes_secrets: false,
    },
    human_decision: "pending",
    smoke_result: "not_run",
    nonce,
  };
}

function windowsGateContextFrom(
  opts: PreviewOptions | ApplyOptions | undefined,
  writePaths?: WindowsWriteGateContext["writePaths"],
): WindowsWriteGateContext {
  return {
    hostPlatform: opts?.hostPlatform,
    userOwnedRoots: opts?.userOwnedRoots,
    managed: opts?.managed,
    writePaths: writePaths ?? opts?.writePaths,
  };
}

function refuseWindowsWriteScope(
  operation: "preview" | "apply",
  targetReal: string,
  opts?: PreviewOptions | ApplyOptions,
  writePaths?: WindowsWriteGateContext["writePaths"],
  extra: Partial<RepairResult> = {},
): RepairResult | null {
  const gate = evaluateWindowsWriteGate(
    targetReal,
    windowsGateContextFrom(opts, writePaths),
  );
  if (!gate.blocked) return null;
  return fail(operation, gate.error_code, gate.error_message, {
    admin_handoff: gate.admin_handoff,
    user_resolution: userReceipt(
      "ADMIN_ACTION_REQUIRED",
      "Windows target requires administrator/IT action; local mutation refused.",
    ),
    upstream_contribution: upstreamReceipt(
      "NONE",
      "No local repair; IT handoff only.",
    ),
    evidence: [
      {
        kind: "windows_write_scope",
        detail: `scope=${gate.classification.scope} policy_class=${gate.classification.policy_class}`,
        measured: true,
      },
    ],
    ...extra,
  });
}

/**
 * Preview a Repair Capsule for the isolated target.
 * Tries Ticket 08 plugin-cache when inventory is present, then protected-process,
 * then Ticket 07 config set/remove.
 * Completely read-only over the entire target tree — no .changeguard writes.
 * Returns a self-contained authorization token for cross-process apply.
 *
 * On trusted Windows hosts, write-scope classification runs first (target dir +
 * optional artifact paths): admin/forbidden/unknown fail closed with
 * ADMIN_ACTION_REQUIRED + IT handoff.
 */
export function previewRepair(
  targetPath: string,
  options: PreviewOptions = {},
): RepairResult {
  let targetReal: string;
  try {
    ({ targetReal } = resolveTargetDirectory(targetPath));
  } catch (e) {
    if (e instanceof PathSafetyError) return fail("preview", e.code, e.message);
    return fail("preview", "TARGET_ERROR", "Target refused.");
  }

  // Ticket 14: Windows write-scope gate (shared CLI/MCP recovery path).
  const winRefuse = refuseWindowsWriteScope("preview", targetReal, options);
  if (winRefuse) return winRefuse;

  // Ticket 08 plugin-cache pack takes precedence when inventory is present.
  if (isPluginCacheTarget(targetReal)) {
    return previewPluginCacheRepair(targetReal);
  }

  const evidence: MeasuredEvidence[] = [];
  const scope_digest = scopeDigestForTarget(targetReal);

  // --- Protected-process path ---
  try {
    const file = openTargetFile(targetReal, artifactRel(), MAX_ARTIFACT_BYTES);
    const ast = measureProtectedProcessAst(file.bytes.toString("utf8"));
    evidence.push({
      kind: "artifact_hash",
      detail: `Measured ${artifactPathAlias()} sha256=${file.sha256}`,
      measured: true,
    });
    evidence.push({
      kind: "ast_signature",
      detail: `blockCount=${ast.blockCount} matched=${ast.matched}`,
      measured: true,
    });

    if (ast.matched && ast.blockCount === 1) {
      const source = file.bytes.toString("utf8");
      if (preHandshakeFailureStillPresent(source)) {
        const plan = removeProtectedProcessBlock(source);
        if (plan && plan.result_pattern_count === 0) {
          const op_digest = operationDigest();
          const capsule = buildCapsule({
            scope_digest,
            original_sha256: file.sha256,
            pattern_count: 1,
            expected_result_sha256: plan.result_sha256,
            op_digest,
          });
          let authorization: string;
          try {
            authorization = encodeAuthorizationToken(capsule);
          } catch (e) {
            if (e instanceof AuthTokenError) {
              return fail("preview", e.code, e.message, { evidence });
            }
            return fail("preview", "PREVIEW_ERROR", "Preview failed.", { evidence });
          }
          evidence.push({
            kind: "capsule_preview",
            detail: `Capsule ${capsule.capsule_id} binding=${capsule.authorization_binding.slice(0, 16)}…`,
            measured: true,
          });
          return baseResult({
            ok: true,
            operation: "preview",
            capsule,
            authorization,
            user_resolution: userReceipt(
              "REPAIR_PREVIEWED",
              "Repair Capsule preview ready. One scope-bound authorization required to apply.",
            ),
            upstream_contribution: upstreamReceipt(
              "CANDIDATE_ONLY",
              "Local experimental repair only; no external submission.",
              ["openai/codex#32925"],
            ),
            evidence,
            target_mutated: false,
            repair_applied: false,
          });
        }
      }
    }
  } catch (e) {
    if (e instanceof PathSafetyError) {
      if (e.code !== "CANDIDATE_NOT_FOUND") {
        return fail("preview", e.code, e.message, { evidence });
      }
      // Missing protected-process artifact — fall through to config path.
    } else {
      return fail("preview", "PREVIEW_ERROR", "Preview failed.", { evidence });
    }
  }

  // --- Ticket 07 config path ---
  try {
    return previewConfigRepair(targetReal, scope_digest, evidence);
  } catch (e) {
    if (e instanceof PathSafetyError) {
      return fail("preview", e.code, e.message, { evidence });
    }
    return fail("preview", "PREVIEW_ERROR", "Preview failed.", { evidence });
  }
}

/** Ticket 08: preview plugin-cache verified resource copy capsule. */
function previewPluginCacheRepair(targetReal: string): RepairResult {
  const evidence: MeasuredEvidence[] = [];
  try {
    const planned = planPluginCacheRepair(targetReal);
    if (!planned.ok) {
      return fail("preview", planned.code, planned.message, {
        evidence: planned.classification
          ? [
              {
                kind: "plugin_cache_classification",
                detail: planned.classification.reason,
                measured: true,
              },
            ]
          : evidence,
        user_resolution: userReceipt(
          "REPAIR_REFUSED",
          planned.code === "NOT_APPLICABLE"
            ? "No matching plugin-cache mechanism; repair refused."
            : "Plugin-cache repair refused.",
        ),
      });
    }
    const plan = planned.plan;
    const scope_digest = scopeDigestForTarget(targetReal);
    evidence.push({
      kind: "plugin_cache_mechanism",
      detail: `mechanism=${plan.mechanism}`,
      measured: true,
    });
    evidence.push({
      kind: "artifact_hash",
      detail: `Measured ${plan.cache_file.sha256.slice(0, 16)}…`,
      measured: true,
    });
    evidence.push({
      kind: "instance_identity",
      detail: `instance_id=${plan.observation.instance_id} cache_path_hash=${plan.observation.cache_path_hash.slice(0, 16)}…`,
      measured: true,
    });
    evidence.push({
      kind: "trusted_rebuild_source",
      detail: `verified rebuild source sha256=${plan.trusted_file.sha256.slice(0, 16)}…`,
      measured: true,
    });

    const capsule = buildPluginCacheCapsule({
      scope_digest,
      original_sha256: plan.cache_file.sha256,
      expected_result_sha256: plan.expected_result_sha256,
      mechanism: plan.mechanism,
    });

    let authorization: string;
    try {
      authorization = encodeAuthorizationToken(capsule);
    } catch (e) {
      if (e instanceof AuthTokenError) {
        return fail("preview", e.code, e.message, { evidence });
      }
      return fail("preview", "PREVIEW_ERROR", "Preview failed.", { evidence });
    }

    evidence.push({
      kind: "capsule_preview",
      detail: `Capsule ${capsule.capsule_id} binding=${capsule.authorization_binding.slice(0, 16)}…`,
      measured: true,
    });

    return baseResult({
      ok: true,
      operation: "preview",
      capsule,
      authorization,
      user_resolution: userReceipt(
        "REPAIR_PREVIEWED",
        `Plugin-cache Repair Capsule preview ready (${plan.mechanism}). One scope-bound authorization required to apply.`,
      ),
      upstream_contribution: upstreamReceipt(
        "CANDIDATE_ONLY",
        "Local experimental plugin-cache repair only; no external submission.",
        [],
      ),
      evidence,
      target_mutated: false,
      repair_applied: false,
    });
  } catch (e) {
    if (e instanceof PathSafetyError) {
      return fail("preview", e.code, e.message, { evidence });
    }
    return fail("preview", "PREVIEW_ERROR", "Preview failed.", { evidence });
  }
}

function previewConfigRepair(
  targetReal: string,
  scope_digest: string,
  evidence: MeasuredEvidence[],
): RepairResult {
  const { probe, managed_block } = planConfigRepair(targetReal);

  if (managed_block && probe.managed) {
    const m = probe.managed;
    const handoff: AdminHandoff = {
      policy_class: m.policy_class,
      target_path_alias: m.path_alias,
      config_key: probe.fault?.config_key || null,
      requested_action:
        "Contact IT/admin to update managed Codex control configuration through approved enterprise change process.",
      evidence_digests: [m.sha256].filter(Boolean),
      admin_owned: m.admin_owned,
      signed: m.signed,
      permission_bound: m.permission_bound,
    };
    evidence.push({
      kind: "managed_policy",
      detail: `policy_class=${m.policy_class} admin_owned=${m.admin_owned}`,
      measured: true,
    });
    return baseResult({
      ok: false,
      operation: "preview",
      user_resolution: userReceipt(
        "ADMIN_ACTION_REQUIRED",
        "Managed/admin-owned/signed/permission-bound configuration requires administrator action.",
      ),
      upstream_contribution: upstreamReceipt(
        "NONE",
        "No local repair; IT handoff only.",
      ),
      evidence,
      error_code: "ADMIN_ACTION_REQUIRED",
      error_message:
        "Target is under managed policy; local mutation is refused and no privilege-elevation guidance is offered.",
      admin_handoff: handoff,
    });
  }

  if (!probe.fault) {
    return fail(
      "preview",
      "NOT_APPLICABLE",
      "No applicable protected-process or config repair for this target.",
      {
        evidence,
        user_resolution: userReceipt(
          "REPAIR_REFUSED",
          "No matching repairable mechanism; repair refused.",
        ),
      },
    );
  }

  // Open the fault target file and build a live plan.
  const target_rel =
    probe.fault.path_rel ||
    relForConfigAlias(probe.fault.path_alias) ||
    null;
  if (!target_rel) {
    return fail("preview", "NOT_APPLICABLE", "Config repair target unknown.", {
      evidence,
    });
  }
  // Source conflict repairs the override file.
  const openRel =
    probe.fault.fault_class === "ConfigSourceConflictError"
      ? "config/config.override.toml"
      : target_rel;

  let file: ReturnType<typeof openTargetFile>;
  try {
    file = openTargetFile(targetReal, openRel, MAX_ARTIFACT_BYTES);
  } catch (e) {
    if (e instanceof PathSafetyError) {
      return fail("preview", e.code, e.message, { evidence });
    }
    return fail("preview", "PREVIEW_ERROR", "Preview failed.", { evidence });
  }

  const text = file.bytes.toString("utf8");
  const plan = buildLiveConfigPlan(text, file.sha256, probe);
  if (!plan || !plan.next_text) {
    return fail(
      "preview",
      "NOT_APPLICABLE",
      "Config fault is not covered by a registered set/remove repair.",
      {
        evidence,
        user_resolution: userReceipt(
          "REPAIR_REFUSED",
          "Config fault diagnosed but no registered repair operation applies.",
        ),
      },
    );
  }

  evidence.push({
    kind: "config_fault",
    detail: `fault_class=${plan.fault.fault_class} key=${plan.config_key}`,
    measured: true,
  });
  evidence.push({
    kind: "config_hash",
    detail: `Measured ${plan.target_path_alias} sha256=${file.sha256}`,
    measured: true,
  });

  const capsule = buildConfigCapsule(scope_digest, plan);
  let authorization: string;
  try {
    authorization = encodeAuthorizationToken(capsule);
  } catch (e) {
    if (e instanceof AuthTokenError) {
      return fail("preview", e.code, e.message, { evidence });
    }
    return fail("preview", "PREVIEW_ERROR", "Preview failed.", { evidence });
  }

  evidence.push({
    kind: "capsule_preview",
    detail: `Capsule ${capsule.capsule_id} op=${plan.kind} key=${plan.config_key}`,
    measured: true,
  });

  return baseResult({
    ok: true,
    operation: "preview",
    capsule,
    authorization,
    user_resolution: userReceipt(
      "REPAIR_PREVIEWED",
      "Config Repair Capsule preview ready. One scope-bound authorization required to apply.",
    ),
    upstream_contribution: upstreamReceipt(
      "CANDIDATE_ONLY",
      "Local experimental config repair only; no external submission.",
      ["openai/codex#33790"],
    ),
    evidence,
    target_mutated: false,
    repair_applied: false,
  });
}

function buildConfigCapsule(
  scope_digest: string,
  plan: ConfigRepairPlan,
): RepairCapsule {
  const expires_at = defaultExpiryIso();
  const nonce = mintNonce();
  const backup_rel = registeredBackupRel(plan.target_path_alias);
  const invalidation_digest = invalidationMaterial({
    original_sha256: plan.original_sha256,
    expected_pattern_count: plan.expected_pattern_count,
    scope_digest,
    operation_digest: plan.operation_digest,
    expected_result_sha256: plan.result_sha256,
    backup_rel,
    capsule_id: plan.capsule_id,
    mode: "apply_authorized",
    authorization_tier: "experimental_one_shot",
  });
  const binding = authorizationBinding({
    capsule_id: plan.capsule_id,
    scope_digest,
    original_sha256: plan.original_sha256,
    expected_pattern_count: plan.expected_pattern_count,
    operation_digest: plan.operation_digest,
    expected_result_sha256: plan.result_sha256,
    backup_rel,
    invalidation_digest,
    trust_tier: "T1_community",
    authorization_tier: "experimental_one_shot",
    mode: "apply_authorized",
    target_path_alias: plan.target_path_alias,
    expires_at,
    nonce,
  });

  return {
    schema_version: 1,
    capsule_id: plan.capsule_id,
    trust_tier: "T1_community",
    mode: "apply_authorized",
    authorization_tier: "experimental_one_shot",
    risk: "moderate",
    target_path_alias: plan.target_path_alias,
    scope_digest,
    original_sha256: plan.original_sha256,
    expected_pattern_count: plan.expected_pattern_count,
    operation: {
      kind: plan.kind,
      target_path_alias: plan.target_path_alias,
      expected_pattern_count: plan.expected_pattern_count,
      operation_digest: plan.operation_digest,
      expected_result_sha256: plan.result_sha256,
      config_key: plan.config_key,
      old_value_type: plan.old_value_type,
      old_value_summary: plan.old_value_summary,
      new_value: plan.new_value,
    },
    applicability: {
      version_match: false,
      platform_match: true,
      target_hash_match: true,
      pattern_count_match: true,
    },
    backup: {
      required: true,
      original_sha256: plan.original_sha256,
      backup_rel,
      verified: false,
      receipt_id: null,
    },
    verification: {
      checks: [
        "original-failure-not-reproduced",
        "config-reload",
        "registered-command",
        "result-hash-matches-expected",
      ],
      original_failure_must_not_reproduce: true,
      core_health_required: true,
    },
    rollback: {
      recipe: [
        "Restore exact original config bytes from verified backup under the isolated target.",
        "Re-verify original SHA-256.",
        "Clear applied-repair session state.",
      ],
      restores_original_sha256: plan.original_sha256,
    },
    dry_run_checks: [
      "config-fault-matches-registered-op",
      "target-hash-matches",
      "scope-isolated",
      "authorization-binding-fresh",
    ],
    expires_at,
    invalidation_digest,
    authorization_binding: binding,
    disclosure: {
      fields_leaving_device: [],
      includes_source_bytes: false,
      includes_secrets: false,
    },
    human_decision: "pending",
    smoke_result: "not_run",
    nonce,
  };
}

type LivePlan =
  | {
      kind: "exact_block_removal";
      file: ReturnType<typeof openTargetFile>;
      next: string;
      target_rel: string;
    }
  | {
      kind: "config_set" | "config_remove";
      file: ReturnType<typeof openTargetFile>;
      next: string;
      target_rel: string;
      config_plan: ConfigRepairPlan;
    };

function recomputeLiveBinding(
  targetReal: string,
  capsule: RepairCapsule,
):
  | { ok: true; live: LivePlan }
  | { ok: false; code: string; message: string } {
  if (isExpired(capsule.expires_at)) {
    return { ok: false, code: "AUTH_EXPIRED", message: "Capsule authorization expired." };
  }
  const scope_digest = scopeDigestForTarget(targetReal);
  if (scope_digest !== capsule.scope_digest) {
    return { ok: false, code: "AUTH_INVALID", message: "Scope changed; authorization invalid." };
  }

  if (capsule.operation.kind === "exact_block_removal") {
    return recomputeProtectedProcessBinding(targetReal, capsule, scope_digest);
  }
  if (
    capsule.operation.kind === "config_set" ||
    capsule.operation.kind === "config_remove"
  ) {
    return recomputeConfigBinding(targetReal, capsule, scope_digest);
  }
  return { ok: false, code: "AUTH_INVALID", message: "Unknown operation kind." };
}

function recomputeProtectedProcessBinding(
  targetReal: string,
  capsule: RepairCapsule,
  scope_digest: string,
):
  | { ok: true; live: LivePlan }
  | { ok: false; code: string; message: string } {
  let file: ReturnType<typeof openTargetFile>;
  try {
    file = openTargetFile(targetReal, artifactRel(), MAX_ARTIFACT_BYTES);
  } catch (e) {
    if (e instanceof PathSafetyError) {
      return { ok: false, code: e.code, message: e.message };
    }
    return { ok: false, code: "TARGET_ERROR", message: "Target refused." };
  }
  if (file.sha256 !== capsule.original_sha256) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Target hash changed; authorization invalid.",
    };
  }
  const source = file.bytes.toString("utf8");
  const ast = measureProtectedProcessAst(source);
  if (!ast.matched || ast.blockCount !== capsule.expected_pattern_count) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Pattern count changed; authorization invalid.",
    };
  }
  const plan = removeProtectedProcessBlock(source);
  if (!plan) {
    return { ok: false, code: "REPAIR_PLAN", message: "Repair plan no longer applicable." };
  }
  if (plan.result_sha256 !== capsule.operation.expected_result_sha256) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Operation result digest changed; authorization invalid.",
    };
  }
  const op_digest = operationDigest();
  if (op_digest !== capsule.operation.operation_digest) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Operation digest changed; authorization invalid.",
    };
  }
  const backup_rel = registeredBackupRel(PROTECTED_PROCESS_OP.target_path_alias);
  if (capsule.backup.backup_rel !== backup_rel) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Backup path refused; authorization invalid.",
    };
  }
  const bindingCheck = verifyBindingMaterial(
    capsule,
    file.sha256,
    scope_digest,
    op_digest,
    backup_rel,
  );
  if (!bindingCheck.ok) return bindingCheck;
  return {
    ok: true,
    live: {
      kind: "exact_block_removal",
      file,
      next: plan.next,
      target_rel: artifactRel(),
    },
  };
}

function recomputeConfigBinding(
  targetReal: string,
  capsule: RepairCapsule,
  scope_digest: string,
):
  | { ok: true; live: LivePlan }
  | { ok: false; code: string; message: string } {
  if (!isConfigCapsuleId(capsule.capsule_id)) {
    return { ok: false, code: "AUTH_INVALID", message: "Config capsule id refused." };
  }
  const target_rel = relForConfigAlias(capsule.target_path_alias);
  if (!target_rel) {
    return { ok: false, code: "AUTH_INVALID", message: "Config target alias refused." };
  }
  let file: ReturnType<typeof openTargetFile>;
  try {
    file = openTargetFile(targetReal, target_rel, MAX_ARTIFACT_BYTES);
  } catch (e) {
    if (e instanceof PathSafetyError) {
      return { ok: false, code: e.code, message: e.message };
    }
    return { ok: false, code: "TARGET_ERROR", message: "Target refused." };
  }
  if (file.sha256 !== capsule.original_sha256) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Target hash changed; authorization invalid.",
    };
  }
  const { probe, managed_block } = planConfigRepair(targetReal);
  if (managed_block) {
    return {
      ok: false,
      code: "ADMIN_ACTION_REQUIRED",
      message: "Target became managed; authorization invalid.",
    };
  }
  const text = file.bytes.toString("utf8");
  const config_plan = buildLiveConfigPlan(text, file.sha256, probe);
  if (!config_plan || config_plan.capsule_id !== capsule.capsule_id) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Config repair plan no longer applicable.",
    };
  }
  if (config_plan.result_sha256 !== capsule.operation.expected_result_sha256) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Operation result digest changed; authorization invalid.",
    };
  }
  if (config_plan.operation_digest !== capsule.operation.operation_digest) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Operation digest changed; authorization invalid.",
    };
  }
  if (config_plan.config_key !== capsule.operation.config_key) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Config key changed; authorization invalid.",
    };
  }
  const backup_rel = registeredBackupRel(capsule.target_path_alias);
  if (capsule.backup.backup_rel !== backup_rel) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Backup path refused; authorization invalid.",
    };
  }
  const bindingCheck = verifyBindingMaterial(
    capsule,
    file.sha256,
    scope_digest,
    config_plan.operation_digest,
    backup_rel,
  );
  if (!bindingCheck.ok) return bindingCheck;
  return {
    ok: true,
    live: {
      kind: config_plan.kind,
      file,
      next: config_plan.next_text,
      target_rel,
      config_plan,
    },
  };
}

function verifyBindingMaterial(
  capsule: RepairCapsule,
  original_sha256: string,
  scope_digest: string,
  op_digest: string,
  backup_rel: string,
): { ok: true } | { ok: false; code: string; message: string } {
  const invalidation_digest = invalidationMaterial({
    original_sha256,
    expected_pattern_count: capsule.expected_pattern_count,
    scope_digest,
    operation_digest: op_digest,
    expected_result_sha256: capsule.operation.expected_result_sha256,
    backup_rel,
    capsule_id: capsule.capsule_id,
    mode: capsule.mode,
    authorization_tier: capsule.authorization_tier,
  });
  if (invalidation_digest !== capsule.invalidation_digest) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Invalidation material changed; authorization invalid.",
    };
  }
  const expectedBinding = authorizationBinding({
    capsule_id: capsule.capsule_id,
    scope_digest,
    original_sha256,
    expected_pattern_count: capsule.expected_pattern_count,
    operation_digest: op_digest,
    expected_result_sha256: capsule.operation.expected_result_sha256,
    backup_rel,
    invalidation_digest,
    trust_tier: capsule.trust_tier,
    authorization_tier: capsule.authorization_tier,
    mode: capsule.mode,
    target_path_alias: capsule.target_path_alias,
    expires_at: capsule.expires_at,
    nonce: capsule.nonce,
  });
  if (expectedBinding !== capsule.authorization_binding) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Capsule binding mismatch; authorization invalid.",
    };
  }
  return { ok: true };
}

/**
 * Refuse replay of a token that already completed a successful apply (or was
 * consumed and rolled back). Session state is ChangeGuard-owned and written
 * only after authorized apply begins.
 */
function refuseConsumedToken(
  targetReal: string,
  capsule: RepairCapsule,
): { refuse: true; code: string; message: string } | { refuse: false } {
  const session = readSessionState(targetReal, RECOVERY_SESSION_REL, 64 * 1024);
  if (!session) return { refuse: false };
  const consumed =
    session.consumed === true ||
    session.status === "resolved_verified" ||
    session.status === "explicit_rollback";
  const sameBinding =
    typeof session.authorization_binding === "string" &&
    session.authorization_binding.toLowerCase() ===
      capsule.authorization_binding.toLowerCase();
  const sameNonce =
    typeof session.nonce === "string" && session.nonce === capsule.nonce;
  if (consumed && (sameBinding || sameNonce)) {
    return {
      refuse: true,
      code: "AUTH_REPLAY",
      message: "Authorization token already consumed; re-preview required.",
    };
  }
  // Materially different session after rollback/recreation: if session records
  // a different original hash for a still-consumed binding family, refuse silent
  // re-authorization of a different repair session with this token material.
  if (
    consumed &&
    typeof session.original_sha256 === "string" &&
    session.original_sha256 !== capsule.original_sha256 &&
    sameBinding
  ) {
    return {
      refuse: true,
      code: "AUTH_REPLAY",
      message: "Authorization does not match this recovery session.",
    };
  }
  return { refuse: false };
}

function runVerification(
  targetReal: string,
  originalSha: string,
  expectedResultSha: string,
  opts: {
    family: "protected_process" | "config";
    target_rel: string;
  } = { family: "protected_process", target_rel: artifactRel() },
): VerificationReport {
  const checks: VerificationReport["checks"] = [];
  let measured_sha256: string | null = null;
  let measured_pattern_count: number | null = null;
  let original_failure_reproduces = true;
  let core_health_passed = false;

  // Harness-induced verification failure: sentinel file under isolated target.
  try {
    openTargetFile(targetReal, INDUCE_VERIFY_FAIL_REL, 4096);
    checks.push({
      id: "induced_verify_fail",
      passed: false,
      detail: "Induced verification failure sentinel present.",
    });
    return {
      passed: false,
      original_failure_reproduces: true,
      core_health_passed: false,
      checks,
      measured_sha256: null,
      measured_pattern_count: null,
    };
  } catch (e) {
    if (!(e instanceof PathSafetyError) || e.code !== "CANDIDATE_NOT_FOUND") {
      checks.push({
        id: "induced_verify_probe",
        passed: false,
        detail: "Verification probe error.",
      });
      return {
        passed: false,
        original_failure_reproduces: true,
        core_health_passed: false,
        checks,
        measured_sha256: null,
        measured_pattern_count: null,
      };
    }
  }

  if (opts.family === "config") {
    const r = configStartupVerification(
      targetReal,
      expectedResultSha,
      opts.target_rel,
      originalSha,
    );
    return {
      passed: r.passed,
      original_failure_reproduces: r.original_failure_reproduces,
      core_health_passed: r.core_health_passed,
      checks: r.checks,
      measured_sha256: r.measured_sha256,
      measured_pattern_count: null,
    };
  }

  try {
    const file = openTargetFile(targetReal, artifactRel(), MAX_ARTIFACT_BYTES);
    measured_sha256 = file.sha256;
    const source = file.bytes.toString("utf8");
    const ast = measureProtectedProcessAst(source);
    measured_pattern_count = ast.blockCount;
    original_failure_reproduces = preHandshakeFailureStillPresent(source);

    checks.push({
      id: "original_failure_absent",
      passed: !original_failure_reproduces,
      detail: original_failure_reproduces
        ? "Original protected-process failure still reproduces."
        : "Original failure no longer reproduces.",
    });
    checks.push({
      id: "pattern_count_zero",
      passed: ast.blockCount === 0,
      detail: `pattern_count=${ast.blockCount}`,
    });
    checks.push({
      id: "hash_changed",
      passed: file.sha256 !== originalSha,
      detail:
        file.sha256 !== originalSha
          ? "Artifact hash differs from original."
          : "Artifact hash unchanged.",
    });
    checks.push({
      id: "expected_result_hash",
      passed: file.sha256 === expectedResultSha,
      detail:
        file.sha256 === expectedResultSha
          ? "Result hash matches capsule expectation."
          : "Result hash does not match capsule expectation.",
    });
    const health = coreHealthChecks(source);
    core_health_passed = health.passed;
    checks.push(...health.checks);
  } catch (e) {
    const msg = e instanceof PathSafetyError ? e.message : "Verification failed.";
    checks.push({ id: "verify_error", passed: false, detail: msg });
    return {
      passed: false,
      original_failure_reproduces: true,
      core_health_passed: false,
      checks,
      measured_sha256,
      measured_pattern_count,
    };
  }

  const passed =
    checks.every((c) => c.passed) &&
    !original_failure_reproduces &&
    core_health_passed;

  return {
    passed,
    original_failure_reproduces,
    core_health_passed,
    checks,
    measured_sha256,
    measured_pattern_count,
  };
}

/**
 * Apply one experimental repair after exact scope-consistent authorization.
 * On verification failure, automatically restores original bytes.
 * No state write occurs until authorization and live preconditions pass.
 *
 * On trusted Windows hosts, write-scope classification runs on the target
 * directory and the live artifact write path before any mutation.
 */
export function applyRepair(targetPath: string, options: ApplyOptions): RepairResult {
  const auth =
    typeof options.authorization === "string" ? options.authorization.trim() : "";
  if (!auth || auth.length < 16 || auth.length > MAX_AUTH_TOKEN_LEN) {
    return fail("apply", "AUTH_INVALID", "Authorization token refused.");
  }

  let targetReal: string;
  try {
    ({ targetReal } = resolveTargetDirectory(targetPath));
  } catch (e) {
    if (e instanceof PathSafetyError) return fail("apply", e.code, e.message);
    return fail("apply", "TARGET_ERROR", "Target refused.");
  }

  // Ticket 14: Windows write-scope gate before any mutation (target dir).
  const winRefuseEarly = refuseWindowsWriteScope("apply", targetReal, options);
  if (winRefuseEarly) return winRefuseEarly;

  // Decode self-contained token (no target-local preview file).
  let capsule: RepairCapsule;
  try {
    capsule = decodeAuthorizationToken(auth);
  } catch (e) {
    if (e instanceof AuthTokenError) {
      return fail("apply", e.code === "AUTH_EXPIRED" ? "AUTH_EXPIRED" : "AUTH_INVALID", e.message);
    }
    return fail("apply", "AUTH_INVALID", "Authorization token refused.");
  }

  const replay = refuseConsumedToken(targetReal, capsule);
  if (replay.refuse) {
    return fail("apply", replay.code, replay.message, { capsule });
  }

  // Ticket 08 plugin-cache apply path.
  if (isPluginCacheCapsuleId(capsule.capsule_id)) {
    // Classify capsule artifact write path when resolvable.
    const cacheRel = pluginCacheArtifactRel();
    const winRefuseCache = refuseWindowsWriteScope(
      "apply",
      targetReal,
      options,
      [
        {
          absPath: path.join(targetReal, cacheRel),
          alias: capsule.target_path_alias,
        },
      ],
      { capsule },
    );
    if (winRefuseCache) return winRefuseCache;
    return applyPluginCacheAuthorized(targetReal, capsule);
  }

  // Mechanism must still be present and match capsule preconditions.
  const liveResult = recomputeLiveBinding(targetReal, capsule);
  if (!liveResult.ok) {
    return fail("apply", liveResult.code, liveResult.message, { capsule });
  }
  const live = liveResult.live;

  // Classify the actual artifact write path under the target.
  const winRefuseArtifact = refuseWindowsWriteScope(
    "apply",
    targetReal,
    options,
    [
      {
        absPath: path.join(targetReal, live.target_rel),
        alias: capsule.target_path_alias,
      },
    ],
    { capsule },
  );
  if (winRefuseArtifact) return winRefuseArtifact;

  const evidence: MeasuredEvidence[] = [
    {
      kind: "authorization",
      detail: "Authorization token verified against live preconditions.",
      measured: true,
    },
  ];
  let backupReceipt: BackupReceipt | null = null;
  // Always derive backup path from registered constants — never token/session path.
  const backup_rel = registeredBackupRel(capsule.target_path_alias);
  const target_rel = live.target_rel;
  const verifyFamily: "protected_process" | "config" =
    live.kind === "exact_block_removal" ? "protected_process" : "config";

  try {
    // First authorized mutation: transaction state + backup under ChangeGuard dir.
    const backup = createVerifiedBackup(targetReal, backup_rel, live.file);
    backupReceipt = {
      backup_rel,
      original_sha256: backup.original_sha256,
      verified: backup.verified,
      receipt_id: backup.receipt_id,
    };
    evidence.push({
      kind: "backup_verified",
      detail: `Backup verified sha256=${backup.original_sha256}`,
      measured: true,
    });

    const newBytes = Buffer.from(live.next, "utf8");
    const replaced = atomicReplaceFile(
      targetReal,
      target_rel,
      live.file,
      newBytes,
      MAX_ARTIFACT_BYTES,
    );
    evidence.push({
      kind: "atomic_replace",
      detail: `Replaced artifact resulting_sha256=${replaced.resulting_sha256}`,
      measured: true,
    });

    // Session state for explicit rollback / one-shot replay protection.
    writeSessionState(targetReal, RECOVERY_SESSION_REL, {
      schema_version: 1,
      capsule_id: capsule.capsule_id,
      original_sha256: capsule.original_sha256,
      result_sha256: replaced.resulting_sha256,
      backup_rel,
      target_path_alias: capsule.target_path_alias,
      target_rel,
      repair_family: verifyFamily,
      authorization_binding: capsule.authorization_binding,
      nonce: capsule.nonce,
      applied_at: new Date().toISOString(),
      status: "applied_pending_verify",
      consumed: false,
    });

    const verification = runVerification(
      targetReal,
      capsule.original_sha256,
      capsule.operation.expected_result_sha256,
      { family: verifyFamily, target_rel },
    );
    evidence.push({
      kind: "verification",
      detail: `passed=${verification.passed} original_failure_reproduces=${verification.original_failure_reproduces}`,
      measured: true,
    });

    if (!verification.passed) {
      // Automatic rollback — RESOLVED_VERIFIED is impossible.
      restoreFromBackup(
        targetReal,
        target_rel,
        backup_rel,
        capsule.original_sha256,
        MAX_ARTIFACT_BYTES,
      );
      const restored = openTargetFile(targetReal, target_rel, MAX_ARTIFACT_BYTES);
      writeSessionState(targetReal, RECOVERY_SESSION_REL, {
        schema_version: 1,
        capsule_id: capsule.capsule_id,
        original_sha256: capsule.original_sha256,
        status: "auto_rolled_back",
        backup_rel,
        target_path_alias: capsule.target_path_alias,
        target_rel,
        repair_family: verifyFamily,
        authorization_binding: capsule.authorization_binding,
        nonce: capsule.nonce,
        // Failed apply is not a successful consumption; same token may retry
        // only while live preconditions still match.
        consumed: false,
      });
      evidence.push({
        kind: "auto_rollback",
        detail: `Restored original sha256=${restored.sha256}`,
        measured: true,
      });
      return baseResult({
        ok: false,
        operation: "apply",
        capsule: {
          ...capsule,
          human_decision: "approved",
          smoke_result: "fail",
          backup: {
            ...capsule.backup,
            verified: true,
            receipt_id: backupReceipt.receipt_id,
          },
        },
        user_resolution: userReceipt(
          "REPAIR_FAILED_ROLLED_BACK",
          "Verification failed; automatic rollback restored original bytes. RESOLVED_VERIFIED is impossible.",
        ),
        upstream_contribution: upstreamReceipt(
          "NONE",
          "No upstream contribution; local recovery only.",
        ),
        evidence,
        error_code: "VERIFY_FAILED",
        error_message: "Verification failed; automatic rollback completed.",
        target_mutated: true, // mutated then restored — net may equal original
        repair_applied: false,
        auto_rolled_back: true,
        verification,
        backup: backupReceipt,
        resulting_sha256: restored.sha256,
      });
    }

    writeSessionState(targetReal, RECOVERY_SESSION_REL, {
      schema_version: 1,
      capsule_id: capsule.capsule_id,
      original_sha256: capsule.original_sha256,
      result_sha256: replaced.resulting_sha256,
      backup_rel,
      target_path_alias: capsule.target_path_alias,
      target_rel,
      repair_family: verifyFamily,
      authorization_binding: capsule.authorization_binding,
      nonce: capsule.nonce,
      applied_at: new Date().toISOString(),
      status: "resolved_verified",
      consumed: true,
    });

    return baseResult({
      ok: true,
      operation: "apply",
      capsule: {
        ...capsule,
        human_decision: "approved",
        smoke_result: "pass",
        backup: {
          ...capsule.backup,
          verified: true,
          receipt_id: backupReceipt.receipt_id,
        },
      },
      user_resolution: userReceipt(
        "RESOLVED_VERIFIED",
        "Original failure no longer reproduces and core health checks passed. Local repair only; no external submission.",
      ),
      upstream_contribution: upstreamReceipt(
        "CANDIDATE_ONLY",
        "Local recovery receipt only; upstream contribution is separate and not submitted.",
        ["openai/codex#32925"],
      ),
      evidence,
      target_mutated: true,
      repair_applied: true,
      auto_rolled_back: false,
      verification,
      backup: backupReceipt,
      resulting_sha256: replaced.resulting_sha256,
    });
  } catch (e) {
    // Best-effort rollback if backup exists.
    if (backupReceipt) {
      try {
        restoreFromBackup(
          targetReal,
          target_rel,
          backup_rel,
          capsule.original_sha256,
          MAX_ARTIFACT_BYTES,
        );
        return baseResult({
          ok: false,
          operation: "apply",
          capsule,
          user_resolution: userReceipt(
            "REPAIR_FAILED_ROLLED_BACK",
            "Apply failed; automatic rollback restored original bytes.",
          ),
          upstream_contribution: upstreamReceipt("NONE", "No upstream contribution."),
          evidence,
          error_code: e instanceof PathSafetyError ? e.code : "APPLY_ERROR",
          error_message: e instanceof PathSafetyError ? e.message : "Apply failed.",
          target_mutated: true,
          repair_applied: false,
          auto_rolled_back: true,
          backup: backupReceipt,
          resulting_sha256: capsule.original_sha256,
        });
      } catch {
        /* fall through */
      }
    }
    if (e instanceof PathSafetyError) {
      return fail("apply", e.code, e.message, {
        capsule,
        evidence,
        backup: backupReceipt,
      });
    }
    return fail("apply", "APPLY_ERROR", "Apply failed.", {
      capsule,
      evidence,
      backup: backupReceipt,
    });
  }
}

/** Ticket 08 authorized apply for plugin-cache pack. */
function applyPluginCacheAuthorized(
  targetReal: string,
  capsule: RepairCapsule,
): RepairResult {
  const live = recomputePluginCacheLiveBinding(targetReal, capsule);
  if (!live.ok) {
    return fail("apply", live.code, live.message, { capsule });
  }
  // Scope must still match preview binding.
  const scope_digest = scopeDigestForTarget(targetReal);
  if (scope_digest !== capsule.scope_digest) {
    return fail("apply", "AUTH_INVALID", "Scope changed; authorization invalid.", {
      capsule,
    });
  }

  const plan = live.plan;
  const evidence: MeasuredEvidence[] = [
    {
      kind: "authorization",
      detail: "Authorization token verified against live plugin-cache preconditions.",
      measured: true,
    },
    {
      kind: "plugin_cache_mechanism",
      detail: `mechanism=${plan.mechanism}`,
      measured: true,
    },
  ];
  let backupReceipt: BackupReceipt | null = null;
  const backup_rel = pluginCacheBackupRel();

  try {
    const backups = backupPluginCachePair(
      targetReal,
      plan.cache_file,
      plan.manifest_file,
    );
    backupReceipt = {
      backup_rel,
      original_sha256: backups.cache.original_sha256,
      verified: backups.cache.verified && backups.manifest.verified,
      receipt_id: backups.cache.receipt_id,
    };
    evidence.push({
      kind: "backup_verified",
      detail: `Cache+manifest backups verified sha256=${backups.cache.original_sha256.slice(0, 16)}…`,
      measured: true,
    });

    const replaced = applyPluginCacheRepair(targetReal, plan);
    evidence.push({
      kind: "verified_resource_copy",
      detail: `Atomic trusted copy resulting_sha256=${replaced.resulting_sha256}`,
      measured: true,
    });

    writeSessionState(targetReal, RECOVERY_SESSION_REL, {
      schema_version: 1,
      capsule_id: capsule.capsule_id,
      pack: "plugin_cache",
      repair_family: "plugin_cache",
      original_sha256: capsule.original_sha256,
      original_manifest_sha256: plan.manifest_file.sha256,
      result_sha256: replaced.resulting_sha256,
      backup_rel,
      manifest_backup_rel: pluginCacheManifestBackupRel(),
      target_path_alias: capsule.target_path_alias,
      target_rel: pluginCacheArtifactRel(),
      authorization_binding: capsule.authorization_binding,
      nonce: capsule.nonce,
      applied_at: new Date().toISOString(),
      status: "applied_pending_verify",
      consumed: false,
    });

    const verification = runPluginCacheVerification(
      targetReal,
      capsule.original_sha256,
      capsule.operation.expected_result_sha256,
      { runReconCycle: true },
    );
    evidence.push({
      kind: "verification",
      detail: `passed=${verification.passed} original_failure_reproduces=${verification.original_failure_reproduces}`,
      measured: true,
    });

    if (!verification.passed) {
      restoreFromBackup(
        targetReal,
        pluginCacheArtifactRel(),
        backup_rel,
        capsule.original_sha256,
        MAX_ARTIFACT_BYTES,
      );
      restoreFromBackup(
        targetReal,
        pluginCacheManifestRel(),
        pluginCacheManifestBackupRel(),
        plan.manifest_file.sha256,
        MAX_ARTIFACT_BYTES,
      );
      const restored = openTargetFile(
        targetReal,
        pluginCacheArtifactRel(),
        MAX_ARTIFACT_BYTES,
      );
      writeSessionState(targetReal, RECOVERY_SESSION_REL, {
        schema_version: 1,
        capsule_id: capsule.capsule_id,
        pack: "plugin_cache",
        repair_family: "plugin_cache",
        original_sha256: capsule.original_sha256,
        original_manifest_sha256: plan.manifest_file.sha256,
        status: "auto_rolled_back",
        backup_rel,
        manifest_backup_rel: pluginCacheManifestBackupRel(),
        target_path_alias: capsule.target_path_alias,
        target_rel: pluginCacheArtifactRel(),
        authorization_binding: capsule.authorization_binding,
        nonce: capsule.nonce,
        consumed: false,
      });
      evidence.push({
        kind: "auto_rollback",
        detail: `Restored original cache+manifest sha256=${restored.sha256.slice(0, 16)}…`,
        measured: true,
      });
      const blocked =
        verification.original_failure_reproduces === true
          ? "Recurrence or verification failure after reconciliation cycle; RESOLVED_VERIFIED blocked."
          : "Verification failed; automatic rollback restored original cache+manifest bytes.";
      return baseResult({
        ok: false,
        operation: "apply",
        capsule: {
          ...capsule,
          human_decision: "approved",
          smoke_result: "fail",
          backup: {
            ...capsule.backup,
            verified: true,
            receipt_id: backupReceipt.receipt_id,
          },
        },
        user_resolution: userReceipt("REPAIR_FAILED_ROLLED_BACK", blocked),
        upstream_contribution: upstreamReceipt(
          "NONE",
          "No upstream contribution; local recovery only.",
        ),
        evidence,
        error_code: verification.original_failure_reproduces
          ? "RECURRENCE_BLOCKED"
          : "VERIFY_FAILED",
        error_message: blocked,
        target_mutated: true,
        repair_applied: false,
        auto_rolled_back: true,
        verification,
        backup: backupReceipt,
        resulting_sha256: restored.sha256,
      });
    }

    writeSessionState(targetReal, RECOVERY_SESSION_REL, {
      schema_version: 1,
      capsule_id: capsule.capsule_id,
      pack: "plugin_cache",
      repair_family: "plugin_cache",
      original_sha256: capsule.original_sha256,
      original_manifest_sha256: plan.manifest_file.sha256,
      result_sha256: replaced.resulting_sha256,
      backup_rel,
      manifest_backup_rel: pluginCacheManifestBackupRel(),
      target_path_alias: capsule.target_path_alias,
      target_rel: pluginCacheArtifactRel(),
      authorization_binding: capsule.authorization_binding,
      nonce: capsule.nonce,
      applied_at: new Date().toISOString(),
      status: "resolved_verified",
      consumed: true,
    });

    return baseResult({
      ok: true,
      operation: "apply",
      capsule: {
        ...capsule,
        human_decision: "approved",
        smoke_result: "pass",
        backup: {
          ...capsule.backup,
          verified: true,
          receipt_id: backupReceipt.receipt_id,
        },
      },
      user_resolution: userReceipt(
        "RESOLVED_VERIFIED",
        "Plugin-cache fault cleared across reconciliation cycle and restart health check. Local repair only.",
      ),
      upstream_contribution: upstreamReceipt(
        "CANDIDATE_ONLY",
        "Local recovery receipt only; upstream contribution is separate and not submitted.",
        [],
      ),
      evidence,
      target_mutated: true,
      repair_applied: true,
      auto_rolled_back: false,
      verification,
      backup: backupReceipt,
      resulting_sha256: replaced.resulting_sha256,
    });
  } catch (e) {
    if (backupReceipt) {
      try {
        restoreFromBackup(
          targetReal,
          pluginCacheArtifactRel(),
          backup_rel,
          capsule.original_sha256,
          MAX_ARTIFACT_BYTES,
        );
        return baseResult({
          ok: false,
          operation: "apply",
          capsule,
          user_resolution: userReceipt(
            "REPAIR_FAILED_ROLLED_BACK",
            "Apply failed; automatic rollback restored original cache bytes.",
          ),
          upstream_contribution: upstreamReceipt("NONE", "No upstream contribution."),
          evidence,
          error_code: e instanceof PathSafetyError ? e.code : "APPLY_ERROR",
          error_message: e instanceof PathSafetyError ? e.message : "Apply failed.",
          target_mutated: true,
          repair_applied: false,
          auto_rolled_back: true,
          backup: backupReceipt,
          resulting_sha256: capsule.original_sha256,
        });
      } catch {
        /* fall through */
      }
    }
    if (e instanceof PathSafetyError) {
      return fail("apply", e.code, e.message, {
        capsule,
        evidence,
        backup: backupReceipt,
      });
    }
    return fail("apply", "APPLY_ERROR", "Apply failed.", {
      capsule,
      evidence,
      backup: backupReceipt,
    });
  }
}

/** Verify current target against original failure + core health. */
export function verifyRepair(targetPath: string): RepairResult {
  let targetReal: string;
  try {
    ({ targetReal } = resolveTargetDirectory(targetPath));
  } catch (e) {
    if (e instanceof PathSafetyError) return fail("verify", e.code, e.message);
    return fail("verify", "TARGET_ERROR", "Target refused.");
  }

  const session = readSessionState(targetReal, RECOVERY_SESSION_REL, 64 * 1024);
  const originalSha =
    typeof session?.original_sha256 === "string" ? session.original_sha256 : null;
  const expectedResult =
    typeof session?.result_sha256 === "string" ? session.result_sha256 : null;

  if (!originalSha || !expectedResult) {
    return fail(
      "verify",
      "NO_SESSION",
      "No recovery session; apply a repair before verify.",
    );
  }

  const isPluginPack =
    session?.pack === "plugin_cache" ||
    session?.repair_family === "plugin_cache" ||
    session?.capsule_id === PLUGIN_CACHE_CAPSULE_ID;

  if (isPluginPack) {
    const verification = runPluginCacheVerification(
      targetReal,
      originalSha,
      expectedResult,
      { runReconCycle: true },
    );
    const evidence: MeasuredEvidence[] = [
      {
        kind: "verification",
        detail: `passed=${verification.passed}`,
        measured: true,
      },
    ];
    if (!verification.passed) {
      return baseResult({
        ok: false,
        operation: "verify",
        user_resolution: userReceipt(
          "INCONCLUSIVE",
          verification.original_failure_reproduces
            ? "Recurrence or verification failure; RESOLVED_VERIFIED is impossible."
            : "Verification did not pass; RESOLVED_VERIFIED is impossible.",
        ),
        upstream_contribution: upstreamReceipt("NONE", "No upstream contribution."),
        evidence,
        error_code: verification.original_failure_reproduces
          ? "RECURRENCE_BLOCKED"
          : "VERIFY_FAILED",
        error_message: "Verification failed.",
        verification,
        resulting_sha256: verification.measured_sha256,
        repair_applied: session?.status === "resolved_verified",
        target_mutated: false,
      });
    }
    return baseResult({
      ok: true,
      operation: "verify",
      user_resolution: userReceipt(
        "RESOLVED_VERIFIED",
        "Verification passed: original failure absent and core health OK.",
      ),
      upstream_contribution: upstreamReceipt(
        "CANDIDATE_ONLY",
        "Local verification only; no external submission.",
        [],
      ),
      evidence,
      verification,
      resulting_sha256: verification.measured_sha256,
      repair_applied: true,
      target_mutated: false,
    });
  }

  const family =
    session?.repair_family === "config" ? "config" : "protected_process";
  const target_rel =
    typeof session?.target_rel === "string" && session.target_rel.length > 0
      ? session.target_rel
      : artifactRel();

  const verification = runVerification(targetReal, originalSha, expectedResult, {
    family,
    target_rel,
  });
  const evidence: MeasuredEvidence[] = [
    {
      kind: "verification",
      detail: `passed=${verification.passed}`,
      measured: true,
    },
  ];

  if (!verification.passed) {
    return baseResult({
      ok: false,
      operation: "verify",
      user_resolution: userReceipt(
        "INCONCLUSIVE",
        "Verification did not pass; RESOLVED_VERIFIED is impossible.",
      ),
      upstream_contribution: upstreamReceipt("NONE", "No upstream contribution."),
      evidence,
      error_code: "VERIFY_FAILED",
      error_message: "Verification failed.",
      verification,
      resulting_sha256: verification.measured_sha256,
      repair_applied: session?.status === "resolved_verified",
      target_mutated: false,
    });
  }

  return baseResult({
    ok: true,
    operation: "verify",
    user_resolution: userReceipt(
      "RESOLVED_VERIFIED",
      "Verification passed: original failure absent and core health OK.",
    ),
    upstream_contribution: upstreamReceipt(
      "CANDIDATE_ONLY",
      "Local verification only; no external submission.",
      ["openai/codex#32925"],
    ),
    evidence,
    verification,
    resulting_sha256: verification.measured_sha256,
    repair_applied: true,
    target_mutated: false,
  });
}

/** Explicit rollback to verified original bytes. */
export function rollbackRepair(targetPath: string): RepairResult {
  let targetReal: string;
  try {
    ({ targetReal } = resolveTargetDirectory(targetPath));
  } catch (e) {
    if (e instanceof PathSafetyError) return fail("rollback", e.code, e.message);
    return fail("rollback", "TARGET_ERROR", "Target refused.");
  }

  const session = readSessionState(targetReal, RECOVERY_SESSION_REL, 64 * 1024);
  if (!session) {
    return fail("rollback", "NO_SESSION", "No recovery session to roll back.");
  }
  const originalSha =
    typeof session.original_sha256 === "string" ? session.original_sha256 : null;
  if (!originalSha) {
    return fail("rollback", "NO_SESSION", "Session missing original hash.");
  }

  const isPluginPack =
    session.pack === "plugin_cache" ||
    session.repair_family === "plugin_cache" ||
    session.capsule_id === PLUGIN_CACHE_CAPSULE_ID;

  if (isPluginPack) {
    const backup_rel = pluginCacheBackupRel();
    const artifact = pluginCacheArtifactRel();
    const evidence: MeasuredEvidence[] = [];
    try {
      const restored = restoreFromBackup(
        targetReal,
        artifact,
        backup_rel,
        originalSha,
        MAX_ARTIFACT_BYTES,
      );
      evidence.push({
        kind: "explicit_rollback",
        detail: `Restored sha256=${restored.resulting_sha256}`,
        measured: true,
      });

      const originalManifest =
        typeof session.original_manifest_sha256 === "string"
          ? session.original_manifest_sha256
          : null;
      if (originalManifest) {
        const mRestored = restoreFromBackup(
          targetReal,
          pluginCacheManifestRel(),
          pluginCacheManifestBackupRel(),
          originalManifest,
          MAX_ARTIFACT_BYTES,
        );
        evidence.push({
          kind: "manifest_rollback",
          detail: `Manifest restored sha256=${mRestored.resulting_sha256.slice(0, 16)}…`,
          measured: true,
        });
        const mLive = openTargetFile(
          targetReal,
          pluginCacheManifestRel(),
          MAX_ARTIFACT_BYTES,
        );
        if (mLive.sha256 !== originalManifest) {
          return fail("rollback", "ROLLBACK_MISMATCH", "Manifest rollback hash mismatch.", {
            evidence,
            resulting_sha256: mLive.sha256,
            target_mutated: true,
          });
        }
      }

      writeSessionState(targetReal, RECOVERY_SESSION_REL, {
        schema_version: 1,
        capsule_id: session.capsule_id ?? PLUGIN_CACHE_CAPSULE_ID,
        pack: "plugin_cache",
        repair_family: "plugin_cache",
        original_sha256: originalSha,
        original_manifest_sha256: session.original_manifest_sha256 ?? null,
        backup_rel,
        target_path_alias:
          typeof session.target_path_alias === "string" &&
          session.target_path_alias.length > 0
            ? session.target_path_alias
            : "PLUGIN_CACHE_ENTRY",
        target_rel: artifact,
        authorization_binding: session.authorization_binding ?? null,
        nonce: session.nonce ?? null,
        status: "explicit_rollback",
        consumed: true,
        rolled_back_at: new Date().toISOString(),
      });

      const live = openTargetFile(targetReal, artifact, MAX_ARTIFACT_BYTES);
      if (live.sha256 !== originalSha) {
        return fail("rollback", "ROLLBACK_MISMATCH", "Rollback hash mismatch.", {
          evidence,
          resulting_sha256: live.sha256,
          target_mutated: true,
        });
      }

      return baseResult({
        ok: true,
        operation: "rollback",
        user_resolution: userReceipt(
          "MITIGATED_VERIFIED_BY_ROLLBACK",
          "Explicit rollback restored exact original cache+manifest bytes. Mitigation only; not root-cause resolution.",
        ),
        upstream_contribution: upstreamReceipt(
          "NONE",
          "No upstream contribution; local rollback only.",
        ),
        evidence,
        target_mutated: true,
        repair_applied: false,
        resulting_sha256: live.sha256,
        backup: {
          backup_rel,
          original_sha256: originalSha,
          verified: true,
          receipt_id: receiptId("backup"),
        },
      });
    } catch (e) {
      if (e instanceof PathSafetyError) {
        return fail("rollback", e.code, e.message, { evidence });
      }
      return fail("rollback", "ROLLBACK_ERROR", "Rollback failed.", { evidence });
    }
  }

  const alias =
    typeof session.target_path_alias === "string" &&
    session.target_path_alias.length > 0
      ? session.target_path_alias
      : PROTECTED_PROCESS_OP.target_path_alias;
  const target_rel =
    typeof session.target_rel === "string" && session.target_rel.length > 0
      ? session.target_rel
      : artifactRel();
  // Always restore from registered backup path — never trust session.backup_rel.
  const backup_rel = registeredBackupRel(alias);

  const evidence: MeasuredEvidence[] = [];
  try {
    const restored = restoreFromBackup(
      targetReal,
      target_rel,
      backup_rel,
      originalSha,
      MAX_ARTIFACT_BYTES,
    );
    evidence.push({
      kind: "explicit_rollback",
      detail: `Restored sha256=${restored.resulting_sha256}`,
      measured: true,
    });
    writeSessionState(targetReal, RECOVERY_SESSION_REL, {
      schema_version: 1,
      capsule_id: session.capsule_id ?? CAPSULE_ID,
      original_sha256: originalSha,
      backup_rel,
      target_path_alias: alias,
      target_rel,
      repair_family: session.repair_family ?? "protected_process",
      authorization_binding: session.authorization_binding ?? null,
      nonce: session.nonce ?? null,
      status: "explicit_rollback",
      consumed: true,
      rolled_back_at: new Date().toISOString(),
    });

    // Confirm exact original bytes.
    const live = openTargetFile(targetReal, target_rel, MAX_ARTIFACT_BYTES);
    if (live.sha256 !== originalSha) {
      return fail("rollback", "ROLLBACK_MISMATCH", "Rollback hash mismatch.", {
        evidence,
        resulting_sha256: live.sha256,
        target_mutated: true,
      });
    }

    return baseResult({
      ok: true,
      operation: "rollback",
      user_resolution: userReceipt(
        "MITIGATED_VERIFIED_BY_ROLLBACK",
        "Explicit rollback restored exact original bytes. Mitigation only; not root-cause resolution.",
      ),
      upstream_contribution: upstreamReceipt(
        "NONE",
        "No upstream contribution; local rollback only.",
      ),
      evidence,
      target_mutated: true,
      repair_applied: false,
      resulting_sha256: live.sha256,
      backup: {
        backup_rel,
        original_sha256: originalSha,
        verified: true,
        receipt_id: receiptId("backup"),
      },
    });
  } catch (e) {
    if (e instanceof PathSafetyError) {
      return fail("rollback", e.code, e.message, { evidence });
    }
    return fail("rollback", "ROLLBACK_ERROR", "Rollback failed.", { evidence });
  }
}

/** Test helper: stable digest for empty objects (unused in prod paths). */
export function emptyDigest(): string {
  return digestObject({});
}

export function measureArtifactSha(targetPath: string): string | null {
  try {
    const { targetReal } = resolveTargetDirectory(targetPath);
    const file = openTargetFile(targetReal, artifactRel(), MAX_ARTIFACT_BYTES);
    return file.sha256;
  } catch {
    return null;
  }
}

export { sha256Buffer };
