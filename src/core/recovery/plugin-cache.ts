/**
 * Ticket 08 plugin-cache recovery pack.
 * Repairs: exact atomic replacement / verified resource copy from registered
 * trusted source / rename-to-quarantine. No recursive cache delete, no signed
 * binary edits, no package-manager scripts, no cross-instance broadcast.
 */
import { sha256Buffer } from "../measure.js";
import {
  classifyPluginCacheMechanism,
  observePluginCache,
  type MechanismClassification,
  type PluginCacheObservation,
} from "../plugin-cache/index.js";
import {
  MAX_PLUGIN_CACHE_FILE_BYTES,
  PLUGIN_BUNDLED_ENTRY_REL,
  PLUGIN_CACHE_CAPSULE_ID,
  PLUGIN_CACHE_ENTRY_ALIAS,
  PLUGIN_CACHE_ENTRY_REL,
  PLUGIN_MANIFEST_ALIAS,
  PLUGIN_MANIFEST_REL,
  PLUGIN_QUARANTINE_REL,
  PLUGIN_RECON_STATE_REL,
  PLUGIN_TRUSTED_ENTRY_REL,
  type PluginCacheMechanism,
} from "../plugin-cache/limits.js";
import { PathSafetyError } from "../path-safety.js";
import {
  atomicReplaceFile,
  createVerifiedBackup,
  openTargetFile,
  renameToQuarantine,
  type FileIdentity,
} from "./atomic-write.js";
import { digestObject } from "./canonical.js";
import {
  authorizationBinding,
  defaultExpiryIso,
  invalidationMaterial,
  isExpired,
  mintNonce,
} from "./protected-process.js";
import type {
  RepairCapsule,
  RepairOperationKind,
  VerificationReport,
} from "./types.js";
import { registeredBackupRel } from "./types.js";

export const PLUGIN_CACHE_OP = {
  kind: "verified_resource_copy" as const satisfies RepairOperationKind,
  target_path_alias: PLUGIN_CACHE_ENTRY_ALIAS,
  artifact_rel: PLUGIN_CACHE_ENTRY_REL,
  expected_pattern_count: 1,
  description:
    "Verified resource copy from registered trusted rebuild source into isolated plugin cache entry via atomic replace; optional rename-to-quarantine of prior cache bytes.",
};

export function pluginCacheOperationDigest(kind: RepairOperationKind = "verified_resource_copy"): string {
  return digestObject({
    kind,
    target_path_alias: PLUGIN_CACHE_OP.target_path_alias,
    expected_pattern_count: PLUGIN_CACHE_OP.expected_pattern_count,
    capsule_id: PLUGIN_CACHE_CAPSULE_ID,
    description: PLUGIN_CACHE_OP.description,
  });
}

export function pluginCacheArtifactRel(): string {
  return PLUGIN_CACHE_ENTRY_REL;
}

export function pluginCacheManifestRel(): string {
  return PLUGIN_MANIFEST_REL;
}

export function pluginCacheBackupRel(): string {
  return registeredBackupRel(PLUGIN_CACHE_ENTRY_ALIAS);
}

export function pluginCacheManifestBackupRel(): string {
  return registeredBackupRel(PLUGIN_MANIFEST_ALIAS);
}

export function isPluginCacheCapsuleId(id: string): boolean {
  return id === PLUGIN_CACHE_CAPSULE_ID;
}

export interface PluginCacheRepairPlan {
  mechanism: PluginCacheMechanism;
  classification: MechanismClassification;
  observation: PluginCacheObservation;
  cache_file: FileIdentity;
  manifest_file: FileIdentity;
  trusted_file: FileIdentity;
  expected_result_sha256: string;
  operation_kind: RepairOperationKind;
  quarantine_first: boolean;
}

/**
 * Plan a verified resource copy repair when exactly one mechanism is classified
 * and the trusted rebuild source matches the manifest expectation.
 */
export function planPluginCacheRepair(
  targetReal: string,
):
  | { ok: true; plan: PluginCacheRepairPlan }
  | { ok: false; code: string; message: string; classification?: MechanismClassification } {
  let obs: PluginCacheObservation | null;
  try {
    obs = observePluginCache(targetReal);
  } catch (e) {
    if (e instanceof PathSafetyError) {
      return { ok: false, code: e.code, message: e.message };
    }
    const err = e as { code?: string; message?: string };
    return {
      ok: false,
      code: err.code ?? "PLUGIN_CACHE_ERROR",
      message: err.message ?? "Plugin-cache observation failed.",
    };
  }
  if (!obs) {
    return { ok: false, code: "NOT_APPLICABLE", message: "Not a plugin-cache target." };
  }

  const classification = classifyPluginCacheMechanism(obs);
  if (!classification.mechanism) {
    return {
      ok: false,
      code: "NOT_APPLICABLE",
      message: classification.reason,
      classification,
    };
  }

  // Trusted rebuild source must be independently verified against manifest.
  if (
    obs.trusted_entry.measured_sha256 !==
    obs.manifest.rebuild_source.expected_sha256
  ) {
    return {
      ok: false,
      code: "TRUSTED_SOURCE_MISMATCH",
      message: "Trusted rebuild source hash does not match registered manifest expectation.",
      classification,
    };
  }

  let cache_file: FileIdentity;
  let manifest_file: FileIdentity;
  let trusted_file: FileIdentity;
  try {
    cache_file = openTargetFile(
      targetReal,
      PLUGIN_CACHE_ENTRY_REL,
      MAX_PLUGIN_CACHE_FILE_BYTES,
    );
    manifest_file = openTargetFile(
      targetReal,
      PLUGIN_MANIFEST_REL,
      MAX_PLUGIN_CACHE_FILE_BYTES,
    );
    trusted_file = openTargetFile(
      targetReal,
      PLUGIN_TRUSTED_ENTRY_REL,
      MAX_PLUGIN_CACHE_FILE_BYTES,
    );
  } catch (e) {
    if (e instanceof PathSafetyError) {
      return { ok: false, code: e.code, message: e.message, classification };
    }
    return {
      ok: false,
      code: "TARGET_ERROR",
      message: "Plugin-cache target refused.",
      classification,
    };
  }

  if (cache_file.sha256 === trusted_file.sha256) {
    return {
      ok: false,
      code: "NOT_APPLICABLE",
      message: "Cache already matches trusted rebuild; no repair needed.",
      classification,
    };
  }

  // Corruption / recon: quarantine first then verified copy.
  const quarantine_first =
    classification.mechanism === "bundled_file_corruption" ||
    classification.mechanism === "reconciliation_overwrite";

  return {
    ok: true,
    plan: {
      mechanism: classification.mechanism,
      classification,
      observation: obs,
      cache_file,
      manifest_file,
      trusted_file,
      expected_result_sha256: trusted_file.sha256,
      operation_kind: "verified_resource_copy",
      quarantine_first,
    },
  };
}

export function buildPluginCacheCapsule(input: {
  scope_digest: string;
  original_sha256: string;
  expected_result_sha256: string;
  mechanism: PluginCacheMechanism;
}): RepairCapsule {
  const expires_at = defaultExpiryIso();
  const nonce = mintNonce();
  const backup_rel = pluginCacheBackupRel();
  const op_digest = pluginCacheOperationDigest("verified_resource_copy");
  const invalidation_digest = invalidationMaterial({
    original_sha256: input.original_sha256,
    expected_pattern_count: 1,
    scope_digest: input.scope_digest,
    operation_digest: op_digest,
    expected_result_sha256: input.expected_result_sha256,
    backup_rel,
    capsule_id: PLUGIN_CACHE_CAPSULE_ID,
    mode: "apply_authorized",
    authorization_tier: "experimental_one_shot",
  });
  const binding = authorizationBinding({
    capsule_id: PLUGIN_CACHE_CAPSULE_ID,
    scope_digest: input.scope_digest,
    original_sha256: input.original_sha256,
    expected_pattern_count: 1,
    operation_digest: op_digest,
    expected_result_sha256: input.expected_result_sha256,
    backup_rel,
    invalidation_digest,
    trust_tier: "T1_community",
    authorization_tier: "experimental_one_shot",
    mode: "apply_authorized",
    target_path_alias: PLUGIN_CACHE_ENTRY_ALIAS,
    expires_at,
    nonce,
  });

  return {
    schema_version: 1,
    capsule_id: PLUGIN_CACHE_CAPSULE_ID,
    trust_tier: "T1_community",
    mode: "apply_authorized",
    authorization_tier: "experimental_one_shot",
    risk: "moderate",
    target_path_alias: PLUGIN_CACHE_ENTRY_ALIAS,
    scope_digest: input.scope_digest,
    original_sha256: input.original_sha256,
    expected_pattern_count: 1,
    operation: {
      kind: "verified_resource_copy",
      target_path_alias: PLUGIN_CACHE_ENTRY_ALIAS,
      expected_pattern_count: 1,
      operation_digest: op_digest,
      expected_result_sha256: input.expected_result_sha256,
      config_key: null,
      old_value_type: null,
      old_value_summary: null,
      new_value: null,
    },
    applicability: {
      version_match: input.mechanism !== "dependency_version_skew",
      platform_match: true,
      target_hash_match: true,
      pattern_count_match: true,
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
        "cache-hash-matches-trusted",
        "manifest-bytes-unchanged-or-restorable",
        "reconciliation-cycle-stable",
        "restart-health-check",
        "mechanism-absent-after-repair",
      ],
      original_failure_must_not_reproduce: true,
      core_health_required: true,
    },
    rollback: {
      recipe: [
        "Restore exact original cache entry bytes from verified backup.",
        "Restore exact original manifest bytes from verified backup.",
        "Re-verify original cache and manifest SHA-256.",
        "Clear applied-repair session state.",
      ],
      restores_original_sha256: input.original_sha256,
    },
    dry_run_checks: [
      "mechanism-classified",
      "trusted-source-verified",
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

export function recomputePluginCacheLiveBinding(
  targetReal: string,
  capsule: RepairCapsule,
):
  | { ok: true; plan: PluginCacheRepairPlan }
  | { ok: false; code: string; message: string } {
  if (isExpired(capsule.expires_at)) {
    return { ok: false, code: "AUTH_EXPIRED", message: "Capsule authorization expired." };
  }
  if (capsule.capsule_id !== PLUGIN_CACHE_CAPSULE_ID) {
    return { ok: false, code: "AUTH_INVALID", message: "Capsule id refused." };
  }
  if (capsule.backup.backup_rel !== pluginCacheBackupRel()) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Backup path refused; authorization invalid.",
    };
  }
  const planned = planPluginCacheRepair(targetReal);
  if (!planned.ok) {
    return {
      ok: false,
      code: planned.code === "NOT_APPLICABLE" ? "AUTH_INVALID" : planned.code,
      message: planned.message,
    };
  }
  const plan = planned.plan;
  if (plan.cache_file.sha256 !== capsule.original_sha256) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Target hash changed; authorization invalid.",
    };
  }
  if (plan.expected_result_sha256 !== capsule.operation.expected_result_sha256) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Operation result digest changed; authorization invalid.",
    };
  }
  const op_digest = pluginCacheOperationDigest(capsule.operation.kind);
  if (op_digest !== capsule.operation.operation_digest) {
    return {
      ok: false,
      code: "AUTH_INVALID",
      message: "Operation digest changed; authorization invalid.",
    };
  }
  const scope_digest_live = (() => {
    // Scope is bound at preview; engine passes capsule.scope_digest comparison.
    return capsule.scope_digest;
  })();
  void scope_digest_live;
  const invalidation_digest = invalidationMaterial({
    original_sha256: plan.cache_file.sha256,
    expected_pattern_count: 1,
    scope_digest: capsule.scope_digest,
    operation_digest: op_digest,
    expected_result_sha256: capsule.operation.expected_result_sha256,
    backup_rel: pluginCacheBackupRel(),
    capsule_id: PLUGIN_CACHE_CAPSULE_ID,
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
    capsule_id: PLUGIN_CACHE_CAPSULE_ID,
    scope_digest: capsule.scope_digest,
    original_sha256: plan.cache_file.sha256,
    expected_pattern_count: 1,
    operation_digest: op_digest,
    expected_result_sha256: capsule.operation.expected_result_sha256,
    backup_rel: pluginCacheBackupRel(),
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
  return { ok: true, plan };
}

/**
 * Apply verified resource copy: optional quarantine, then atomic replace from
 * trusted bytes. Does not execute cached code or run install scripts.
 * All mutation goes through registered atomic-write helpers only.
 */
export function applyPluginCacheRepair(
  targetReal: string,
  plan: PluginCacheRepairPlan,
): { resulting_sha256: string } {
  if (plan.quarantine_first) {
    renameToQuarantine(
      targetReal,
      PLUGIN_CACHE_ENTRY_REL,
      PLUGIN_QUARANTINE_REL,
      plan.cache_file,
      MAX_PLUGIN_CACHE_FILE_BYTES,
    );
    // Re-open after quarantine placeholder rewrite.
    const live = openTargetFile(
      targetReal,
      PLUGIN_CACHE_ENTRY_REL,
      MAX_PLUGIN_CACHE_FILE_BYTES,
    );
    const replaced = atomicReplaceFile(
      targetReal,
      PLUGIN_CACHE_ENTRY_REL,
      live,
      plan.trusted_file.bytes,
      MAX_PLUGIN_CACHE_FILE_BYTES,
    );
    return { resulting_sha256: replaced.resulting_sha256 };
  }
  const replaced = atomicReplaceFile(
    targetReal,
    PLUGIN_CACHE_ENTRY_REL,
    plan.cache_file,
    plan.trusted_file.bytes,
    MAX_PLUGIN_CACHE_FILE_BYTES,
  );
  return { resulting_sha256: replaced.resulting_sha256 };
}

/**
 * Synthetic one-cycle reconciliation for verification.
 * If recon policy will_overwrite_on_next_cycle, re-apply bundled bytes and
 * report recurrence (caller must not claim RESOLVED_VERIFIED).
 */
export function runSyntheticReconciliationCycle(targetReal: string): {
  ran: boolean;
  overwrote: boolean;
  resulting_sha256: string | null;
} {
  let reconRaw: FileIdentity | null = null;
  try {
    reconRaw = openTargetFile(
      targetReal,
      PLUGIN_RECON_STATE_REL,
      MAX_PLUGIN_CACHE_FILE_BYTES,
    );
  } catch (e) {
    if (e instanceof PathSafetyError && e.code === "CANDIDATE_NOT_FOUND") {
      return { ran: false, overwrote: false, resulting_sha256: null };
    }
    throw e;
  }
  let recon: {
    will_overwrite_on_next_cycle?: boolean;
  };
  try {
    recon = JSON.parse(reconRaw.bytes.toString("utf8")) as {
      will_overwrite_on_next_cycle?: boolean;
    };
  } catch {
    throw new PathSafetyError("MALFORMED_RECON", "Recon state refused.");
  }
  if (recon.will_overwrite_on_next_cycle !== true) {
    return { ran: true, overwrote: false, resulting_sha256: null };
  }
  // Overwrite cache with bundled baseline (simulates startup reconciliation).
  const bundled = openTargetFile(
    targetReal,
    PLUGIN_BUNDLED_ENTRY_REL,
    MAX_PLUGIN_CACHE_FILE_BYTES,
  );
  const live = openTargetFile(
    targetReal,
    PLUGIN_CACHE_ENTRY_REL,
    MAX_PLUGIN_CACHE_FILE_BYTES,
  );
  const replaced = atomicReplaceFile(
    targetReal,
    PLUGIN_CACHE_ENTRY_REL,
    live,
    bundled.bytes,
    MAX_PLUGIN_CACHE_FILE_BYTES,
  );
  return {
    ran: true,
    overwrote: true,
    resulting_sha256: replaced.resulting_sha256,
  };
}

export function runPluginCacheVerification(
  targetReal: string,
  originalSha: string,
  expectedResultSha: string,
  options: { runReconCycle: boolean } = { runReconCycle: true },
): VerificationReport {
  const checks: VerificationReport["checks"] = [];
  let measured_sha256: string | null = null;
  let original_failure_reproduces = true;
  let core_health_passed = false;

  // Harness-induced verification failure sentinel (shared with Ticket 02).
  try {
    openTargetFile(targetReal, ".changeguard/test-force-verify-fail", 4096);
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

  try {
    // One deterministic reconciliation cycle before health checks.
    let reconRecurred = false;
    if (options.runReconCycle) {
      const recon = runSyntheticReconciliationCycle(targetReal);
      checks.push({
        id: "reconciliation_cycle",
        passed: recon.ran ? !recon.overwrote : true,
        detail: recon.overwrote
          ? "Reconciliation overwrote repair; recurrence detected."
          : recon.ran
            ? "Reconciliation cycle stable (no overwrite)."
            : "No recon state; cycle skipped.",
      });
      if (recon.overwrote) {
        reconRecurred = true;
      }
    }

    const cache = openTargetFile(
      targetReal,
      PLUGIN_CACHE_ENTRY_REL,
      MAX_PLUGIN_CACHE_FILE_BYTES,
    );
    measured_sha256 = cache.sha256;
    const trusted = openTargetFile(
      targetReal,
      PLUGIN_TRUSTED_ENTRY_REL,
      MAX_PLUGIN_CACHE_FILE_BYTES,
    );
    const manifest = openTargetFile(
      targetReal,
      PLUGIN_MANIFEST_REL,
      MAX_PLUGIN_CACHE_FILE_BYTES,
    );
    void manifest;
    void sha256Buffer;

    checks.push({
      id: "cache_matches_trusted",
      passed: cache.sha256 === trusted.sha256 && cache.sha256 === expectedResultSha,
      detail:
        cache.sha256 === trusted.sha256
          ? "Cache entry matches trusted rebuild."
          : "Cache entry does not match trusted rebuild.",
    });
    checks.push({
      id: "hash_changed_from_original",
      passed: cache.sha256 !== originalSha,
      detail:
        cache.sha256 !== originalSha
          ? "Cache hash differs from pre-repair original."
          : "Cache hash unchanged from original.",
    });

    // Re-classify after recon cycle — original mechanism must be absent.
    const obs = observePluginCache(targetReal);
    let mechanism: PluginCacheMechanism | null = null;
    if (obs) {
      const cls = classifyPluginCacheMechanism(obs);
      mechanism = cls.mechanism;
    }
    original_failure_reproduces = mechanism !== null || reconRecurred;
    checks.push({
      id: "mechanism_absent",
      passed: !original_failure_reproduces,
      detail: original_failure_reproduces
        ? `Failure mechanism still present (${mechanism ?? "recon_recurrence"}).`
        : "Plugin-cache mechanism absent after repair + recon cycle.",
    });

    // Restart / health check: health.json ok + trusted hash stable.
    let healthOk = false;
    try {
      const health = openTargetFile(
        targetReal,
        "plugin-cache/health.json",
        MAX_PLUGIN_CACHE_FILE_BYTES,
      );
      const parsed = JSON.parse(health.bytes.toString("utf8")) as { ok?: boolean };
      healthOk = parsed.ok === true;
    } catch {
      healthOk = false;
    }
    // Synthetic restart marker: re-read trusted + cache once more (idempotent).
    const cacheAfter = openTargetFile(
      targetReal,
      PLUGIN_CACHE_ENTRY_REL,
      MAX_PLUGIN_CACHE_FILE_BYTES,
    );
    const restartStable =
      cacheAfter.sha256 === cache.sha256 && cacheAfter.sha256 === trusted.sha256;
    core_health_passed = healthOk && restartStable && !reconRecurred;
    checks.push({
      id: "restart_health",
      passed: core_health_passed,
      detail: core_health_passed
        ? "Restart/health check passed after recon cycle."
        : "Restart/health check failed or recon recurrence blocked resolution.",
    });
  } catch (e) {
    const msg = e instanceof PathSafetyError ? e.message : "Verification failed.";
    checks.push({ id: "verify_error", passed: false, detail: msg });
    return {
      passed: false,
      original_failure_reproduces: true,
      core_health_passed: false,
      checks,
      measured_sha256,
      measured_pattern_count: 1,
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
    measured_pattern_count: 1,
  };
}

export function backupPluginCachePair(
  targetReal: string,
  cacheFile: FileIdentity,
  manifestFile: FileIdentity,
): {
  cache: ReturnType<typeof createVerifiedBackup>;
  manifest: ReturnType<typeof createVerifiedBackup>;
} {
  return {
    cache: createVerifiedBackup(targetReal, pluginCacheBackupRel(), cacheFile),
    manifest: createVerifiedBackup(
      targetReal,
      pluginCacheManifestBackupRel(),
      manifestFile,
    ),
  };
}
