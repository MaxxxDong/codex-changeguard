/**
 * Ticket 02 recovery engine — preview, authorize-bound apply, verify, rollback.
 * Single registered repair path for the isolated protected-process fixture.
 * Diagnosis modules remain read-only; only this recovery surface mutates.
 *
 * Preview is completely read-only over the entire target tree (no .changeguard).
 * Apply receives a self-contained authorization token; backup paths come only
 * from registered constants — never from mutable token/session path fields.
 */
import { MAX_ARTIFACT_BYTES } from "../limits.js";
import { measureProtectedProcessAst, sha256Buffer } from "../measure.js";
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
import type {
  ApplyOptions,
  BackupReceipt,
  RepairCapsule,
  RepairResult,
  VerificationReport,
} from "./types.js";
import {
  INDUCE_VERIFY_FAIL_REL,
  registeredBackupRel,
  RECOVERY_SESSION_REL,
} from "./types.js";

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
      code === "AUTH_INVALID" ||
        code === "AUTH_EXPIRED" ||
        code === "AUTH_MALFORMED" ||
        code === "AUTH_REPLAY" ||
        code === "NOT_APPLICABLE"
        ? "REPAIR_REFUSED"
        : "INCONCLUSIVE",
      "Repair operation refused or could not complete safely.",
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

/**
 * Preview a Repair Capsule for the isolated protected-process target.
 * Completely read-only over the entire target tree — no .changeguard writes.
 * Returns a self-contained authorization token for cross-process apply.
 */
export function previewRepair(targetPath: string): RepairResult {
  let targetReal: string;
  try {
    ({ targetReal } = resolveTargetDirectory(targetPath));
  } catch (e) {
    if (e instanceof PathSafetyError) return fail("preview", e.code, e.message);
    return fail("preview", "TARGET_ERROR", "Target refused.");
  }

  const evidence: MeasuredEvidence[] = [];
  try {
    const scope_digest = scopeDigestForTarget(targetReal);
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

    // Mechanism gate: must be exactly one protected-process block.
    if (!ast.matched || ast.blockCount !== 1) {
      return fail(
        "preview",
        "NOT_APPLICABLE",
        "Protected-process repair is not applicable to this target.",
        {
          evidence,
          user_resolution: userReceipt(
            "REPAIR_REFUSED",
            "No matching protected-process mechanism; repair refused.",
          ),
        },
      );
    }

    const source = file.bytes.toString("utf8");
    // Pre-handshake signal: failure mechanism is the shim itself (before browser handshake).
    if (!preHandshakeFailureStillPresent(source)) {
      return fail("preview", "NOT_APPLICABLE", "Original failure mechanism not present.", {
        evidence,
      });
    }

    const plan = removeProtectedProcessBlock(source);
    if (!plan || plan.result_pattern_count !== 0) {
      return fail("preview", "REPAIR_PLAN", "Could not plan exact block removal.", {
        evidence,
      });
    }

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

    // No target writes — token is self-contained for cross-process apply.
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
  } catch (e) {
    if (e instanceof PathSafetyError) {
      // Missing artifact on negative control → not applicable.
      if (e.code === "CANDIDATE_NOT_FOUND") {
        return fail(
          "preview",
          "NOT_APPLICABLE",
          "Protected-process repair is not applicable to this target.",
          { evidence },
        );
      }
      return fail("preview", e.code, e.message, { evidence });
    }
    return fail("preview", "PREVIEW_ERROR", "Preview failed.", { evidence });
  }
}

function recomputeLiveBinding(
  targetReal: string,
  capsule: RepairCapsule,
):
  | {
      ok: true;
      file: ReturnType<typeof openTargetFile>;
      plan: NonNullable<ReturnType<typeof removeProtectedProcessBlock>>;
    }
  | { ok: false; code: string; message: string } {
  if (isExpired(capsule.expires_at)) {
    return { ok: false, code: "AUTH_EXPIRED", message: "Capsule authorization expired." };
  }
  const scope_digest = scopeDigestForTarget(targetReal);
  if (scope_digest !== capsule.scope_digest) {
    return { ok: false, code: "AUTH_INVALID", message: "Scope changed; authorization invalid." };
  }
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
  // expected_result_sha256 is required and bound — always revalidate.
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
  const invalidation_digest = invalidationMaterial({
    original_sha256: file.sha256,
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
    original_sha256: file.sha256,
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
  return { ok: true, file, plan };
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

  // Mechanism must still be present and match capsule preconditions.
  const live = recomputeLiveBinding(targetReal, capsule);
  if (!live.ok) {
    return fail("apply", live.code, live.message, { capsule });
  }

  const evidence: MeasuredEvidence[] = [
    {
      kind: "authorization",
      detail: "Authorization token verified against live preconditions.",
      measured: true,
    },
  ];
  let backupReceipt: BackupReceipt | null = null;
  // Always derive backup path from registered constants — never token/session path.
  const backup_rel = registeredBackupRel(PROTECTED_PROCESS_OP.target_path_alias);

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

    const newBytes = Buffer.from(live.plan.next, "utf8");
    const replaced = atomicReplaceFile(
      targetReal,
      artifactRel(),
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
        artifactRel(),
        backup_rel,
        capsule.original_sha256,
        MAX_ARTIFACT_BYTES,
      );
      const restored = openTargetFile(targetReal, artifactRel(), MAX_ARTIFACT_BYTES);
      writeSessionState(targetReal, RECOVERY_SESSION_REL, {
        schema_version: 1,
        capsule_id: capsule.capsule_id,
        original_sha256: capsule.original_sha256,
        status: "auto_rolled_back",
        backup_rel,
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
          artifactRel(),
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

  const verification = runVerification(targetReal, originalSha, expectedResult);
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
  // Always restore from registered backup path — never trust session.backup_rel.
  const backup_rel = registeredBackupRel(PROTECTED_PROCESS_OP.target_path_alias);
  if (!originalSha) {
    return fail("rollback", "NO_SESSION", "Session missing original hash.");
  }

  const evidence: MeasuredEvidence[] = [];
  try {
    const restored = restoreFromBackup(
      targetReal,
      artifactRel(),
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
      authorization_binding: session.authorization_binding ?? null,
      nonce: session.nonce ?? null,
      status: "explicit_rollback",
      consumed: true,
      rolled_back_at: new Date().toISOString(),
    });

    // Confirm exact original bytes.
    const live = openTargetFile(targetReal, artifactRel(), MAX_ARTIFACT_BYTES);
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
