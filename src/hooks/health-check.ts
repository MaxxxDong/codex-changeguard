/**
 * Bounded read-only health check for SessionStart after fingerprint change.
 * Must complete under the configured budget (default 10s). No network, no mutation.
 *
 * `ok` stays the all-checks-pass boolean for backward compatibility.
 * `classification` separates version-evidence gaps from identity/budget faults
 * so operators do not misread missing metadata as a Codex host failure.
 */
import type {
  HealthCheckResult,
  HealthClassification,
  HealthClassificationReason,
  InstanceIdentity,
} from "../instances/types.js";

function classifyHealth(
  checks: Array<{ id: string; ok: boolean }>,
  withinBudget: boolean,
): {
  classification: HealthClassification;
  classification_reason: HealthClassificationReason;
} {
  const byId = new Map(checks.map((c) => [c.id, c.ok]));
  const identityOk = byId.get("identity_uniqueness") !== false;
  const enumOk = byId.get("instance_enumeration") !== false;
  const versionOk = byId.get("version_evidence_coverage") !== false;
  const budgetOk = withinBudget && byId.get("budget") !== false;

  if (!identityOk) {
    return {
      classification: "identity_integrity_failed",
      classification_reason: "duplicate_instance_ids",
    };
  }
  if (!enumOk) {
    return {
      classification: "check_failed",
      classification_reason: "instance_enumeration_failed",
    };
  }
  if (!budgetOk) {
    return {
      classification: "budget_exceeded",
      classification_reason: "health_check_budget_exceeded",
    };
  }
  if (!versionOk) {
    // Version metadata missing is incomplete evidence — not a host fault.
    return {
      classification: "evidence_incomplete",
      classification_reason: "version_evidence_missing",
    };
  }
  const allOk = checks.every((c) => c.ok) && withinBudget;
  if (allOk) {
    return {
      classification: "healthy",
      classification_reason: "all_checks_passed",
    };
  }
  return {
    classification: "check_failed",
    classification_reason: "one_or_more_checks_failed",
  };
}

export function runReadOnlyHealthCheck(
  instances: InstanceIdentity[],
  opts?: { budgetMs?: number; now?: () => number },
): HealthCheckResult {
  const budget = opts?.budgetMs ?? 10_000;
  const t0 = opts?.now?.() ?? performance.now();
  const checks: HealthCheckResult["checks"] = [];

  // Structural inventory integrity (read-only, in-memory).
  const sources = new Set(instances.map((i) => i.install_source));
  checks.push({
    id: "instance_enumeration",
    ok: instances.length >= 0,
    detail: `observed_instances=${instances.length};sources=${[...sources].sort().join(",")}`,
  });

  const missingVersion = instances.filter((i) => !i.version).length;
  checks.push({
    id: "version_evidence_coverage",
    ok: missingVersion === 0 || instances.length === 0,
    detail:
      missingVersion === 0
        ? "all_instances_have_version_metadata"
        : `missing_version_count=${missingVersion}`,
  });

  // Distinct identities: path hashes must not collapse multi-source installs incorrectly.
  // Same path_hash with different install_source is allowed (still distinct instance_id).
  const ids = new Set(instances.map((i) => i.instance_id));
  checks.push({
    id: "identity_uniqueness",
    ok: ids.size === instances.length,
    detail:
      ids.size === instances.length
        ? "instance_ids_unique"
        : "duplicate_instance_ids",
  });

  const t1 = opts?.now?.() ?? performance.now();
  const duration_ms = Math.max(0, t1 - t0);
  const withinBudget = duration_ms <= budget;
  checks.push({
    id: "budget",
    ok: withinBudget,
    detail: `duration_ms=${duration_ms.toFixed(3)};budget_ms=${budget}`,
  });

  const { classification, classification_reason } = classifyHealth(
    checks,
    withinBudget,
  );

  return {
    ok: checks.every((c) => c.ok) && withinBudget,
    duration_ms,
    checks,
    bounded: true,
    read_only: true,
    classification,
    classification_reason,
  };
}
