/**
 * Bounded read-only health check for SessionStart after fingerprint change.
 * Must complete under the configured budget (default 10s). No network, no mutation.
 */
import type { HealthCheckResult, InstanceIdentity } from "../instances/types.js";

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

  return {
    ok: checks.every((c) => c.ok) && withinBudget,
    duration_ms,
    checks,
    bounded: true,
    read_only: true,
  };
}
