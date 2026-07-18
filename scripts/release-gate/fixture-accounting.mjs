/**
 * Declarative fixture accounting for Ticket 16 release gate.
 *
 * Binds real public-seam tests/fixtures. Does not re-run repair engines.
 * Mechanical enforcement: each row's test file + fixture path must exist;
 * minimum bucket counts must hold.
 *
 * Thresholds (spec Testing Decisions):
 *   >=2 RESOLVED_VERIFIED (verified repair)
 *   >=2 MITIGATED_* / UPSTREAM_BLOCKED
 *   >=3 similar-symptom wrong-repair refusals
 */

import fs from "node:fs";
import path from "node:path";

/** @typedef {"resolved_verified" | "mitigation_or_upstream_blocked" | "wrong_repair_refusal"} AccountingBucket */

/**
 * Canonical accounting rows. Each row is a public-seam evidence pointer.
 * `test_file` + `test_name_substr` must exist; `fixture` path must exist when set.
 */
export const FIXTURE_ACCOUNTING_ROWS = Object.freeze([
  // --- RESOLVED_VERIFIED (verified repair) ---
  {
    id: "t02-protected-process-repair",
    bucket: "resolved_verified",
    expected_status: "RESOLVED_VERIFIED",
    fixture: "fixtures/protected-process",
    public_seam: "repair-preview → repair-apply",
    test_file: "tests/ticket02-repair-harness.test.ts",
    test_name_substr: "successful repair preview → apply → RESOLVED_VERIFIED",
  },
  {
    id: "t07-config-set-repair",
    bucket: "resolved_verified",
    expected_status: "RESOLVED_VERIFIED",
    fixture: "fixtures/config-wrong-type",
    public_seam: "repair-preview → repair-apply (config_set)",
    test_file: "tests/ticket07-config-startup.test.ts",
    test_name_substr: "valid fix path config_set → RESOLVED_VERIFIED",
  },
  {
    id: "t08-plugin-cache-corruption-repair",
    bucket: "resolved_verified",
    expected_status: "RESOLVED_VERIFIED",
    fixture: "fixtures/plugin-cache",
    public_seam: "repair-preview → repair-apply (plugin-cache)",
    test_file: "tests/ticket08-plugin-cache-harness.test.ts",
    test_name_substr: "successful repair preview → apply → RESOLVED_VERIFIED",
  },
  // --- Mitigation / UPSTREAM_BLOCKED ---
  {
    id: "t06-surface-rollback-mitigation",
    bucket: "mitigation_or_upstream_blocked",
    expected_status: "MITIGATED_VERIFIED_BY_ROLLBACK",
    fixture: "fixtures/lifecycle",
    public_seam: "lifecycle rollback_surface",
    test_file: "tests/ticket06-lifecycle.test.ts",
    test_name_substr: "exact-instance surface rollback → MITIGATED_VERIFIED_BY_ROLLBACK",
  },
  {
    id: "t09-crash-family-upstream-blocked",
    bucket: "mitigation_or_upstream_blocked",
    expected_status: "UPSTREAM_BLOCKED",
    fixture: "fixtures/crash-family/access-violation-crbrowser",
    public_seam: "diagnose (crash-family)",
    test_file: "tests/ticket09-crash-family.test.ts",
    test_name_substr: "0xC0000005",
  },
  {
    id: "t02-explicit-rollback-mitigation",
    bucket: "mitigation_or_upstream_blocked",
    expected_status: "MITIGATED_VERIFIED_BY_ROLLBACK",
    fixture: "fixtures/protected-process",
    public_seam: "rollback after apply",
    test_file: "tests/ticket02-repair-harness.test.ts",
    test_name_substr: "explicit rollback restores exact original",
  },
  // --- Similar-symptom wrong-repair refusals ---
  {
    id: "t02-negative-control-refuse",
    bucket: "wrong_repair_refusal",
    expected_status: "refused",
    fixture: "fixtures/negative-control",
    public_seam: "repair-preview refuse",
    test_file: "tests/ticket02-repair-harness.test.ts",
    test_name_substr: "negative control refuses same repair",
  },
  {
    id: "t07-wrong-candidate-refuse",
    bucket: "wrong_repair_refusal",
    expected_status: "refused",
    fixture: "fixtures/negative-control",
    public_seam: "repair-preview refuse (wrong candidate)",
    test_file: "tests/ticket07-config-startup.test.ts",
    test_name_substr: "wrong candidate (negative control) refuses config repair",
  },
  {
    id: "t09-symptom-repair-refuse",
    bucket: "wrong_repair_refusal",
    expected_status: "refused",
    fixture: "fixtures/crash-family/access-violation-crbrowser",
    public_seam: "repair-preview refuse (no safe applicability)",
    test_file: "tests/ticket09-crash-family.test.ts",
    test_name_substr: "repair-preview",
  },
  {
    id: "t08-plugin-cache-negative-refuse",
    bucket: "wrong_repair_refusal",
    expected_status: "refused",
    fixture: "fixtures/plugin-cache/negative-control",
    public_seam: "repair-preview refuse (dependency-install-like)",
    test_file: "tests/ticket08-plugin-cache-harness.test.ts",
    test_name_substr: "negative control refuses repair preview",
  },
]);

export const FIXTURE_THRESHOLDS = Object.freeze({
  resolved_verified: 2,
  mitigation_or_upstream_blocked: 2,
  wrong_repair_refusal: 3,
});

/**
 * @param {string} repoRoot
 * @param {{ rows?: readonly typeof FIXTURE_ACCOUNTING_ROWS, thresholds?: typeof FIXTURE_THRESHOLDS }} [opts]
 */
export function checkFixtureAccounting(repoRoot, opts = {}) {
  const rows = opts.rows ?? FIXTURE_ACCOUNTING_ROWS;
  const thresholds = opts.thresholds ?? FIXTURE_THRESHOLDS;
  const counts = {
    resolved_verified: 0,
    mitigation_or_upstream_blocked: 0,
    wrong_repair_refusal: 0,
  };
  /** @type {string[]} */
  const errors = [];

  for (const row of rows) {
    if (!counts[row.bucket] && counts[row.bucket] !== 0) {
      errors.push(`unknown_bucket:${row.id}`);
      continue;
    }
    const testAbs = path.join(repoRoot, row.test_file);
    if (!fs.existsSync(testAbs) || !fs.statSync(testAbs).isFile()) {
      errors.push(`missing_test_file:${row.id}`);
      continue;
    }
    const testText = fs.readFileSync(testAbs, "utf8");
    if (!testText.includes(row.test_name_substr)) {
      errors.push(`missing_test_name:${row.id}`);
      continue;
    }
    if (row.fixture) {
      const fixAbs = path.join(repoRoot, row.fixture);
      if (!fs.existsSync(fixAbs)) {
        errors.push(`missing_fixture:${row.id}`);
        continue;
      }
    }
    counts[row.bucket] += 1;
  }

  for (const [bucket, min] of Object.entries(thresholds)) {
    if ((counts[bucket] ?? 0) < min) {
      errors.push(`undercount:${bucket}:${counts[bucket] ?? 0}<${min}`);
    }
  }

  if (errors.length > 0) {
    return {
      ok: false,
      reason_code: "GATE_FIXTURE_ACCOUNTING",
      counts,
      errors,
      // Never include free-form secret data
      detail: "fixture_accounting_failed",
    };
  }
  return {
    ok: true,
    reason_code: null,
    counts,
    errors: [],
    detail: "fixture_accounting_ok",
  };
}
