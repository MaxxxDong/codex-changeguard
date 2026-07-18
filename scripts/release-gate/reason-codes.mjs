/**
 * Stable Ticket 16 release-gate reason codes (SSOT).
 * Exact strings are part of the product contract; do not rename lightly.
 */

export const REASON = Object.freeze({
  GATE_TYPECHECK: "GATE_TYPECHECK",
  GATE_TEST: "GATE_TEST",
  GATE_BOUNDARY: "GATE_BOUNDARY",
  GATE_BOUNDARY_SELFTEST: "GATE_BOUNDARY_SELFTEST",
  GATE_SCHEMA: "GATE_SCHEMA",
  GATE_FIXTURE_ACCOUNTING: "GATE_FIXTURE_ACCOUNTING",
  GATE_PRIVACY: "GATE_PRIVACY",
  GATE_INJECTION: "GATE_INJECTION",
  GATE_WRITE_PATH: "GATE_WRITE_PATH",
  GATE_PACKAGE: "GATE_PACKAGE",
  GATE_PACKAGE_SMOKE: "GATE_PACKAGE_SMOKE",
  GATE_PACKAGE_AUDIT: "GATE_PACKAGE_AUDIT",
  GATE_CLI_HASH: "GATE_CLI_HASH",
  GATE_DIFF_CHECK: "GATE_DIFF_CHECK",
  GATE_UNKNOWN_STEP: "GATE_UNKNOWN_STEP",
});

/** Ordered mandatory steps for verify:release. */
export const MANDATORY_STEPS = Object.freeze([
  { id: "typecheck", reason: REASON.GATE_TYPECHECK, kind: "npm", command: ["npm", "run", "typecheck"] },
  { id: "test", reason: REASON.GATE_TEST, kind: "npm", command: ["npm", "test"] },
  { id: "boundary", reason: REASON.GATE_BOUNDARY, kind: "npm", command: ["npm", "run", "check:boundary"] },
  {
    id: "boundary_selftest",
    reason: REASON.GATE_BOUNDARY_SELFTEST,
    kind: "node",
    command: ["node", "scripts/check-production-boundary.mjs", "--self-test"],
  },
  { id: "schema", reason: REASON.GATE_SCHEMA, kind: "pure", pure: "schema" },
  { id: "fixture_accounting", reason: REASON.GATE_FIXTURE_ACCOUNTING, kind: "pure", pure: "fixture_accounting" },
  { id: "privacy", reason: REASON.GATE_PRIVACY, kind: "pure", pure: "privacy" },
  { id: "injection", reason: REASON.GATE_INJECTION, kind: "pure", pure: "injection" },
  { id: "write_path", reason: REASON.GATE_WRITE_PATH, kind: "pure", pure: "write_path" },
  { id: "package", reason: REASON.GATE_PACKAGE, kind: "npm", command: ["npm", "run", "package"] },
  { id: "package_smoke", reason: REASON.GATE_PACKAGE_SMOKE, kind: "npm", command: ["npm", "run", "package:smoke"] },
  { id: "package_audit", reason: REASON.GATE_PACKAGE_AUDIT, kind: "pure", pure: "package_audit" },
  {
    id: "cli_hash",
    reason: REASON.GATE_CLI_HASH,
    kind: "node",
    command: ["node", "scripts/cli-hash-proof.mjs"],
  },
  { id: "diff_check", reason: REASON.GATE_DIFF_CHECK, kind: "shell", command: ["git", "diff", "--check"] },
]);

export function isKnownReason(code) {
  return Object.values(REASON).includes(code);
}
