/**
 * Injection / evidence / auth / DSL / platform / official-fix matrix bind (Ticket 16).
 *
 * Binds existing malicious-page, Issue/upstream, official prose, blocked-action,
 * follow-up authority, repair DSL, platform capability, and official-fix tests.
 * Each row's must_not / invariant is enforced via assertion evidence inside the
 * named test case (whole-file title presence is insufficient).
 */

import fs from "node:fs";
import path from "node:path";
import {
  bodyHasExecutableAssertCall,
  bodySatisfiesMustNot,
  expandSameFileHelpers,
  extractNamedTestCase,
} from "./test-case-bind.mjs";

/**
 * Each row binds a real test + fixture (when applicable) that already proves
 * the safety invariant. Gate fails if any bind drifts.
 */
export const INJECTION_MATRIX_ROWS = Object.freeze([
  {
    id: "page-prompt-injection",
    class: "malicious_page",
    invariant: "quarantine; no repair authorization; policy_mutations_blocked",
    test_file: "tests/ticket05-page-analysis.test.ts",
    test_name_substr: "prompt injection is quarantined and cannot alter policy or authorize repair",
    fixture: "fixtures/page-evidence/prompt-injection.json",
    must_not: ["raise_confidence", "authorize_repair"],
  },
  {
    id: "page-wrong-platform",
    class: "malicious_page",
    invariant: "wrong_platform hard gate; confidence none",
    test_file: "tests/ticket05-page-analysis.test.ts",
    test_name_substr: "wrong platform hard-gates high confidence and repair eligibility",
    fixture: "fixtures/page-evidence/wrong-platform.json",
    must_not: ["raise_confidence", "authorize_repair"],
  },
  {
    id: "upstream-prompt-injection",
    class: "issue_upstream",
    invariant: "PREVIEW_BLOCKED; injection quarantined",
    test_file: "tests/ticket10-upstream-preview.test.ts",
    test_name_substr: "prompt injection: PREVIEW_BLOCKED ok=false, no usable drafts, no raw free text",
    fixture: "fixtures/upstream/request-prompt-injection.json",
    must_not: ["authorize_repair", "mint_confirmation", "external_write"],
  },
  {
    id: "official-prose-quarantine",
    class: "official_prose",
    invariant: "malicious upstream injection quarantined; maintainer_status preserved",
    test_file: "tests/ticket04-evidence-impact.test.ts",
    test_name_substr: "malicious upstream prose is quarantined and never treated as instructions",
    fixture: null,
    must_not: ["add_change_to_local_edge", "execute_prose"],
  },
  {
    id: "model-edge-escalation",
    class: "change_to_local",
    invariant: "model edge-escalation payload refused; graph SHA unchanged",
    test_file: "tests/ticket04-evidence-impact.test.ts",
    test_name_substr: "model edge-escalation attempt is refused; graph unchanged",
    fixture: null,
    must_not: ["add_change_to_local_edge"],
  },
  {
    id: "blocked-action-capsule",
    class: "blocked_action",
    invariant: "blocked/injection capsules cannot become actions",
    test_file: "tests/ticket11-upstream-actions.test.ts",
    test_name_substr: "blocked/injection capsule cannot become actions",
    fixture: null,
    must_not: ["mint_confirmation", "external_write"],
  },
  {
    id: "followup-authority",
    class: "followup_authority",
    invariant: "subscribe/status lifecycle: no external write / no auto authority",
    test_file: "tests/ticket12-followup-core.test.ts",
    test_name_substr: "subscribe / status / unsubscribe / idempotent re-subscribe",
    fixture: null,
    // Subscription lifecycle proves no external write only — NOT live-witness supersession.
    must_not: ["external_write"],
  },
  {
    id: "followup-supersede-without-witness",
    class: "followup_authority",
    invariant: "direct supersede verified/measured without live witness cannot supersede",
    test_file: "tests/ticket12-followup-core.test.ts",
    test_name_substr:
      "Ticket12 adversarial: direct supersedeRecipe verified/measured without witness cannot supersede",
    fixture: null,
    must_not: ["supersede_without_witness"],
  },
  {
    id: "followup-snapshot-path-refuse",
    class: "followup_authority",
    invariant: "caller snapshot_path refused for candidate validation",
    test_file: "tests/ticket12-phaseb-p2.test.ts",
    test_name_substr: "public request JSON rejects snapshot_path",
    fixture: null,
    must_not: ["supersede_recipe_from_caller_path"],
  },
  {
    id: "repair-dsl-candidate-only",
    class: "repair_dsl",
    invariant: "page commands are candidate_only; Ticket 02 gates remain",
    test_file: "tests/ticket05-page-analysis.test.ts",
    test_name_substr: "DSL candidates never escalate to apply authorization",
    fixture: "fixtures/page-evidence/valid-protected-process.json",
    must_not: ["authorize_repair"],
  },
  {
    id: "crash-no-symptom-repair",
    class: "repair_dsl",
    invariant: "symptom-level patch authorization refused",
    test_file: "tests/ticket09-crash-family.test.ts",
    test_name_substr: "repair-preview on crash fixture never enters authorization (wrong fix blocked)",
    fixture: "fixtures/crash-family/access-violation-crbrowser",
    must_not: ["authorize_repair"],
  },
  {
    id: "platform-capability-closed",
    class: "platform_capability",
    invariant: "synthetic capability cannot Full; writes fail closed without proof",
    test_file: "tests/ticket15-platform-capability.test.ts",
    test_name_substr: "synthetic receipt cannot claim FULL",
    fixture: null,
    must_not: ["claim_full_without_receipt"],
  },
  {
    // Retargeted from positive SUPERSEDED path: that row proved success/binary
    // absence, not refusal without official bind. Negative control binds fixed
    // error_code for supersede_without_official_bind.
    id: "official-fix-supersession-bind",
    class: "official_fix",
    invariant: "self-attestation / missing official bind refuses supersession",
    test_file: "tests/ticket12-followup-core.test.ts",
    test_name_substr:
      "Ticket12 adversarial: all-true self-consistent legacy measurement JSON never unlocks",
    fixture: null,
    must_not: ["supersede_without_official_bind"],
  },
  {
    // binary_install kept separately on the positive path (binary_* === false).
    id: "official-fix-no-binary-install",
    class: "official_fix",
    invariant: "official-fix path never downloads or installs binaries",
    test_file: "tests/ticket12-followup-core.test.ts",
    test_name_substr: "live registered positive path → SUPERSEDED_BY_UPSTREAM_FIX",
    fixture: null,
    must_not: ["binary_install"],
  },
  {
    id: "offline-forge-confirmation",
    class: "blocked_action",
    invariant: "offline-forged confirmation refused",
    test_file: "tests/ticket11-upstream-actions.test.ts",
    test_name_substr: "offline forged token without preview registration is refused",
    fixture: null,
    must_not: ["mint_confirmation"],
  },
]);

/**
 * Bind one injection row to named-test assertion evidence for each must_not.
 * @param {string} repoRoot
 * @param {(typeof INJECTION_MATRIX_ROWS)[number]} row
 * @returns {{ ok: true } | { ok: false, errors: string[] }}
 */
export function bindInjectionMatrixRow(repoRoot, row) {
  /** @type {string[]} */
  const errors = [];
  const testAbs = path.join(repoRoot, row.test_file);
  if (!fs.existsSync(testAbs)) {
    return { ok: false, errors: [`missing_test:${row.id}`] };
  }
  let text;
  try {
    text = fs.readFileSync(testAbs, "utf8");
  } catch {
    return { ok: false, errors: [`unreadable_test:${row.id}`] };
  }
  const extracted = extractNamedTestCase(text, row.test_name_substr);
  if (!extracted) {
    return { ok: false, errors: [`missing_or_ambiguous_test_case:${row.id}`] };
  }
  const expanded = expandSameFileHelpers(extracted.body, text);
  if (row.fixture) {
    const fAbs = path.join(repoRoot, row.fixture);
    if (!fs.existsSync(fAbs)) {
      errors.push(`missing_fixture:${row.id}`);
    }
  }
  for (const token of row.must_not ?? []) {
    if (!bodySatisfiesMustNot(expanded, token)) {
      errors.push(`missing_must_not_assert:${row.id}:${token}`);
    }
  }
  // Invariant string is documentary; require at least one real assert call when
  // no must_not (comments / string-spoofed "assert." text never count).
  if ((!row.must_not || row.must_not.length === 0) && !bodyHasExecutableAssertCall(expanded)) {
    errors.push(`missing_invariant_assert:${row.id}`);
  }
  if (errors.length > 0) return { ok: false, errors };
  return { ok: true };
}

/**
 * @param {string} repoRoot
 * @param {{ rows?: readonly typeof INJECTION_MATRIX_ROWS }} [opts]
 */
export function checkInjectionMatrix(repoRoot, opts = {}) {
  const rows = opts.rows ?? INJECTION_MATRIX_ROWS;
  /** @type {string[]} */
  const errors = [];
  const classes = new Set();

  for (const row of rows) {
    classes.add(row.class);
    const bind = bindInjectionMatrixRow(repoRoot, row);
    if (!bind.ok) {
      errors.push(...bind.errors);
    }
  }

  const requiredClasses = [
    "malicious_page",
    "issue_upstream",
    "official_prose",
    "blocked_action",
    "followup_authority",
    "repair_dsl",
    "platform_capability",
    "official_fix",
    "change_to_local",
  ];
  for (const c of requiredClasses) {
    if (!classes.has(c)) {
      errors.push(`missing_class:${c}`);
    }
  }

  if (rows.length < 8) {
    errors.push(`matrix_too_small:${rows.length}`);
  }

  if (errors.length > 0) {
    return {
      ok: false,
      reason_code: "GATE_INJECTION",
      errors,
      detail: "injection_matrix_failed",
    };
  }
  return {
    ok: true,
    reason_code: null,
    errors: [],
    detail: "injection_matrix_ok",
    row_count: rows.length,
    classes: [...classes].sort(),
  };
}
