/**
 * Production write-path inventory (Ticket 16).
 *
 * Every production writer is classified as repair | state | ledger.
 * Repair paths require source contract markers *and* named behavioral tests
 * proving precondition/backup/atomic replace/verification/rollback and that
 * RESOLVED_VERIFIED cannot be claimed on failure.
 * State/ledger paths must NOT be falsely forced into a repair contract
 * (`forbid_false_repair_claim` is enforced).
 */

import fs from "node:fs";
import path from "node:path";
import {
  bodyHasExecutableAssertCall,
  bodyHasNegativeStatusAssert,
  bodyHasOutcomeAssert,
  expandSameFileHelpers,
  extractNamedTestCase,
} from "./test-case-bind.mjs";
import ts from "typescript";

/**
 * Canonical production writers. Harness-only writers (e.g. macos-scenario)
 * are intentionally excluded.
 */
export const WRITE_PATH_INVENTORY = Object.freeze([
  {
    id: "recovery-atomic-write",
    class: "repair",
    rel: "src/core/recovery/atomic-write.ts",
    required_markers: [
      "createVerifiedBackup",
      "atomicReplaceFile",
      "restoreFromBackup",
    ],
    /** Companion engine that forbids RESOLVED_VERIFIED on verify failure */
    companion_rel: "src/core/recovery/engine.ts",
    companion_markers: [
      "RESOLVED_VERIFIED is impossible",
      "auto_rollback",
      "createVerifiedBackup",
    ],
    boundary_bind: "recovery",
    /**
     * Named behavioral tests that exercise the repair contract end-to-end.
     * Static markers alone are insufficient.
     */
    behavioral_tests: Object.freeze([
      {
        id: "backup_and_resolved",
        test_file: "tests/ticket02-repair-harness.test.ts",
        test_name_substr:
          "successful repair preview → apply → RESOLVED_VERIFIED with hash proof",
        // Declarative semantic contracts (not generic token substrings).
        require_evidence: Object.freeze([
          { kind: "callee", name: "runCliRepairApply" },
          {
            kind: "field_assert",
            field: "backup",
            // capsule.backup object presence or capsule.backup.backup_rel
            roots: Object.freeze(["capsule"]),
          },
          { kind: "outcome", status: "RESOLVED_VERIFIED" },
        ]),
        require_outcome: "RESOLVED_VERIFIED",
      },
      {
        id: "verify_fail_no_resolved",
        test_file: "tests/ticket02-repair-harness.test.ts",
        test_name_substr:
          "induced verification failure auto-rollbacks to original bytes",
        require_evidence: Object.freeze([
          {
            kind: "field_assert",
            field: "auto_rolled_back",
            equals: true,
            roots: Object.freeze(["apply", "result", "r"]),
          },
          { kind: "outcome", status: "REPAIR_FAILED_ROLLED_BACK" },
          { kind: "negative_outcome", status: "RESOLVED_VERIFIED" },
        ]),
        // Must positively prove failure path + not claim RESOLVED_VERIFIED
        require_not_resolved_on_failure: true,
      },
      {
        id: "explicit_rollback",
        test_file: "tests/ticket02-repair-harness.test.ts",
        test_name_substr: "explicit rollback restores exact original bytes/hash",
        require_evidence: Object.freeze([
          { kind: "callee", name: "runCliRollback" },
          { kind: "outcome", status: "MITIGATED_VERIFIED_BY_ROLLBACK" },
        ]),
        require_outcome: "MITIGATED_VERIFIED_BY_ROLLBACK",
      },
    ]),
  },
  {
    id: "instance-fingerprint-state",
    class: "state",
    rel: "src/instances/state.ts",
    required_markers: ["writeFileSync", "renameSync"],
    // State writes are ChangeGuard-owned; no repair backup/rollback contract.
    forbid_false_repair_claim: true,
    boundary_bind: "state_allowlist",
    behavioral_tests: Object.freeze([
      {
        id: "state_symlink_refuse",
        test_file: "tests/instance-scan.test.ts",
        test_name_substr: "state refuses symlink state file",
        require_evidence: Object.freeze([
          {
            kind: "field_assert",
            field: "error_code",
            equals: "SYMLINK_REFUSED",
            roots: Object.freeze(["scan", "result", "r"]),
          },
        ]),
      },
    ]),
  },
  {
    id: "upstream-confirmation-ledger",
    class: "ledger",
    rel: "src/upstream/actions/ledger.ts",
    required_markers: ["writeFileSync", "renameSync"],
    forbid_false_repair_claim: true,
    boundary_bind: "state_allowlist",
    behavioral_tests: Object.freeze([
      {
        id: "offline_forge_refuse",
        test_file: "tests/ticket11-upstream-actions.test.ts",
        test_name_substr:
          "offline forged token without preview registration is refused",
        // Local variable name `forged` is not proof; require product fields.
        require_evidence: Object.freeze([
          {
            kind: "field_assert",
            field: "external_write",
            equals: false,
            roots: Object.freeze(["confirm", "result", "r", "preview"]),
          },
          {
            kind: "one_of_field_codes",
            fields: Object.freeze(["status", "error_code"]),
            codes: Object.freeze([
              "INVALID_CONFIRMATION",
              "UNREGISTERED_CONFIRMATION",
              "MALFORMED_CONFIRMATION",
            ]),
            roots: Object.freeze(["confirm", "result", "r", "preview"]),
          },
        ]),
      },
    ]),
  },
  {
    id: "followup-ledger",
    class: "ledger",
    rel: "src/upstream/followup/ledger.ts",
    required_markers: ["writeFileSync", "renameSync"],
    forbid_false_repair_claim: true,
    boundary_bind: "state_allowlist",
    behavioral_tests: Object.freeze([
      {
        id: "followup_ledger_schema",
        test_file: "tests/ticket12-followup-core.test.ts",
        test_name_substr:
          "Ticket12 ledger: exact schema, digest, capacity, no secrets/raw paths",
        require_evidence: Object.freeze([
          {
            kind: "field_assert",
            field: "ledger_digest",
            roots: Object.freeze([
              "empty",
              "loaded",
              "sealed",
              "ledger",
              "result",
              "r",
            ]),
          },
        ]),
      },
    ]),
  },
  {
    id: "lifecycle-ledger",
    class: "ledger",
    rel: "src/core/lifecycle/ledger.ts",
    required_markers: ["KNOWN_GOOD", "checkpoint"],
    forbid_false_repair_claim: true,
    boundary_bind: "lifecycle",
    behavioral_tests: Object.freeze([
      {
        id: "lifecycle_corrupt_refuse",
        test_file: "tests/ticket06-lifecycle.test.ts",
        test_name_substr: "corrupt/tampered/symlink ledger refused",
        require_evidence: Object.freeze([
          {
            kind: "one_of_field_codes",
            fields: Object.freeze(["error_code"]),
            codes: Object.freeze([
              "TAMPERED_LEDGER",
              "CORRUPT_LEDGER",
              "LEDGER_IO",
              "SYMLINK_REFUSED",
              "SYMLINK_ESCAPE",
            ]),
            roots: Object.freeze([
              "tampered",
              "corrupt",
              "sym",
              "result",
              "r",
              "out",
            ]),
          },
        ]),
      },
    ]),
  },
]);

/** Mirrors scripts/check-production-boundary.mjs DEFAULT_STATE_WRITE_ALLOWLIST. */
export const BOUNDARY_STATE_WRITE_ALLOWLIST = Object.freeze([
  "src/instances/state.ts",
  "src/upstream/actions/ledger.ts",
  "src/upstream/followup/ledger.ts",
]);

export const BOUNDARY_RECOVERY_WRITE_PATH = "src/core/recovery/atomic-write.ts";

/** Repair-contract tokens that state/ledger writers must not claim as their own. */
const FALSE_REPAIR_CLAIM_MARKERS = Object.freeze([
  "createVerifiedBackup",
  "restoreFromBackup",
  "RESOLVED_VERIFIED is impossible",
  "experimental_one_shot",
]);

/**
 * Parse body for AST walks; fail closed on parse errors.
 * @param {string} source
 * @returns {import("typescript").SourceFile | null}
 */
function parseBody(source) {
  if (typeof source !== "string") return null;
  try {
    return ts.createSourceFile(
      "behavioral.ts",
      source,
      ts.ScriptTarget.ES2022,
      /* setParentNodes */ true,
      ts.ScriptKind.TS,
    );
  } catch {
    return null;
  }
}

/**
 * @param {import("typescript").Node | undefined} node
 * @returns {import("typescript").Node | undefined}
 */
function unwrapTokenExpr(node) {
  if (!node) return node;
  if (ts.isParenthesizedExpression(node)) return unwrapTokenExpr(node.expression);
  if (
    ts.isAsExpression(node) ||
    ts.isTypeAssertionExpression(node) ||
    ts.isNonNullExpression(node)
  ) {
    return unwrapTokenExpr(node.expression);
  }
  return node;
}

/**
 * @param {import("typescript").CallExpression} node
 */
function isAssertCall(node) {
  const expr = node.expression;
  if (
    ts.isPropertyAccessExpression(expr) &&
    ts.isIdentifier(expr.expression) &&
    expr.expression.text === "assert"
  ) {
    return true;
  }
  if (
    ts.isElementAccessExpression(expr) &&
    ts.isIdentifier(expr.expression) &&
    expr.expression.text === "assert"
  ) {
    return true;
  }
  return false;
}

/**
 * @param {import("typescript").CallExpression} node
 * @param {string[]} methods
 */
function isAssertMethod(node, methods) {
  if (!isAssertCall(node)) return false;
  const expr = node.expression;
  if (ts.isPropertyAccessExpression(expr)) {
    return methods.includes(expr.name.text);
  }
  if (
    ts.isElementAccessExpression(expr) &&
    (ts.isStringLiteral(expr.argumentExpression) ||
      ts.isNoSubstitutionTemplateLiteral(expr.argumentExpression))
  ) {
    return methods.includes(expr.argumentExpression.text);
  }
  return false;
}

/**
 * @param {import("typescript").CallExpression} node
 * @returns {string | null}
 */
function calleeIdentName(node) {
  const expr = node.expression;
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.name)) {
    return expr.name.text;
  }
  return null;
}

/**
 * Leaf property name of an expression chain.
 * @param {import("typescript").Node | undefined} node
 * @returns {string | null}
 */
function fieldLeafName(node) {
  const n = unwrapTokenExpr(node);
  if (!n) return null;
  if (ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.name)) {
    return n.name.text;
  }
  if (ts.isElementAccessExpression(n)) {
    const arg = unwrapTokenExpr(n.argumentExpression);
    if (
      arg &&
      (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg))
    ) {
      return arg.text;
    }
  }
  if (ts.isIdentifier(n)) return n.text;
  return null;
}

/**
 * Root identifier of a property chain (`apply.result!.auto_rolled_back` → apply).
 * @param {import("typescript").Node | undefined} node
 * @returns {string | null}
 */
function fieldRootName(node) {
  let n = unwrapTokenExpr(node);
  if (!n) return null;
  while (n) {
    if (ts.isPropertyAccessExpression(n)) {
      n = unwrapTokenExpr(n.expression);
      continue;
    }
    if (ts.isElementAccessExpression(n)) {
      n = unwrapTokenExpr(n.expression);
      continue;
    }
    if (ts.isCallExpression(n) || ts.isNewExpression(n)) return null;
    if (ts.isIdentifier(n)) return n.text;
    return null;
  }
  return null;
}

/**
 * True when node is a property access whose leaf is `field` and (if roots given)
 * whose root identifier is in `roots`. Bare identifiers never count when roots
 * are required; without roots, a property leaf match is still required (not bare).
 * @param {import("typescript").Node | undefined} node
 * @param {string} field
 * @param {readonly string[] | undefined} roots
 */
function isAnchoredFieldAccess(node, field, roots) {
  const n = unwrapTokenExpr(node);
  if (!n) return false;
  // Must be a property/element access, not a bare identifier (blocks forged=true).
  if (ts.isIdentifier(n)) return false;
  if (!ts.isPropertyAccessExpression(n) && !ts.isElementAccessExpression(n)) {
    // Nested casts already unwrapped; reject other shapes.
    return false;
  }
  const leaf = fieldLeafName(n);
  if (leaf !== field) {
    // Allow nested segment: capsule.backup.backup_rel for field "backup"
    // by walking the chain for an exact segment match.
    let cur = n;
    let saw = false;
    while (cur && (ts.isPropertyAccessExpression(cur) || ts.isElementAccessExpression(cur))) {
      const seg = fieldLeafName(cur);
      if (seg === field) {
        saw = true;
        break;
      }
      cur = ts.isPropertyAccessExpression(cur)
        ? unwrapTokenExpr(cur.expression)
        : unwrapTokenExpr(cur.expression);
    }
    if (!saw) return false;
  }
  if (roots && roots.length > 0) {
    const root = fieldRootName(n);
    if (!root || !roots.includes(root)) return false;
  }
  return true;
}

/**
 * @param {import("typescript").Node | undefined} node
 * @param {unknown} expected
 */
function literalMatchesEquals(node, expected) {
  const n = unwrapTokenExpr(node);
  if (!n) return false;
  if (expected === true) return n.kind === ts.SyntaxKind.TrueKeyword;
  if (expected === false) return n.kind === ts.SyntaxKind.FalseKeyword;
  if (expected === null) return n.kind === ts.SyntaxKind.NullKeyword;
  if (typeof expected === "string") {
    return (
      (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) &&
      n.text === expected
    );
  }
  if (typeof expected === "number") {
    return ts.isNumericLiteral(n) && Number(n.text) === expected;
  }
  return false;
}

/**
 * Executable callee presence (e.g. runCliRepairApply(...)).
 * @param {string} body
 * @param {string} name
 */
export function bodyHasExecutableCallee(body, name) {
  if (!body || !name) return false;
  const sf = parseBody(body);
  if (!sf) return false;
  let found = false;
  /**
   * @param {import("typescript").Node} node
   */
  const visit = (node) => {
    if (found) return;
    if (ts.isCallExpression(node)) {
      const expr = node.expression;
      if (ts.isIdentifier(expr) && expr.text === name) {
        found = true;
        return;
      }
      if (
        ts.isPropertyAccessExpression(expr) &&
        ts.isIdentifier(expr.name) &&
        expr.name.text === name
      ) {
        found = true;
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/**
 * Anchored product-field assertion: field path must appear on a comparison /
 * assert side (or assert.ok truthiness of the field access). Unrelated leaf
 * names on unlisted roots and bare identifiers fail closed.
 *
 * @param {string} body
 * @param {{ field: string, equals?: unknown, roots?: readonly string[] }} spec
 */
export function bodyHasFieldAssert(body, spec) {
  if (!body || !spec?.field) return false;
  const sf = parseBody(body);
  if (!sf) return false;
  const field = spec.field;
  const roots = spec.roots;
  const hasEquals = Object.prototype.hasOwnProperty.call(spec, "equals");
  let found = false;

  /**
   * @param {import("typescript").Node | undefined} a
   * @param {import("typescript").Node | undefined} b
   */
  const pairOk = (a, b) => {
    if (isAnchoredFieldAccess(a, field, roots)) {
      if (!hasEquals) return true;
      return literalMatchesEquals(b, spec.equals);
    }
    if (isAnchoredFieldAccess(b, field, roots)) {
      if (!hasEquals) return true;
      return literalMatchesEquals(a, spec.equals);
    }
    return false;
  };

  /**
   * @param {import("typescript").Node} node
   */
  const visit = (node) => {
    if (found) return;
    if (ts.isCallExpression(node) && isAssertMethod(node, ["equal", "strictEqual", "deepEqual"])) {
      if (node.arguments.length >= 2 && pairOk(node.arguments[0], node.arguments[1])) {
        found = true;
        return;
      }
    }
    // assert.ok(capsule.backup && typeof capsule.backup === "object")
    // assert.match(empty.ledger_digest, /.../)
    if (
      ts.isCallExpression(node) &&
      isAssertMethod(node, ["ok", "match", "doesNotMatch", "truthy"])
    ) {
      for (const arg of node.arguments) {
        if (exprMentionsAnchoredField(arg, field, roots)) {
          // When equals is required, assert.ok alone is insufficient unless the
          // nested binary compares to that literal.
          if (!hasEquals) {
            found = true;
            return;
          }
          if (binaryEqualsField(arg, field, roots, spec.equals)) {
            found = true;
            return;
          }
        }
      }
    }
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      if (
        op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        op === ts.SyntaxKind.EqualsEqualsToken
      ) {
        if (pairOk(node.left, node.right)) {
          found = true;
          return;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/**
 * @param {import("typescript").Node | undefined} expr
 * @param {string} field
 * @param {readonly string[] | undefined} roots
 */
function exprMentionsAnchoredField(expr, field, roots) {
  let hit = false;
  /**
   * @param {import("typescript").Node | undefined} node
   */
  const walk = (node) => {
    if (!node || hit) return;
    if (isAnchoredFieldAccess(node, field, roots)) {
      hit = true;
      return;
    }
    ts.forEachChild(node, walk);
  };
  walk(unwrapTokenExpr(expr));
  return hit;
}

/**
 * @param {import("typescript").Node | undefined} expr
 * @param {string} field
 * @param {readonly string[] | undefined} roots
 * @param {unknown} equals
 */
function binaryEqualsField(expr, field, roots, equals) {
  let hit = false;
  /**
   * @param {import("typescript").Node | undefined} node
   */
  const walk = (node) => {
    if (!node || hit) return;
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      if (
        op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        op === ts.SyntaxKind.EqualsEqualsToken
      ) {
        if (
          (isAnchoredFieldAccess(node.left, field, roots) &&
            literalMatchesEquals(node.right, equals)) ||
          (isAnchoredFieldAccess(node.right, field, roots) &&
            literalMatchesEquals(node.left, equals))
        ) {
          hit = true;
          return;
        }
      }
    }
    ts.forEachChild(node, walk);
  };
  walk(unwrapTokenExpr(expr));
  return hit;
}

/**
 * One-of status/error_code assertions (logical OR groups allowed).
 * @param {string} body
 * @param {{ fields: readonly string[], codes: readonly string[], roots?: readonly string[] }} spec
 */
export function bodyHasOneOfFieldCodes(body, spec) {
  if (!body || !spec?.fields?.length || !spec?.codes?.length) return false;
  const sf = parseBody(body);
  if (!sf) return false;
  const fields = new Set(spec.fields);
  const codes = new Set(spec.codes);
  const roots = spec.roots;
  let found = false;

  /**
   * @param {import("typescript").Node | undefined} a
   * @param {import("typescript").Node | undefined} b
   */
  const pairOk = (a, b) => {
    const tryPair = (fieldSide, litSide) => {
      const leaf = fieldLeafName(unwrapTokenExpr(fieldSide));
      if (!leaf || !fields.has(leaf)) return false;
      // Require property access, not bare ident.
      const fs = unwrapTokenExpr(fieldSide);
      if (!fs || ts.isIdentifier(fs)) return false;
      if (!ts.isPropertyAccessExpression(fs) && !ts.isElementAccessExpression(fs)) {
        // Walk for nested property with matching leaf on allowlisted root
        if (!exprMentionsAnchoredField(fs, leaf, roots)) return false;
      } else if (roots && roots.length > 0) {
        if (!isAnchoredFieldAccess(fs, leaf, roots)) return false;
      } else if (!isAnchoredFieldAccess(fs, leaf, undefined)) {
        return false;
      }
      const lit = unwrapTokenExpr(litSide);
      if (
        lit &&
        (ts.isStringLiteral(lit) || ts.isNoSubstitutionTemplateLiteral(lit)) &&
        codes.has(lit.text)
      ) {
        return true;
      }
      return false;
    };
    return tryPair(a, b) || tryPair(b, a);
  };

  /**
   * @param {import("typescript").Node} node
   */
  const visit = (node) => {
    if (found) return;
    if (ts.isCallExpression(node) && isAssertMethod(node, ["equal", "strictEqual"])) {
      if (node.arguments.length >= 2 && pairOk(node.arguments[0], node.arguments[1])) {
        found = true;
        return;
      }
    }
    // assert.ok(a === "X" || b === "Y")
    if (ts.isCallExpression(node) && isAssertMethod(node, ["ok"])) {
      if (node.arguments.length >= 1 && binaryTreeHasCode(node.arguments[0], pairOk)) {
        found = true;
        return;
      }
    }
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      if (
        op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        op === ts.SyntaxKind.EqualsEqualsToken
      ) {
        if (pairOk(node.left, node.right)) {
          found = true;
          return;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/**
 * @param {import("typescript").Node | undefined} expr
 * @param {(a: import("typescript").Node, b: import("typescript").Node) => boolean} pairOk
 */
function binaryTreeHasCode(expr, pairOk) {
  let hit = false;
  /**
   * @param {import("typescript").Node | undefined} node
   */
  const walk = (node) => {
    if (!node || hit) return;
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      if (
        op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        op === ts.SyntaxKind.EqualsEqualsToken
      ) {
        if (pairOk(node.left, node.right)) {
          hit = true;
          return;
        }
      }
    }
    ts.forEachChild(node, walk);
  };
  walk(unwrapTokenExpr(expr));
  return hit;
}

/**
 * Evaluate one declarative evidence contract against an expanded test body.
 * @param {string} body
 * @param {Record<string, unknown>} evidence
 * @returns {boolean}
 */
export function bodySatisfiesEvidence(body, evidence) {
  if (!body || !evidence || typeof evidence !== "object") return false;
  const kind = evidence.kind;
  if (kind === "callee") {
    return bodyHasExecutableCallee(body, /** @type {string} */ (evidence.name));
  }
  if (kind === "field_assert") {
    /** @type {{ field: string, equals?: unknown, roots?: readonly string[] }} */
    const spec = {
      field: /** @type {string} */ (evidence.field),
      roots: /** @type {readonly string[] | undefined} */ (evidence.roots),
    };
    // Only require a literal comparator when the contract declares one.
    if (Object.prototype.hasOwnProperty.call(evidence, "equals")) {
      spec.equals = evidence.equals;
    }
    return bodyHasFieldAssert(body, spec);
  }
  if (kind === "one_of_field_codes") {
    return bodyHasOneOfFieldCodes(body, {
      fields: /** @type {readonly string[]} */ (evidence.fields),
      codes: /** @type {readonly string[]} */ (evidence.codes),
      roots: /** @type {readonly string[] | undefined} */ (evidence.roots),
    });
  }
  if (kind === "outcome") {
    return bodyHasOutcomeAssert(body, /** @type {string} */ (evidence.status));
  }
  if (kind === "negative_outcome") {
    return bodyHasNegativeStatusAssert(body, /** @type {string} */ (evidence.status));
  }
  return false;
}

/**
 * Compatibility helper used by Ticket 16 unit probes. Maps legacy token names
 * onto semantic field/callee contracts so residual false-greens stay closed
 * without re-introducing generic superstring matching.
 *
 * - callees: executable CallExpression only
 * - backup / auto_rolled_back / ledger_digest: anchored property asserts
 * - forged / ledger / symlink: never bare-ident; require real product fields/codes
 *
 * @param {string} body
 * @param {string} token
 */
export function bodyHasAssertToken(body, token) {
  if (!body || !token) return false;
  if (
    token === "runCliRepairApply" ||
    token === "runCliRollback" ||
    token === "runCliRepairPreview"
  ) {
    return bodyHasExecutableCallee(body, token);
  }
  if (token === "backup") {
    return bodyHasFieldAssert(body, {
      field: "backup",
      roots: ["capsule", "result", "apply", "preview", "r"],
    });
  }
  if (token === "auto_rolled_back") {
    return bodyHasFieldAssert(body, {
      field: "auto_rolled_back",
      roots: ["apply", "result", "r", "out"],
    });
  }
  if (token === "ledger_digest") {
    return bodyHasFieldAssert(body, {
      field: "ledger_digest",
      roots: ["empty", "loaded", "sealed", "ledger", "result", "r", "raw"],
    });
  }
  if (token === "forged") {
    // Variable name is never proof.
    return false;
  }
  if (token === "symlink") {
    return (
      bodyHasOneOfFieldCodes(body, {
        fields: ["error_code"],
        codes: ["SYMLINK_REFUSED", "SYMLINK_ESCAPE", "LEDGER_SYMLINK"],
        roots: ["scan", "result", "r", "sym", "out"],
      }) || bodyHasExecutableCallee(body, "symlinkSync")
    );
  }
  if (token === "ledger") {
    return bodyHasOneOfFieldCodes(body, {
      fields: ["error_code"],
      codes: [
        "TAMPERED_LEDGER",
        "CORRUPT_LEDGER",
        "LEDGER_IO",
        "SYMLINK_REFUSED",
        "SYMLINK_ESCAPE",
        "LEDGER_SYMLINK",
        "LEDGER_CORRUPT",
      ],
      roots: [
        "tampered",
        "corrupt",
        "sym",
        "result",
        "r",
        "out",
        "scan",
      ],
    });
  }
  // Unknown tokens: require anchored property assert with that leaf name
  // (no bare ident, no superstring).
  return bodyHasFieldAssert(body, { field: token });
}

/**
 * Executable proof that failure path cannot claim RESOLVED_VERIFIED:
 * positive REPAIR_FAILED_ROLLED_BACK / auto_rolled_back true evidence AND
 * either negative status assert against RESOLVED_VERIFIED or positive failed
 * status without a positive RESOLVED_VERIFIED claim.
 * @param {string} body
 */
export function bodyProvesNotResolvedOnFailure(body) {
  if (!body) return false;
  const hasFailedStatus = bodyHasOutcomeAssert(body, "REPAIR_FAILED_ROLLED_BACK");
  const hasAutoRollback = bodyHasFieldAssert(body, {
    field: "auto_rolled_back",
    equals: true,
    roots: ["apply", "result", "r", "out"],
  });
  const hasFail = hasFailedStatus || hasAutoRollback;
  if (!hasFail) return false;
  if (bodyHasNegativeStatusAssert(body, "RESOLVED_VERIFIED")) return true;
  // Failed status asserted positively and no positive RESOLVED_VERIFIED claim.
  if (hasFailedStatus && !bodyHasOutcomeAssert(body, "RESOLVED_VERIFIED")) {
    return true;
  }
  return false;
}

/**
 * @param {string} repoRoot
 * @param {{
 *   test_file: string,
 *   test_name_substr: string,
 *   require_evidence?: readonly Record<string, unknown>[],
 *   require_assert_substrings?: string[],
 *   require_outcome?: string,
 *   require_not_resolved_on_failure?: boolean,
 *   id?: string
 * }} bt
 * @param {string} entryId
 * @returns {string[]}
 */
export function bindBehavioralTest(repoRoot, bt, entryId) {
  /** @type {string[]} */
  const errors = [];
  const testAbs = path.join(repoRoot, bt.test_file);
  if (!fs.existsSync(testAbs)) {
    errors.push(`missing_behavioral_test_file:${entryId}:${bt.id ?? bt.test_name_substr}`);
    return errors;
  }
  let text;
  try {
    text = fs.readFileSync(testAbs, "utf8");
  } catch {
    errors.push(`unreadable_behavioral_test:${entryId}:${bt.id ?? "x"}`);
    return errors;
  }
  const extracted = extractNamedTestCase(text, bt.test_name_substr);
  if (!extracted) {
    errors.push(`missing_behavioral_test_case:${entryId}:${bt.id ?? bt.test_name_substr}`);
    return errors;
  }
  const expanded = expandSameFileHelpers(extracted.body, text);

  // Preferred path: declarative require_evidence contracts.
  const evidenceList = bt.require_evidence ?? null;
  if (evidenceList && evidenceList.length > 0) {
    for (const ev of evidenceList) {
      if (!bodySatisfiesEvidence(expanded, ev)) {
        const tag =
          typeof ev.kind === "string"
            ? `${ev.kind}:${ev.name ?? ev.field ?? ev.status ?? "x"}`
            : "evidence";
        errors.push(`missing_behavioral_assert:${entryId}:${bt.id ?? "x"}:${tag}`);
      }
    }
  } else {
    // Legacy require_assert_substrings (tests / hollow inventory fixtures).
    for (const sub of bt.require_assert_substrings ?? []) {
      if (sub === "assert") {
        if (!bodyHasExecutableAssertCall(expanded)) {
          errors.push(`missing_behavioral_assert:${entryId}:${bt.id ?? "x"}:${sub}`);
        }
        continue;
      }
      if (
        sub === "RESOLVED_VERIFIED" ||
        sub === "MITIGATED_VERIFIED_BY_ROLLBACK" ||
        sub === "REPAIR_FAILED_ROLLED_BACK" ||
        sub === "UPSTREAM_BLOCKED"
      ) {
        const okStatus =
          bodyHasOutcomeAssert(expanded, sub) ||
          bodyHasNegativeStatusAssert(expanded, sub);
        if (!okStatus) {
          errors.push(`missing_behavioral_assert:${entryId}:${bt.id ?? "x"}:${sub}`);
        }
        continue;
      }
      if (!bodyHasAssertToken(expanded, sub)) {
        errors.push(`missing_behavioral_assert:${entryId}:${bt.id ?? "x"}:${sub}`);
      }
    }
  }

  if (bt.require_outcome && !bodyHasOutcomeAssert(expanded, bt.require_outcome)) {
    errors.push(
      `missing_behavioral_outcome:${entryId}:${bt.id ?? "x"}:${bt.require_outcome}`,
    );
  }
  if (bt.require_not_resolved_on_failure) {
    if (!bodyProvesNotResolvedOnFailure(expanded)) {
      errors.push(`missing_no_resolved_on_failure:${entryId}:${bt.id ?? "x"}`);
    }
  }
  // At least one real assert.* CallExpression must live in the named body
  // (comments / string-spoofed "assert." text never count).
  if (!bodyHasExecutableAssertCall(expanded)) {
    errors.push(`hollow_behavioral_test:${entryId}:${bt.id ?? "x"}`);
  }
  return errors;
}

/**
 * @param {string} repoRoot
 * @param {{ inventory?: readonly typeof WRITE_PATH_INVENTORY, stateAllowlist?: readonly string[], recoveryPath?: string }} [opts]
 */
export function checkWritePathInventory(repoRoot, opts = {}) {
  const inventory = opts.inventory ?? WRITE_PATH_INVENTORY;
  const stateAllowlist = new Set(opts.stateAllowlist ?? BOUNDARY_STATE_WRITE_ALLOWLIST);
  const recoveryPath = opts.recoveryPath ?? BOUNDARY_RECOVERY_WRITE_PATH;
  /** @type {string[]} */
  const errors = [];

  const inventoryRels = new Set(inventory.map((e) => e.rel));

  // Drift: every state allowlist path must appear as state or ledger in inventory
  for (const rel of stateAllowlist) {
    const entry = inventory.find((e) => e.rel === rel);
    if (!entry) {
      errors.push(`missing_inventory_for_allowlist:${rel}`);
      continue;
    }
    if (entry.class !== "state" && entry.class !== "ledger") {
      errors.push(`allowlist_not_state_or_ledger:${rel}`);
    }
  }

  // Recovery path must be inventory repair class
  const recoveryEntry = inventory.find((e) => e.rel === recoveryPath);
  if (!recoveryEntry) {
    errors.push(`missing_recovery_inventory:${recoveryPath}`);
  } else if (recoveryEntry.class !== "repair") {
    errors.push(`recovery_not_repair_class:${recoveryPath}`);
  }

  for (const entry of inventory) {
    const abs = path.join(repoRoot, entry.rel);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
      errors.push(`missing_writer:${entry.id}`);
      continue;
    }
    const text = fs.readFileSync(abs, "utf8");
    for (const m of entry.required_markers) {
      if (!text.includes(m)) {
        errors.push(`missing_marker:${entry.id}:${m}`);
      }
    }
    if (entry.companion_rel) {
      const cAbs = path.join(repoRoot, entry.companion_rel);
      if (!fs.existsSync(cAbs)) {
        errors.push(`missing_companion:${entry.id}`);
      } else {
        const cText = fs.readFileSync(cAbs, "utf8");
        for (const m of entry.companion_markers ?? []) {
          if (!cText.includes(m)) {
            errors.push(`missing_companion_marker:${entry.id}:${m}`);
          }
        }
      }
    }
    if (entry.class === "repair") {
      // Repair must prove cannot yield RESOLVED_VERIFIED on failure via companion/engine
      const engineAbs = path.join(repoRoot, entry.companion_rel ?? "src/core/recovery/engine.ts");
      if (fs.existsSync(engineAbs)) {
        const eng = fs.readFileSync(engineAbs, "utf8");
        if (!eng.includes("RESOLVED_VERIFIED is impossible")) {
          errors.push(`repair_missing_resolved_block:${entry.id}`);
        }
      }
      if (!entry.behavioral_tests || entry.behavioral_tests.length === 0) {
        errors.push(`repair_missing_behavioral_tests:${entry.id}`);
      }
    }
    // Enforce forbid_false_repair_claim for state/ledger
    if (entry.forbid_false_repair_claim) {
      if (entry.class === "repair") {
        errors.push(`forbid_false_repair_on_repair_class:${entry.id}`);
      } else {
        for (const m of FALSE_REPAIR_CLAIM_MARKERS) {
          if (text.includes(m)) {
            errors.push(`false_repair_claim:${entry.id}:${m}`);
          }
        }
        // Companion must not reclassify as repair via markers without class=repair
        if (entry.class !== "state" && entry.class !== "ledger") {
          errors.push(`forbid_false_repair_bad_class:${entry.id}`);
        }
      }
    } else if (entry.class === "state" || entry.class === "ledger") {
      // State/ledger without the flag is a contract hole
      errors.push(`missing_forbid_false_repair_claim:${entry.id}`);
    }

    for (const bt of entry.behavioral_tests ?? []) {
      errors.push(...bindBehavioralTest(repoRoot, bt, entry.id));
    }

    if (entry.boundary_bind === "state_allowlist" && !stateAllowlist.has(entry.rel)) {
      errors.push(`not_on_boundary_allowlist:${entry.id}`);
    }
    if (entry.boundary_bind === "recovery" && entry.rel !== recoveryPath) {
      errors.push(`recovery_path_mismatch:${entry.id}`);
    }
  }

  // Detect unregistered production writers under known write surfaces
  const scanRoots = [
    "src/core/recovery",
    "src/instances",
    "src/upstream/actions",
    "src/upstream/followup",
    "src/core/lifecycle",
  ];
  for (const root of scanRoots) {
    const absRoot = path.join(repoRoot, root);
    if (!fs.existsSync(absRoot)) continue;
    walkTsFiles(absRoot, repoRoot, (relFromRepo, abs) => {
      if (relFromRepo.includes("/harness/")) return;
      const text = fs.readFileSync(abs, "utf8");
      if (inventoryRels.has(relFromRepo)) return;
      if (relFromRepo === "src/core/recovery/engine.ts") return;
      if (relFromRepo.endsWith("/index.ts")) return;
      if (relFromRepo.endsWith("/types.ts") || relFromRepo.endsWith("/constants.ts")) return;
      if (relFromRepo === "src/core/lifecycle/engine.ts") return;
      if (relFromRepo === "src/core/lifecycle/dispatch.ts") return;
      if (relFromRepo === "src/core/lifecycle/live-measurement.ts") return;
      if (/fs\.(writeFileSync|writeSync|renameSync)/.test(text)) {
        errors.push(`unregistered_writer:${relFromRepo}`);
      }
    });
  }

  if (errors.length > 0) {
    return {
      ok: false,
      reason_code: "GATE_WRITE_PATH",
      errors,
      detail: "write_path_inventory_failed",
    };
  }
  return {
    ok: true,
    reason_code: null,
    errors: [],
    detail: "write_path_inventory_ok",
    count: inventory.length,
  };
}

/**
 * @param {string} dir
 * @param {string} repoRoot
 * @param {(rel: string, abs: string) => void} fn
 */
function walkTsFiles(dir, repoRoot, fn) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, ent.name);
    if (ent.isDirectory()) walkTsFiles(abs, repoRoot, fn);
    else if (ent.isFile() && ent.name.endsWith(".ts")) {
      const rel = path.relative(repoRoot, abs).split(path.sep).join("/");
      fn(rel, abs);
    }
  }
}
