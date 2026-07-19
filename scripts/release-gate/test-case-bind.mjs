/**
 * Deterministic named-test-case binder for Ticket 16 release-gate scripts.
 *
 * Locates a single *executable top-level* `test("…", () => { … })` call by
 * title (TypeScript compiler AST — never regex source scans) and checks that
 * outcome / invariant / fixture evidence lives inside that call's body (after
 * expanding same-file top-level helpers actually invoked from the test chain).
 *
 * Comments, string/template literals that merely contain assertion-shaped text,
 * commented-out helpers/tests, `test.skip` / `test.todo`, and title-only
 * placeholders cannot satisfy outcome, invariant, fixture, seam, or behavioral
 * evidence. Ambiguous substring title matches fail closed unless exactly one
 * exact title equality exists.
 *
 * Boundary (honest): every mandatory injection `must_not` token is proven only
 * by a *forcing* executable assertion over product-rooted fields/calls
 * (`MUST_NOT_CONTRACTS` table + one reusable AST traversal; `authorize_repair`
 * keeps its dedicated product-field walker). Regex / evidence-text fallback is
 * not a source of truth. Free-standing comparisons, `assert.ok` string
 * literals, `assert.ok(... || true)` bypasses, tautologies, bare identifiers,
 * unrelated roots, comments/templates/messages, and mere reason-code literals
 * without the relevant product field never bind. Pure multi-arm OR is accepted
 * only when every arm independently proves the contract.
 * Outcome `refused` is field-bound (product-rooted error_code / authorization /
 * repair_authorized / exitCode / ok leaves). Status outcomes (`status` /
 * `recipe_status` / `diagnosis_state`) require an allowlisted product root and
 * a forcing assertion. Fixture identity requires the row path to *flow into* a
 * terminal fixture-consuming call (`copyFixtureToTemp` / `fixtureTemp`, or
 * nested `path.join` inside a real I/O consumer such as `fs.readFileSync`)
 * after same-file const/object/template resolution. Public-seam markers remain
 * product-call presence checks on comment-stripped bodies.
 *
 * Uses the existing `typescript` devDependency only (zero production runtime
 * deps). Dead brace-scanner code has been removed; the AST path is sole.
 */

import ts from "typescript";

/**
 * @param {string} source
 * @returns {import("typescript").SourceFile | null}
 */
function parseSource(source) {
  if (typeof source !== "string") return null;
  try {
    return ts.createSourceFile(
      "bind.ts",
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
 * Remove line/block comments via TS comment ranges. String/template contents
 * are preserved (callers that need assertion evidence must use AST walkers).
 * @param {string} text
 * @returns {string}
 */
function stripComments(text) {
  if (typeof text !== "string" || !text) return "";
  const sf = parseSource(text);
  if (!sf) return "";
  const full = sf.getFullText();
  /** @type {[number, number][]} */
  const ranges = [];
  /**
   * @param {import("typescript").Node} node
   */
  const collect = (node) => {
    const leading = ts.getLeadingCommentRanges(full, node.getFullStart());
    if (leading) {
      for (const r of leading) ranges.push([r.pos, r.end]);
    }
    const trailing = ts.getTrailingCommentRanges(full, node.end);
    if (trailing) {
      for (const r of trailing) ranges.push([r.pos, r.end]);
    }
    ts.forEachChild(node, collect);
  };
  collect(sf);
  // File-level prologue comments (before first statement).
  const prologue = ts.getLeadingCommentRanges(full, 0);
  if (prologue) {
    for (const r of prologue) ranges.push([r.pos, r.end]);
  }
  if (ranges.length === 0) return full;
  ranges.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  let out = "";
  let cursor = 0;
  for (const [s, e] of ranges) {
    if (s > cursor) out += full.slice(cursor, s);
    if (e > cursor) cursor = e;
  }
  out += full.slice(cursor);
  return out;
}

/**
 * Collect direct callee identifier names from CallExpressions in an AST node.
 * @param {import("typescript").Node} root
 * @param {string[]} out
 */
function collectDirectCallNames(root, out) {
  /**
   * @param {import("typescript").Node} node
   */
  const visit = (node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      out.push(node.expression.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(root);
}

/**
 * @param {import("typescript").Node} node
 * @returns {boolean}
 */
function isAssertPropertyCall(node) {
  if (!ts.isCallExpression(node)) return false;
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
    expr.expression.text === "assert" &&
    (ts.isStringLiteral(expr.argumentExpression) ||
      ts.isNoSubstitutionTemplateLiteral(expr.argumentExpression))
  ) {
    return true;
  }
  return false;
}

/**
 * @param {import("typescript").CallExpression} node
 * @param {string[]} methods
 */
function isAssertMethodCall(node, methods) {
  if (!isAssertPropertyCall(node)) return false;
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
 * @param {import("typescript").Node} node
 * @param {string} value
 */
function nodeHasExactStringLiteral(node, value) {
  let found = false;
  /**
   * @param {import("typescript").Node} n
   */
  const visit = (n) => {
    if (found) return;
    if (
      (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) &&
      n.text === value
    ) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  visit(node);
  return found;
}

/**
 * Outcome-field leaf names that only count when rooted in a product result chain.
 * Bare identifiers and unrelated object leaves never satisfy status outcomes.
 * @type {ReadonlySet<string>}
 */
const OUTCOME_FIELD_LEAVES = Object.freeze(
  new Set(["status", "recipe_status", "diagnosis_state"]),
);

/**
 * Minimal allowlist of product result variable roots used by canonical Ticket 16
 * fixture / write-path / injection GREENs. Unrelated roots (`other`, `fake`,
 * `label`, bare `status`) never bind outcome evidence.
 * Justified by production rows: apply/preview/verify/rollback result chains,
 * diagnose `result`/`r`/`cli`/`mcp`/`core`, and `scan`/`diagnosis` surfaces.
 * @type {ReadonlySet<string>}
 */
const PRODUCT_OUTCOME_ROOTS = Object.freeze(
  new Set([
    "result",
    "apply",
    "preview",
    "verify",
    "rollback",
    "rb",
    "r",
    "core",
    "scan",
    "diagnosis",
    "cli",
    "mcp",
    "out",
    "res",
    "pr",
    "classification",
    "capsule",
    "gate",
    "actionPreview",
    "confirm",
    "sup",
    "sub",
    "cloned",
  ]),
);

/**
 * True when `node` (or a descendant comparison side) is a product-rooted
 * outcome field access (`status` / `recipe_status` / `diagnosis_state`).
 * @param {import("typescript").Node} node
 */
function nodeMentionsProductOutcomeField(node) {
  let found = false;
  /**
   * @param {import("typescript").Node} n
   */
  const visit = (n) => {
    if (found) return;
    if (isStatusLikeExpression(n)) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  visit(node);
  return found;
}

/**
 * Assert method name for a CallExpression, or null.
 * @param {import("typescript").CallExpression} node
 * @returns {string | null}
 */
function assertMethodName(node) {
  if (!isAssertPropertyCall(node)) return null;
  const expr = node.expression;
  if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.name)) {
    return expr.name.text;
  }
  if (
    ts.isElementAccessExpression(expr) &&
    (ts.isStringLiteral(expr.argumentExpression) ||
      ts.isNoSubstitutionTemplateLiteral(expr.argumentExpression))
  ) {
    return expr.argumentExpression.text;
  }
  return null;
}

/**
 * Semantic argument count for an assert method (excludes trailing diagnostic
 * message strings). Equality forms use the two compared operands; ok/match/
 * throws-style forms use only the condition/value/pattern positions.
 * @param {string} method
 * @returns {number}
 */
function assertSemanticArgCount(method) {
  switch (method) {
    case "equal":
    case "strictEqual":
    case "deepEqual":
    case "notEqual":
    case "notStrictEqual":
    case "deepStrictEqual":
    case "match":
    case "doesNotMatch":
      return 2;
    case "ok":
    case "truthy":
    case "falsy":
    case "throws":
    case "doesNotThrow":
    case "rejects":
    case "doesNotReject":
    case "ifError":
      return 1;
    default:
      // Unknown assert.* — take first arg only (never a trailing message).
      return 1;
  }
}

/**
 * Reconstruct `assert.<method>(…)` text using only semantic operand positions.
 * Assertion diagnostic/message arguments are never included, so message-arg
 * spoofs cannot satisfy regex-backed refused / must_not tokens.
 * @param {import("typescript").CallExpression} node
 * @param {import("typescript").SourceFile} sf
 * @returns {string | null}
 */
function assertCallSemanticEvidenceText(node, sf) {
  const method = assertMethodName(node);
  if (!method) return null;
  const n = assertSemanticArgCount(method);
  if (n <= 0 || node.arguments.length === 0) return null;
  const parts = [];
  for (let i = 0; i < n && i < node.arguments.length; i++) {
    parts.push(node.arguments[i].getText(sf));
  }
  if (parts.length === 0) return null;
  return `assert.${method}(${parts.join(", ")})`;
}

/**
 * Executable evidence text: only semantic operands of real `assert.*(...)`
 * calls and product-rooted status-like equality comparisons. Comments,
 * ordinary string/template literals, and assertion message arguments never
 * appear. Full call `getText` is intentionally not used (message-arg RED).
 * @param {string} body
 * @param {import("typescript").SourceFile | null} [preparsed]
 * @returns {string}
 */
function extractExecutableEvidenceText(body, preparsed = null) {
  const sf = preparsed ?? parseSource(body);
  if (!sf) return "";
  /** @type {string[]} */
  const chunks = [];
  /**
   * @param {import("typescript").Node} node
   */
  const visit = (node) => {
    if (ts.isCallExpression(node) && isAssertPropertyCall(node)) {
      const semantic = assertCallSemanticEvidenceText(node, sf);
      if (semantic) chunks.push(semantic);
      // Do not walk into args: nested assert calls are rare; messages stay out.
      return;
    }
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      if (
        (op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
          op === ts.SyntaxKind.EqualsEqualsToken) &&
        nodeMentionsProductOutcomeField(node)
      ) {
        chunks.push(node.getText(sf));
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return chunks.join("\n");
}

/**
 * @param {string} source
 * @param {string} titleSubstr
 * @returns {{ title: string, body: string, header: string, start: number, end: number } | null}
 */
export function extractNamedTestCase(source, titleSubstr) {
  if (typeof source !== "string" || typeof titleSubstr !== "string" || !titleSubstr) {
    return null;
  }
  const sourceFile = parseSource(source);
  if (!sourceFile) return null;
  /** @type {{ title: string, body: string, header: string, start: number, end: number }[]} */
  const matches = [];

  // Only executable top-level ExpressionStatement call expressions:
  //   test("title", () => { ... }) / test('title', function () { ... })
  // Rejects: test.skip / test.todo / test.only (PropertyAccessExpression),
  // nested tests, commented-out text (not in AST), string-spoofed titles.
  for (const statement of sourceFile.statements) {
    if (!ts.isExpressionStatement(statement)) continue;
    const node = statement.expression;
    if (!ts.isCallExpression(node)) continue;
    if (!ts.isIdentifier(node.expression) || node.expression.text !== "test") continue;
    if (node.arguments.length < 2) continue;

    const titleNode = node.arguments[0];
    const callback = node.arguments[1];
    const literalTitle =
      ts.isStringLiteral(titleNode) || ts.isNoSubstitutionTemplateLiteral(titleNode)
        ? titleNode.text
        : null;
    const callbackBody =
      (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback)) &&
      ts.isBlock(callback.body)
        ? callback.body
        : null;
    if (!literalTitle || !callbackBody) continue;
    if (!literalTitle.includes(titleSubstr)) continue;

    const start = node.getStart(sourceFile);
    const bodyStart = callbackBody.getStart(sourceFile);
    matches.push({
      title: literalTitle,
      body: source.slice(bodyStart, callbackBody.end),
      header: source.slice(start, bodyStart),
      start,
      end: node.end,
    });
  }

  if (matches.length === 0) return null;
  if (matches.length > 1) {
    // Exact title equality is the only safe disambiguation; else fail closed.
    const exact = matches.filter((x) => x.title === titleSubstr);
    if (exact.length === 1) return exact[0];
    return null;
  }
  return matches[0];
}

/**
 * Collect identifier texts referenced as values (calls already collected
 * separately; this captures `FAMILY_FIXTURES.access` / `PROTECTED` style
 * constant indirection for fixture-identity expansion).
 * @param {import("typescript").Node} root
 * @param {string[]} out
 */
function collectReferencedIdentifiers(root, out) {
  /**
   * @param {import("typescript").Node} node
   */
  const visit = (node) => {
    if (ts.isIdentifier(node)) {
      out.push(node.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(root);
}

/**
 * Expand top-level helper function bodies *and* top-level const initializers
 * referenced from a test body (same-file only). Only helpers/constants actually
 * reached from the test/helper chain are considered. Commented-out helpers never
 * appear in the AST and cannot satisfy evidence.
 * @param {string} testBody
 * @param {string} fullSource
 * @returns {string}
 */
export function expandSameFileHelpers(testBody, fullSource) {
  const testSource = parseSource(testBody);
  const fullSourceFile = parseSource(fullSource);
  if (!testSource || !fullSourceFile) return "";

  /** @type {Map<string, import("typescript").FunctionDeclaration>} */
  const helpers = new Map();
  /** @type {Map<string, import("typescript").Expression>} */
  const constInits = new Map();
  for (const statement of fullSourceFile.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name && statement.body) {
      helpers.set(statement.name.text, statement);
    }
    if (ts.isVariableStatement(statement)) {
      for (const decl of statement.declarationList.declarations) {
        if (
          ts.isIdentifier(decl.name) &&
          decl.initializer &&
          (statement.declarationList.flags & ts.NodeFlags.Const) !== 0
        ) {
          constInits.set(decl.name.text, decl.initializer);
        }
      }
    }
  }

  /** @type {string[]} */
  const chunks = [stripComments(testBody)];
  /** @type {string[]} */
  const pending = [];
  collectDirectCallNames(testSource, pending);
  collectReferencedIdentifiers(testSource, pending);
  const seen = new Set();
  while (pending.length > 0) {
    const name = pending.shift();
    if (!name || seen.has(name)) continue;
    seen.add(name);
    const helper = helpers.get(name);
    if (helper?.body) {
      const helperText = helper.body.getText(fullSourceFile);
      chunks.push(stripComments(helperText));
      collectDirectCallNames(helper.body, pending);
      collectReferencedIdentifiers(helper.body, pending);
      continue;
    }
    const init = constInits.get(name);
    if (init) {
      // Preserve the binding name so fixture flow analysis can resolve
      // `fixtureTemp(PROTECTED)` / `FAMILY_FIXTURES.access` after expansion.
      // Bare initializer text alone made dead/unreferenced path strings look bound.
      const initText = init.getText(fullSourceFile);
      chunks.push(stripComments(`const ${name} = ${initText};`));
      collectDirectCallNames(init, pending);
      collectReferencedIdentifiers(init, pending);
    }
  }
  return chunks.join("\n");
}

/**
 * @param {string} source
 * @param {string} name
 * @returns {string | null}
 */
export function extractTopLevelFunctionBody(source, name) {
  const sourceFile = parseSource(source);
  if (!sourceFile) return null;
  for (const statement of sourceFile.statements) {
    if (
      ts.isFunctionDeclaration(statement) &&
      statement.name?.text === name &&
      statement.body
    ) {
      return stripComments(statement.body.getText(sourceFile));
    }
  }
  return null;
}

/**
 * True when `node` is a product-rooted outcome field expression:
 *   result.status / apply.result!.user_resolution.status / r.diagnosis_state
 * never a bare identifier (`status`), never an unrelated root (`other.status`,
 * `fake.status`), never a string/template literal. Rejects tautological
 * `assert.equal("STATUS", "STATUS")` and leaf-only spoofs.
 *
 * Property / element access, parentheses, `as` casts, and non-null wrappers
 * are peeled; the leaf must be status | recipe_status | diagnosis_state and
 * the chain root must be in PRODUCT_OUTCOME_ROOTS.
 * @param {import("typescript").Node | undefined} node
 */
function isStatusLikeExpression(node) {
  if (!node) return false;
  // Reuse unwrap for paren/as/non-null; keep local recursion for clarity.
  if (ts.isParenthesizedExpression(node)) {
    return isStatusLikeExpression(node.expression);
  }
  if (
    ts.isAsExpression(node) ||
    ts.isTypeAssertionExpression(node) ||
    ts.isNonNullExpression(node)
  ) {
    return isStatusLikeExpression(node.expression);
  }
  // Bare identifiers never count (no product root).
  if (ts.isIdentifier(node)) return false;

  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    const leaf = propertyAccessLeafName(node);
    if (!leaf || !OUTCOME_FIELD_LEAVES.has(leaf)) return false;
    const root = propertyAccessRootName(node);
    if (!root || !PRODUCT_OUTCOME_ROOTS.has(root)) return false;
    return true;
  }
  return false;
}

/**
 * Exact status string/template literal node (no partial contains).
 * @param {import("typescript").Node | undefined} node
 * @param {string} status
 */
function isExactStatusLiteralNode(node, status) {
  if (!node) return false;
  if (ts.isParenthesizedExpression(node)) {
    return isExactStatusLiteralNode(node.expression, status);
  }
  if (ts.isAsExpression(node) || ts.isTypeAssertionExpression(node) || ts.isNonNullExpression(node)) {
    return isExactStatusLiteralNode(node.expression, status);
  }
  return (
    (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) &&
    node.text === status
  );
}

/**
 * One comparison side is status-like expression; the other is the exact status
 * literal. Literal-vs-literal, message args, and non-status variables fail closed.
 * @param {import("typescript").Node | undefined} a
 * @param {import("typescript").Node | undefined} b
 * @param {string} status
 */
function isStatusComparedToLiteral(a, b, status) {
  return (
    (isStatusLikeExpression(a) && isExactStatusLiteralNode(b, status)) ||
    (isStatusLikeExpression(b) && isExactStatusLiteralNode(a, status))
  );
}

/**
 * True when an assert.ok root condition *semantically forces* a product-rooted
 * status/recipe_status/diagnosis_state comparison to the exact expected literal:
 * - pure `===` / `==` status comparison, or
 * - an AND-only chain in which that comparison is mandatory.
 * OR subtrees never force (a true sibling can satisfy the assert without the
 * status evidence). Parentheses / as / non-null wrappers are peeled.
 * @param {import("typescript").Node | undefined} node
 * @param {string} status
 */
function assertOkForcesStatusLiteral(node, status) {
  const n = unwrapExpr(node);
  if (!n) return false;
  if (ts.isBinaryExpression(n)) {
    const op = n.operatorToken.kind;
    if (
      op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
      op === ts.SyntaxKind.EqualsEqualsToken
    ) {
      return isStatusComparedToLiteral(n.left, n.right, status);
    }
    if (op === ts.SyntaxKind.AmpersandAmpersandToken) {
      // Both sides of && are mandatory for the whole condition to hold.
      return (
        assertOkForcesStatusLiteral(n.left, status) ||
        assertOkForcesStatusLiteral(n.right, status)
      );
    }
    // OR and all other operators never force outcome status evidence.
    return false;
  }
  return false;
}

/**
 * Positive status assertion inside a test body via AST (not assert.notEqual).
 * Counts only when a supported assertion *semantically forces* product-rooted
 * status evidence:
 * - `assert.equal|strictEqual|deepEqual` with product-rooted status expression
 *   and expected literal in the semantic operands;
 * - `assert.ok` only when its root condition is a pure strict/equality status
 *   comparison or an AND-only chain whose relevant comparison is mandatory.
 * Free-standing binary expressions, OR subtrees, tautologies, trailing message
 * args, and dead/unasserted assignments never count.
 * @param {string} body
 * @param {string} status
 */
export function bodyHasPositiveStatusAssert(body, status) {
  if (!body || !status) return false;
  const sf = parseSource(body);
  if (!sf) return false;
  let found = false;
  /**
   * @param {import("typescript").Node} node
   */
  const visit = (node) => {
    if (found) return;
    if (
      ts.isCallExpression(node) &&
      isAssertMethodCall(node, ["equal", "strictEqual", "deepEqual"])
    ) {
      const args = node.arguments;
      if (args.length >= 2 && isStatusComparedToLiteral(args[0], args[1], status)) {
        found = true;
        return;
      }
      // Do not walk into equality args (message args stay out of evidence).
      return;
    }
    if (ts.isCallExpression(node) && isAssertMethodCall(node, ["ok"])) {
      if (
        node.arguments.length >= 1 &&
        assertOkForcesStatusLiteral(node.arguments[0], status)
      ) {
        found = true;
        return;
      }
      // Do not walk free binaries inside non-forcing ok conditions (OR spoofs).
      return;
    }
    // Free-standing status comparisons and unasserted assignments never bind.
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/**
 * True when an assert.ok root condition *semantically forces* a product-rooted
 * status comparison to the exact forbidden literal via inequality:
 * - pure `!==` / `!=` status comparison, or
 * - an AND-only chain in which that inequality is mandatory.
 * OR subtrees never force (a true sibling can satisfy the assert without the
 * negative status evidence). Parentheses / as / non-null wrappers are peeled.
 * @param {import("typescript").Node | undefined} node
 * @param {string} status
 */
function assertOkForcesNegativeStatusLiteral(node, status) {
  const n = unwrapExpr(node);
  if (!n) return false;
  if (ts.isBinaryExpression(n)) {
    const op = n.operatorToken.kind;
    if (
      op === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
      op === ts.SyntaxKind.ExclamationEqualsToken
    ) {
      return isStatusComparedToLiteral(n.left, n.right, status);
    }
    if (op === ts.SyntaxKind.AmpersandAmpersandToken) {
      return (
        assertOkForcesNegativeStatusLiteral(n.left, status) ||
        assertOkForcesNegativeStatusLiteral(n.right, status)
      );
    }
    // OR and all other operators never force negative outcome status evidence.
    return false;
  }
  return false;
}

/**
 * Negative status assertion inside a test body via AST (mirrors positive forcing).
 * Counts only when a supported assertion *semantically forces* product-rooted
 * status inequality evidence:
 * - `assert.notEqual|notStrictEqual` with product-rooted status expression and
 *   expected literal in the semantic operands;
 * - `assert.ok` only when its root condition is a pure inequality status
 *   comparison or an AND-only chain whose relevant comparison is mandatory.
 * Free-standing binaries, OR subtrees, tautologies, trailing message args, and
 * unasserted assignments never count.
 * @param {string} body
 * @param {string} status
 */
export function bodyHasNegativeStatusAssert(body, status) {
  if (!body || !status) return false;
  const sf = parseSource(body);
  if (!sf) return false;
  let found = false;
  /**
   * @param {import("typescript").Node} node
   */
  const visit = (node) => {
    if (found) return;
    if (
      ts.isCallExpression(node) &&
      isAssertMethodCall(node, ["notEqual", "notStrictEqual"])
    ) {
      const args = node.arguments;
      if (args.length >= 2 && isStatusComparedToLiteral(args[0], args[1], status)) {
        found = true;
        return;
      }
      // Do not walk into equality args (message args stay out of evidence).
      return;
    }
    if (ts.isCallExpression(node) && isAssertMethodCall(node, ["ok"])) {
      if (
        node.arguments.length >= 1 &&
        assertOkForcesNegativeStatusLiteral(node.arguments[0], status)
      ) {
        found = true;
        return;
      }
      // Do not walk free binaries inside non-forcing ok conditions (OR spoofs).
      return;
    }
    // Free-standing status inequalities and unasserted assignments never bind.
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/**
 * Product roots allowed for refusal / non-authority field evidence (wrong-repair
 * fixture rows and injection authorize_repair binds). Extends outcome roots with
 * short aliases used by crash-family / page DSL tests (`pr`, `c`, `good`).
 * Bare identifiers and unrelated roots (`other`, `label`, `fake`) never bind.
 * @type {ReadonlySet<string>}
 */
const REFUSAL_PRODUCT_ROOTS = Object.freeze(
  new Set([
    ...PRODUCT_OUTCOME_ROOTS,
    "c",
    "good",
    "bad",
    "approved",
    "classification",
    "cc",
  ]),
);

/**
 * Literal error / status codes that prove a repair was refused (not applicable
 * or explicitly refused). Used only on product-rooted `error_code` / status leaves.
 * @type {ReadonlySet<string>}
 */
const REFUSAL_ERROR_CODES = Object.freeze(
  new Set(["NOT_APPLICABLE", "REPAIR_REFUSED", "WRITE_DISABLED"]),
);

/**
 * Leaf field names whose false/null equality proves non-authority / refusal.
 * @type {ReadonlySet<string>}
 */
const REFUSAL_FALSE_LEAVES = Object.freeze(
  new Set([
    "repair_authorized",
    "eligible_for_repair_capsule_validation",
    "repair_authorization_eligible",
    "eligible_for_validation",
    "ok",
  ]),
);

/**
 * True when node is a product-rooted field access with allowlisted root and the
 * given leaf (or any leaf in a set). Bare identifiers fail closed.
 * @param {import("typescript").Node | undefined} node
 * @param {string | ReadonlySet<string>} leafOrSet
 * @param {ReadonlySet<string>} [roots]
 */
function isRefusalProductField(node, leafOrSet, roots = REFUSAL_PRODUCT_ROOTS) {
  const n = unwrapExpr(node);
  if (!n) return false;
  if (ts.isIdentifier(n)) return false;
  const leaf = propertyAccessLeafName(n);
  if (!leaf) return false;
  if (typeof leafOrSet === "string") {
    if (leaf !== leafOrSet) return false;
  } else if (!leafOrSet.has(leaf)) {
    return false;
  }
  const root = propertyAccessRootName(n);
  if (!root || !roots.has(root)) return false;
  return true;
}

/**
 * One comparison side is product field `leaf`; the other is exact literal/null/bool.
 * @param {import("typescript").Node | undefined} a
 * @param {import("typescript").Node | undefined} b
 * @param {string | ReadonlySet<string>} leafOrSet
 * @param {string} literal
 */
function isProductFieldComparedToLiteral(a, b, leafOrSet, literal) {
  return (
    (isRefusalProductField(a, leafOrSet) &&
      isExactStringOrNullLiteral(b, literal)) ||
    (isRefusalProductField(b, leafOrSet) &&
      isExactStringOrNullLiteral(a, literal))
  );
}

/**
 * Pair is product-rooted refusal evidence (equality operands, either order):
 * - `*.error_code` / status leaf == NOT_APPLICABLE | REPAIR_REFUSED | WRITE_DISABLED
 * - product status leaf == REPAIR_REFUSED (also covered by positive status assert)
 * - `*.authorization` == null
 * - `*.repair_authorized` / eligibility / `.ok` == false
 * - `*.exitCode` / `*.exit_code` != 0 (caller supplies notEqual flag)
 * @param {import("typescript").Node | undefined} a
 * @param {import("typescript").Node | undefined} b
 * @param {{ notEqual?: boolean }} [opts]
 */
function isRefusalOperandPair(a, b, opts = {}) {
  if (opts.notEqual) {
    // assert.notEqual(preview.exitCode, 0) or notEqual(status, REPAIR_PREVIEWED)
    if (
      isProductFieldComparedToLiteral(a, b, new Set(["exitCode", "exit_code"]), "0") ||
      // numeric 0 literal
      ((isRefusalProductField(a, new Set(["exitCode", "exit_code"])) &&
        unwrapExpr(b)?.kind === ts.SyntaxKind.NumericLiteral &&
        /** @type {import("typescript").NumericLiteral} */ (unwrapExpr(b)).text === "0") ||
        (isRefusalProductField(b, new Set(["exitCode", "exit_code"])) &&
          unwrapExpr(a)?.kind === ts.SyntaxKind.NumericLiteral &&
          /** @type {import("typescript").NumericLiteral} */ (unwrapExpr(a)).text ===
            "0"))
    ) {
      return true;
    }
    // notEqual(product.status, REPAIR_PREVIEWED|RESOLVED_VERIFIED) proves non-authority
    if (
      isStatusComparedToLiteral(a, b, "REPAIR_PREVIEWED") ||
      isStatusComparedToLiteral(a, b, "RESOLVED_VERIFIED")
    ) {
      return true;
    }
    return false;
  }

  // error_code / status refusal codes
  if (
    isProductFieldComparedToLiteral(a, b, "error_code", "NOT_APPLICABLE") ||
    isProductFieldComparedToLiteral(a, b, "error_code", "REPAIR_REFUSED") ||
    isProductFieldComparedToLiteral(a, b, "error_code", "WRITE_DISABLED") ||
    isStatusComparedToLiteral(a, b, "REPAIR_REFUSED") ||
    isProductFieldComparedToLiteral(a, b, "status", "REPAIR_REFUSED") ||
    isProductFieldComparedToLiteral(a, b, "status", "candidate_only")
  ) {
    return true;
  }
  // authorization null
  if (isProductFieldComparedToLiteral(a, b, "authorization", "null")) {
    return true;
  }
  // repair_authorized / eligibility / ok === false
  for (const leaf of REFUSAL_FALSE_LEAVES) {
    if (isProductFieldComparedToLiteral(a, b, leaf, "false")) return true;
  }
  return false;
}

/**
 * assert.ok condition forces product refusal evidence:
 * - pure equality of a refusal pair, or
 * - AND chain (any mandatory arm is refusal), or
 * - OR-only chain where *every* arm is a product refusal comparison (sound for
 *   multi-code refusal as in ticket08 negative control).
 * OR mixed with non-refusal arms (e.g. `|| true`) never counts.
 * @param {import("typescript").Node | undefined} node
 */
function assertOkForcesRefusal(node) {
  const n = unwrapExpr(node);
  if (!n) return false;
  if (ts.isBinaryExpression(n)) {
    const op = n.operatorToken.kind;
    if (
      op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
      op === ts.SyntaxKind.EqualsEqualsToken
    ) {
      return isRefusalOperandPair(n.left, n.right);
    }
    if (op === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
        op === ts.SyntaxKind.ExclamationEqualsToken) {
      return isRefusalOperandPair(n.left, n.right, { notEqual: true });
    }
    if (op === ts.SyntaxKind.AmpersandAmpersandToken) {
      return assertOkForcesRefusal(n.left) || assertOkForcesRefusal(n.right);
    }
    if (op === ts.SyntaxKind.BarBarToken) {
      // Every arm must be refusal evidence (OR of pure refusal codes).
      return assertOkIsPureRefusalOrChain(n);
    }
    return false;
  }
  return false;
}

/**
 * @param {import("typescript").Node | undefined} node
 */
function assertOkIsPureRefusalOrChain(node) {
  const n = unwrapExpr(node);
  if (!n) return false;
  if (ts.isBinaryExpression(n)) {
    const op = n.operatorToken.kind;
    if (op === ts.SyntaxKind.BarBarToken) {
      return (
        assertOkIsPureRefusalOrChain(n.left) &&
        assertOkIsPureRefusalOrChain(n.right)
      );
    }
    if (
      op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
      op === ts.SyntaxKind.EqualsEqualsToken
    ) {
      return isRefusalOperandPair(n.left, n.right);
    }
    return false;
  }
  return false;
}

/**
 * Field-bound refusal evidence (AST). Replaces hollow regex over evidence text.
 * Accepts only product-rooted semantic assert operands — never tautologies,
 * bare identifiers, unrelated roots, or assertion message arguments.
 * @param {string} body
 */
export function bodySatisfiesRefusal(body) {
  if (!body) return false;
  // Product status REPAIR_REFUSED under forcing assert still counts.
  if (bodyHasPositiveStatusAssert(body, "REPAIR_REFUSED")) return true;
  const sf = parseSource(body);
  if (!sf) return false;
  let found = false;
  /**
   * @param {import("typescript").Node} node
   */
  const visit = (node) => {
    if (found) return;
    if (
      ts.isCallExpression(node) &&
      isAssertMethodCall(node, ["equal", "strictEqual", "deepEqual"])
    ) {
      if (
        node.arguments.length >= 2 &&
        isRefusalOperandPair(node.arguments[0], node.arguments[1])
      ) {
        found = true;
        return;
      }
      return;
    }
    if (
      ts.isCallExpression(node) &&
      isAssertMethodCall(node, ["notEqual", "notStrictEqual"])
    ) {
      if (
        node.arguments.length >= 2 &&
        isRefusalOperandPair(node.arguments[0], node.arguments[1], {
          notEqual: true,
        })
      ) {
        found = true;
        return;
      }
      return;
    }
    if (ts.isCallExpression(node) && isAssertMethodCall(node, ["ok"])) {
      if (node.arguments.length >= 1 && assertOkForcesRefusal(node.arguments[0])) {
        found = true;
        return;
      }
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/**
 * Field-bound authorize_repair must_not evidence (AST). Product-rooted only:
 * - `*.repair_authorized === false`
 * - `*.authorization === null`
 * - eligibility leaves === false
 * - `*.status === "candidate_only"` (page DSL)
 * - `*.error_code === NOT_APPLICABLE|REPAIR_REFUSED|WRITE_DISABLED`
 * - product status REPAIR_REFUSED
 * - notEqual(product status, REPAIR_PREVIEWED)
 * Unrelated `label` / `other.status` / tautologies never bind.
 * @param {string} body
 */
export function bodySatisfiesAuthorizeRepair(body) {
  if (!body) return false;
  const sf = parseSource(body);
  if (!sf) return false;
  let found = false;
  /**
   * @param {import("typescript").Node | undefined} a
   * @param {import("typescript").Node | undefined} b
   * @param {{ notEqual?: boolean }} [opts]
   */
  const pairMatches = (a, b, opts = {}) => {
    if (opts.notEqual) {
      return (
        isStatusComparedToLiteral(a, b, "REPAIR_PREVIEWED") ||
        isStatusComparedToLiteral(a, b, "RESOLVED_VERIFIED")
      );
    }
    if (
      isProductFieldComparedToLiteral(a, b, "repair_authorized", "false") ||
      isProductFieldComparedToLiteral(a, b, "authorization", "null") ||
      isProductFieldComparedToLiteral(
        a,
        b,
        "eligible_for_repair_capsule_validation",
        "false",
      ) ||
      isProductFieldComparedToLiteral(
        a,
        b,
        "repair_authorization_eligible",
        "false",
      ) ||
      isProductFieldComparedToLiteral(a, b, "eligible_for_validation", "false") ||
      isProductFieldComparedToLiteral(a, b, "status", "candidate_only") ||
      isProductFieldComparedToLiteral(a, b, "error_code", "NOT_APPLICABLE") ||
      isProductFieldComparedToLiteral(a, b, "error_code", "REPAIR_REFUSED") ||
      isProductFieldComparedToLiteral(a, b, "error_code", "WRITE_DISABLED") ||
      isStatusComparedToLiteral(a, b, "REPAIR_REFUSED")
    ) {
      return true;
    }
    return false;
  };
  /**
   * @param {import("typescript").Node} node
   */
  const visit = (node) => {
    if (found) return;
    if (
      ts.isCallExpression(node) &&
      isAssertMethodCall(node, ["equal", "strictEqual", "deepEqual"])
    ) {
      if (
        node.arguments.length >= 2 &&
        pairMatches(node.arguments[0], node.arguments[1])
      ) {
        found = true;
        return;
      }
      return;
    }
    if (
      ts.isCallExpression(node) &&
      isAssertMethodCall(node, ["notEqual", "notStrictEqual"])
    ) {
      if (
        node.arguments.length >= 2 &&
        pairMatches(node.arguments[0], node.arguments[1], { notEqual: true })
      ) {
        found = true;
        return;
      }
      return;
    }
    if (ts.isCallExpression(node) && isAssertMethodCall(node, ["ok"])) {
      const arg = unwrapExpr(node.arguments[0]);
      if (arg && ts.isBinaryExpression(arg)) {
        const op = arg.operatorToken.kind;
        if (
          (op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
            op === ts.SyntaxKind.EqualsEqualsToken) &&
          pairMatches(arg.left, arg.right)
        ) {
          found = true;
          return;
        }
        if (op === ts.SyntaxKind.AmpersandAmpersandToken) {
          // Walk AND arms only via recursive visit of children after return? handle inline:
          const forceAnd = (n) => {
            const u = unwrapExpr(n);
            if (!u || !ts.isBinaryExpression(u)) return false;
            const o = u.operatorToken.kind;
            if (
              o === ts.SyntaxKind.EqualsEqualsEqualsToken ||
              o === ts.SyntaxKind.EqualsEqualsToken
            ) {
              return pairMatches(u.left, u.right);
            }
            if (o === ts.SyntaxKind.AmpersandAmpersandToken) {
              return forceAnd(u.left) || forceAnd(u.right);
            }
            return false;
          };
          if (forceAnd(arg)) {
            found = true;
            return;
          }
        }
      }
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/**
 * Outcome assert: status outcomes require forcing assertion semantics;
 * `refused` is field-bound product refusal evidence (no hollow regex).
 * @param {string} body
 * @param {"refused" | string} expected
 */
export function bodyHasOutcomeAssert(body, expected) {
  if (expected === "refused") {
    return bodySatisfiesRefusal(body);
  }
  return bodyHasPositiveStatusAssert(body, expected);
}

/**
 * Mandatory injection `must_not` tokens are proven only by *forcing* executable
 * assertions over product-rooted fields/calls (declarative contract table + one
 * reusable AST traversal). Regex / evidence-text fallback is not a source of
 * truth. Free-standing comparisons, `assert.ok` string literals, OR-true
 * bypasses, tautologies, bare identifiers, unrelated roots, and message args
 * never bind.
 *
 * @typedef {{
 *   roots: ReadonlySet<string>,
 *   clauses: ReadonlyArray<{
 *     kind: string,
 *     leaf?: string,
 *     values?: ReadonlySet<string>,
 *     prefixes?: ReadonlyArray<string>,
 *     prefix_re?: RegExp,
 *     callee?: string,
 *   }>,
 * }} MustNotContract
 */

/** Shared product roots used by injection-bound canonical tests. */
const MUST_NOT_SHARED_ROOTS = Object.freeze(
  new Set([
    ...PRODUCT_OUTCOME_ROOTS,
    ...REFUSAL_PRODUCT_ROOTS,
    "preview",
    "confirm",
    "result",
    "r",
    "capsule",
    "gate",
    "actionPreview",
    "cli",
    "mcp",
    "sup",
    "sub",
    "out",
    "res",
    "cloned",
    "q",
    "item",
    "bad",
    "v",
    "status",
    "c",
    "good",
    "pr",
    "again",
    "st",
    "un",
    "st2",
  ]),
);

/**
 * Declarative per-token contracts: allowlisted roots + field/call shapes that
 * prove the safety refusal. Inventory-backed by the 15 injection matrix rows.
 * @type {Readonly<Record<string, MustNotContract>>}
 */
export const MUST_NOT_CONTRACTS = Object.freeze({
  raise_confidence: Object.freeze({
    roots: MUST_NOT_SHARED_ROOTS,
    clauses: Object.freeze([
      Object.freeze({
        kind: "field_eq",
        leaf: "confidence",
        values: Object.freeze(new Set(["none"])),
      }),
      Object.freeze({
        kind: "field_eq",
        leaf: "injection_quarantined",
        values: Object.freeze(new Set(["true"])),
      }),
      Object.freeze({
        kind: "field_eq",
        leaf: "policy_mutations_blocked",
        values: Object.freeze(new Set(["true"])),
      }),
      Object.freeze({
        kind: "field_includes",
        leaf: "model_mutation_reasons",
        values: Object.freeze(new Set(["MODEL_CONFIDENCE_ESCALATION_REFUSED"])),
      }),
    ]),
  }),
  external_write: Object.freeze({
    roots: MUST_NOT_SHARED_ROOTS,
    clauses: Object.freeze([
      Object.freeze({
        kind: "field_eq",
        leaf: "external_write",
        values: Object.freeze(new Set(["false"])),
      }),
    ]),
  }),
  add_change_to_local_edge: Object.freeze({
    roots: MUST_NOT_SHARED_ROOTS,
    clauses: Object.freeze([
      // Graph SHA alone never proves refusal: require mutation refusal fields.
      Object.freeze({
        kind: "field_eq",
        leaf: "model_mutation_refused",
        values: Object.freeze(new Set(["true"])),
      }),
      Object.freeze({
        kind: "field_includes",
        leaf: "model_mutation_reasons",
        values: Object.freeze(new Set(["MODEL_ADD_EDGE_REFUSED"])),
      }),
      // Official prose path: quarantine proves prose never becomes edges.
      Object.freeze({ kind: "field_truthy", leaf: "quarantine" }),
      Object.freeze({
        kind: "field_starts_with",
        leaf: "safe_text",
        prefixes: Object.freeze(["<quarantined:"]),
      }),
      Object.freeze({
        kind: "field_starts_with",
        leaf: "title",
        prefixes: Object.freeze(["<quarantined:"]),
      }),
    ]),
  }),
  execute_prose: Object.freeze({
    roots: MUST_NOT_SHARED_ROOTS,
    clauses: Object.freeze([
      Object.freeze({ kind: "field_truthy", leaf: "quarantine" }),
      Object.freeze({
        kind: "field_eq",
        leaf: "reason",
        values: Object.freeze(new Set(["ignore_instructions"])),
      }),
      Object.freeze({
        kind: "field_starts_with",
        leaf: "safe_text",
        prefixes: Object.freeze(["<quarantined:"]),
      }),
      Object.freeze({
        kind: "field_starts_with",
        leaf: "title",
        prefixes: Object.freeze(["<quarantined:"]),
      }),
    ]),
  }),
  supersede_recipe_from_caller_path: Object.freeze({
    roots: MUST_NOT_SHARED_ROOTS,
    clauses: Object.freeze([
      Object.freeze({
        kind: "field_eq",
        leaf: "code",
        values: Object.freeze(new Set(["FORBIDDEN_FIELD", "EXTRA_FIELD", "SNAPSHOT_PATH_FORBIDDEN"])),
      }),
      Object.freeze({
        kind: "field_eq",
        leaf: "error_code",
        values: Object.freeze(new Set(["FORBIDDEN_FIELD", "EXTRA_FIELD", "SNAPSHOT_PATH_FORBIDDEN"])),
      }),
    ]),
  }),
  claim_full_without_receipt: Object.freeze({
    roots: MUST_NOT_SHARED_ROOTS,
    clauses: Object.freeze([
      Object.freeze({
        kind: "field_eq",
        leaf: "reason_code",
        values: Object.freeze(new Set(["FULL_REQUIRES_REAL_MACHINE"])),
      }),
      Object.freeze({
        kind: "field_eq",
        leaf: "full_support_claimed",
        values: Object.freeze(new Set(["false"])),
      }),
      Object.freeze({
        kind: "field_eq",
        leaf: "claimed_status",
        values: Object.freeze(new Set(["LIMITED", "NONE", "PARTIAL"])),
      }),
    ]),
  }),
  // Refusal in the *absence* of official binding — never successful supersession
  // and never binary_install alone. Inventory-backed by Ticket12 adversarial
  // self-attestation / official-evidence refusal tests (fixed error_code).
  supersede_without_official_bind: Object.freeze({
    roots: MUST_NOT_SHARED_ROOTS,
    clauses: Object.freeze([
      Object.freeze({
        kind: "field_eq",
        leaf: "error_code",
        values: Object.freeze(
          new Set([
            "MEASUREMENT_SELF_ATTESTATION_DEPRECATED",
            "OFFICIAL_EVIDENCE_REQUIRED",
            "OFFICIAL_EVIDENCE_DIGEST_MISMATCH",
            "OFFICIAL_EVIDENCE_MISMATCH",
            "OFFICIAL_EVIDENCE_REF_REFUSED",
            "OFFICIAL_EVIDENCE_UNSUITABLE",
            "OFFICIAL_EVIDENCE_MECHANISM_UNRELATED",
          ]),
        ),
      }),
    ]),
  }),
  binary_install: Object.freeze({
    roots: MUST_NOT_SHARED_ROOTS,
    clauses: Object.freeze([
      Object.freeze({
        kind: "field_eq",
        leaf: "binary_installed",
        values: Object.freeze(new Set(["false"])),
      }),
      Object.freeze({
        kind: "field_eq",
        leaf: "binary_downloaded",
        values: Object.freeze(new Set(["false"])),
      }),
    ]),
  }),
  mint_confirmation: Object.freeze({
    roots: Object.freeze(
      new Set([
        "preview",
        "confirm",
        "result",
        "r",
        "capsule",
        "gate",
        "actionPreview",
        "cli",
        "mcp",
      ]),
    ),
    clauses: Object.freeze([
      Object.freeze({
        kind: "field_eq",
        leaf: "confirmation_token",
        values: Object.freeze(new Set(["null"])),
      }),
      Object.freeze({
        kind: "field_eq",
        leaf: "status",
        values: Object.freeze(
          new Set([
            "BLOCKED_CAPSULE",
            "PREVIEW_BLOCKED",
            "INVALID_CONFIRMATION",
            "UNREGISTERED_CONFIRMATION",
            "MALFORMED_CONFIRMATION",
            "EXPIRED_CONFIRMATION",
            "REPLAYED_CONFIRMATION",
          ]),
        ),
      }),
      Object.freeze({
        kind: "field_eq",
        leaf: "error_code",
        values: Object.freeze(
          new Set([
            "BLOCKED_CAPSULE",
            "PREVIEW_BLOCKED",
            "INVALID_CONFIRMATION",
            "UNREGISTERED_CONFIRMATION",
            "MALFORMED_CONFIRMATION",
            "EXPIRED_CONFIRMATION",
            "REPLAYED_CONFIRMATION",
          ]),
        ),
      }),
      Object.freeze({
        kind: "field_eq",
        leaf: "passed",
        values: Object.freeze(new Set(["false"])),
      }),
    ]),
  }),
  supersede_without_witness: Object.freeze({
    roots: Object.freeze(
      new Set([
        "preview",
        "confirm",
        "result",
        "r",
        "capsule",
        "gate",
        "actionPreview",
        "cli",
        "mcp",
        "sup",
        "sub",
        "out",
        "res",
        "cloned",
      ]),
    ),
    clauses: Object.freeze([
      Object.freeze({
        kind: "error_code_prefix",
        leaf: "error_code",
        prefix_re: /^LIVE_WITNESS_[A-Z0-9_]+$/,
      }),
      Object.freeze({
        kind: "callee_eq_false",
        callee: "isLiveMeasurementWitness",
      }),
    ]),
  }),
});

/**
 * Empty legacy export: mandatory must_not evidence is contract/AST only.
 * Kept so accidental imports fail closed rather than matching hollow text.
 * @type {Readonly<Record<string, RegExp[]>>}
 */
export const MUST_NOT_ASSERT_PATTERNS = Object.freeze({});

/**
 * @param {import("typescript").Node | undefined} node
 * @param {string} leaf
 * @param {ReadonlySet<string>} roots
 */
function isMustNotProductField(node, leaf, roots) {
  return isProductFieldAccess(node, leaf, roots);
}

/**
 * @param {import("typescript").Node | undefined} a
 * @param {import("typescript").Node | undefined} b
 * @param {string} leaf
 * @param {string} literal
 * @param {ReadonlySet<string>} roots
 */
function isMustNotFieldComparedToLiteral(a, b, leaf, literal, roots) {
  return (
    (isMustNotProductField(a, leaf, roots) &&
      isExactStringOrNullLiteral(b, literal)) ||
    (isMustNotProductField(b, leaf, roots) &&
      isExactStringOrNullLiteral(a, literal))
  );
}

/**
 * @param {import("typescript").Node | undefined} a
 * @param {import("typescript").Node | undefined} b
 * @param {string} leaf
 * @param {ReadonlySet<string>} roots
 * @param {RegExp} re
 */
function isMustNotFieldComparedToPrefix(a, b, leaf, roots, re) {
  const check = (field, lit) => {
    if (!isMustNotProductField(field, leaf, roots)) return false;
    const l = unwrapExpr(lit);
    if (!l || !(ts.isStringLiteral(l) || ts.isNoSubstitutionTemplateLiteral(l))) {
      return false;
    }
    return re.test(l.text);
  };
  return check(a, b) || check(b, a);
}

/**
 * @param {import("typescript").Node | undefined} node
 * @param {string} leaf
 * @param {ReadonlySet<string>} values
 * @param {ReadonlySet<string>} roots
 */
function isProductIncludesCall(node, leaf, values, roots) {
  const n = unwrapExpr(node);
  if (!n || !ts.isCallExpression(n) || n.arguments.length < 1) return false;
  const expr = n.expression;
  if (
    !ts.isPropertyAccessExpression(expr) ||
    !ts.isIdentifier(expr.name) ||
    expr.name.text !== "includes"
  ) {
    return false;
  }
  if (!isMustNotProductField(expr.expression, leaf, roots)) return false;
  const arg = unwrapExpr(n.arguments[0]);
  if (
    !arg ||
    !(ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg))
  ) {
    return false;
  }
  return values.has(arg.text);
}

/**
 * @param {import("typescript").Node | undefined} node
 * @param {string} leaf
 * @param {ReadonlyArray<string>} prefixes
 * @param {ReadonlySet<string>} roots
 */
function isProductStartsWithCall(node, leaf, prefixes, roots) {
  const n = unwrapExpr(node);
  if (!n || !ts.isCallExpression(n) || n.arguments.length < 1) return false;
  const expr = n.expression;
  if (
    !ts.isPropertyAccessExpression(expr) ||
    !ts.isIdentifier(expr.name) ||
    expr.name.text !== "startsWith"
  ) {
    return false;
  }
  if (!isMustNotProductField(expr.expression, leaf, roots)) return false;
  const arg = unwrapExpr(n.arguments[0]);
  if (
    !arg ||
    !(ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg))
  ) {
    return false;
  }
  return prefixes.some((p) => arg.text.startsWith(p) || arg.text === p);
}

/**
 * Equality / comparison operand pair matches any clause of the contract.
 * @param {import("typescript").Node | undefined} a
 * @param {import("typescript").Node | undefined} b
 * @param {MustNotContract} contract
 */
function pairMatchesMustNotContract(a, b, contract) {
  const roots = contract.roots;
  for (const clause of contract.clauses) {
    if (clause.kind === "field_eq" && clause.leaf && clause.values) {
      for (const val of clause.values) {
        if (isMustNotFieldComparedToLiteral(a, b, clause.leaf, val, roots)) {
          return true;
        }
      }
    } else if (
      clause.kind === "error_code_prefix" &&
      clause.leaf &&
      clause.prefix_re
    ) {
      if (
        isMustNotFieldComparedToPrefix(a, b, clause.leaf, roots, clause.prefix_re)
      ) {
        return true;
      }
    } else if (clause.kind === "callee_eq_false" && clause.callee) {
      const a0 = unwrapExpr(a);
      const a1 = unwrapExpr(b);
      const callSide =
        a0 && ts.isCallExpression(a0) && callCalleeName(a0) === clause.callee
          ? a0
          : a1 && ts.isCallExpression(a1) && callCalleeName(a1) === clause.callee
            ? a1
            : null;
      const boolSide = callSide === a0 ? a1 : callSide === a1 ? a0 : null;
      if (callSide && boolSide && boolSide.kind === ts.SyntaxKind.FalseKeyword) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Single assert.ok condition arm forces contract evidence (no free binaries).
 * @param {import("typescript").Node | undefined} node
 * @param {MustNotContract} contract
 */
function assertOkForcesMustNotContract(node, contract) {
  const n = unwrapExpr(node);
  if (!n) return false;
  const roots = contract.roots;

  // Product field truthy / includes / startsWith call forms.
  for (const clause of contract.clauses) {
    if (clause.kind === "field_truthy" && clause.leaf) {
      if (isMustNotProductField(n, clause.leaf, roots)) return true;
    }
    if (clause.kind === "field_includes" && clause.leaf && clause.values) {
      if (isProductIncludesCall(n, clause.leaf, clause.values, roots)) {
        return true;
      }
    }
    if (clause.kind === "field_starts_with" && clause.leaf && clause.prefixes) {
      if (isProductStartsWithCall(n, clause.leaf, clause.prefixes, roots)) {
        return true;
      }
    }
  }

  if (ts.isBinaryExpression(n)) {
    const op = n.operatorToken.kind;
    if (
      op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
      op === ts.SyntaxKind.EqualsEqualsToken
    ) {
      return pairMatchesMustNotContract(n.left, n.right, contract);
    }
    if (op === ts.SyntaxKind.AmpersandAmpersandToken) {
      return (
        assertOkForcesMustNotContract(n.left, contract) ||
        assertOkForcesMustNotContract(n.right, contract)
      );
    }
    if (op === ts.SyntaxKind.BarBarToken) {
      // Pure OR only when *every* arm independently proves the contract.
      return assertOkIsPureMustNotOrChain(n, contract);
    }
    return false;
  }
  return false;
}

/**
 * @param {import("typescript").Node | undefined} node
 * @param {MustNotContract} contract
 */
function assertOkIsPureMustNotOrChain(node, contract) {
  const n = unwrapExpr(node);
  if (!n) return false;
  if (ts.isBinaryExpression(n)) {
    const op = n.operatorToken.kind;
    if (op === ts.SyntaxKind.BarBarToken) {
      return (
        assertOkIsPureMustNotOrChain(n.left, contract) &&
        assertOkIsPureMustNotOrChain(n.right, contract)
      );
    }
    if (
      op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
      op === ts.SyntaxKind.EqualsEqualsToken
    ) {
      return pairMatchesMustNotContract(n.left, n.right, contract);
    }
    return false;
  }
  // Non-binary arms (e.g. true, string lit) never prove.
  return false;
}

/**
 * Reusable forcing-assertion traversal for a must_not contract.
 * Accepts only assert.equal|strictEqual|deepEqual semantic operands and
 * pure/AND-only assert.ok (or pure multi-arm refusal OR). Free-standing
 * comparisons and message args never bind.
 * @param {string} body
 * @param {MustNotContract} contract
 */
export function bodySatisfiesMustNotContract(body, contract) {
  if (!body || !contract) return false;
  const sf = parseSource(body);
  if (!sf) return false;
  let found = false;
  /**
   * @param {import("typescript").Node} node
   */
  const visit = (node) => {
    if (found) return;
    if (
      ts.isCallExpression(node) &&
      isAssertMethodCall(node, ["equal", "strictEqual", "deepEqual"])
    ) {
      if (
        node.arguments.length >= 2 &&
        pairMatchesMustNotContract(
          node.arguments[0],
          node.arguments[1],
          contract,
        )
      ) {
        found = true;
        return;
      }
      return;
    }
    if (ts.isCallExpression(node) && isAssertMethodCall(node, ["ok"])) {
      if (
        node.arguments.length >= 1 &&
        assertOkForcesMustNotContract(node.arguments[0], contract)
      ) {
        found = true;
        return;
      }
      return;
    }
    // Free-standing binaries / assignments never bind.
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/**
 * True when the body contains at least one real `assert.*(...)` CallExpression
 * (AST). Comments and strings that merely spell "assert." do not count.
 * @param {string} body
 */
export function bodyHasExecutableAssertCall(body) {
  const sf = parseSource(body);
  if (!sf) return false;
  let found = false;
  /**
   * @param {import("typescript").Node} node
   */
  const visit = (node) => {
    if (found) return;
    if (isAssertPropertyCall(node)) {
      found = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

/**
 * Field-bound mint_confirmation evidence (AST, forcing asserts only).
 * @param {string} body
 */
export function bodySatisfiesMintConfirmation(body) {
  return bodySatisfiesMustNotContract(body, MUST_NOT_CONTRACTS.mint_confirmation);
}

/**
 * Field-bound supersede_without_witness evidence (AST, forcing asserts only).
 * @param {string} body
 */
export function bodySatisfiesSupersedeWithoutWitness(body) {
  return bodySatisfiesMustNotContract(
    body,
    MUST_NOT_CONTRACTS.supersede_without_witness,
  );
}

/**
 * @param {string} body
 * @param {string} mustNot
 */
export function bodySatisfiesMustNot(body, mustNot) {
  if (mustNot === "authorize_repair") {
    return bodySatisfiesAuthorizeRepair(body);
  }
  const contract = MUST_NOT_CONTRACTS[mustNot];
  if (!contract) {
    // Unknown token: fail closed (never hollow token-name presence).
    return false;
  }
  return bodySatisfiesMustNotContract(body, contract);
}

/**
 * @param {import("typescript").Node | undefined} node
 * @returns {string | null}
 */
function propertyAccessLeafName(node) {
  const n = unwrapExpr(node);
  if (!n) return null;
  if (ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.name)) {
    return n.name.text;
  }
  if (ts.isElementAccessExpression(n)) {
    const arg = unwrapExpr(n.argumentExpression);
    if (
      arg &&
      (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg))
    ) {
      return arg.text;
    }
  }
  if (ts.isIdentifier(n)) return n.text;
  if (
    ts.isNonNullExpression(n) ||
    ts.isAsExpression(n) ||
    ts.isTypeAssertionExpression(n) ||
    ts.isParenthesizedExpression(n)
  ) {
    return propertyAccessLeafName(
      ts.isParenthesizedExpression(n) ? n.expression : n.expression,
    );
  }
  return null;
}

/**
 * Root identifier of a property chain (`preview.status` → `preview`,
 * `result.capsule!.status` → `result`, bare `status` → null).
 * @param {import("typescript").Node | undefined} node
 * @returns {string | null}
 */
function propertyAccessRootName(node) {
  let n = unwrapExpr(node);
  if (!n) return null;
  while (n) {
    if (ts.isPropertyAccessExpression(n)) {
      n = unwrapExpr(n.expression);
      continue;
    }
    if (ts.isElementAccessExpression(n)) {
      n = unwrapExpr(n.expression);
      continue;
    }
    if (ts.isCallExpression(n)) {
      // Disallow call results as roots (ambiguous product identity).
      return null;
    }
    if (ts.isIdentifier(n)) return n.text;
    return null;
  }
  return null;
}

/**
 * True when expr is a product field access whose root is allowlisted and leaf
 * matches `leaf`. Bare identifiers and unlisted roots fail closed.
 * @param {import("typescript").Node | undefined} node
 * @param {string} leaf
 * @param {ReadonlySet<string>} roots
 */
function isProductFieldAccess(node, leaf, roots) {
  const n = unwrapExpr(node);
  if (!n) return false;
  if (ts.isIdentifier(n)) return false; // bare `status` is not product-bound
  const leafName = propertyAccessLeafName(n);
  if (leafName !== leaf) return false;
  const root = propertyAccessRootName(n);
  if (!root || !roots || !roots.has(root)) return false;
  return true;
}

/**
 * @param {import("typescript").Node | undefined} node
 * @param {string} value
 */
function isExactStringOrNullLiteral(node, value) {
  const n = unwrapExpr(node);
  if (!n) return false;
  if (value === "null") return n.kind === ts.SyntaxKind.NullKeyword;
  if (value === "true") return n.kind === ts.SyntaxKind.TrueKeyword;
  if (value === "false") return n.kind === ts.SyntaxKind.FalseKeyword;
  return (
    (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) &&
    n.text === value
  );
}

/**
 * @param {import("typescript").Node | undefined} node
 * @param {ReadonlySet<string>} values
 */
function isExactStringInSet(node, values) {
  const n = unwrapExpr(node);
  if (!n) return false;
  if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) {
    return values.has(n.text);
  }
  return false;
}

/**
 * Unwrap parenthesized / as / non-null / type-assertion layers.
 * @param {import("typescript").Node | undefined} node
 * @returns {import("typescript").Node | undefined}
 */
function unwrapExpr(node) {
  if (!node) return node;
  if (ts.isParenthesizedExpression(node)) return unwrapExpr(node.expression);
  if (ts.isAsExpression(node) || ts.isTypeAssertionExpression(node) || ts.isNonNullExpression(node)) {
    return unwrapExpr(node.expression);
  }
  return node;
}

/**
 * Static string values carried by an expression when they are pure literals or
 * fully-literal template/concatenation fragments (fail closed on unresolved).
 * When `resolveIdent` is provided, template `${IDENT}` / + concatenation may
 * resolve same-file const string initials (e.g. CRASH_ROOT + leaf).
 * @param {import("typescript").Node | undefined} node
 * @param {(name: string) => string[] | null} [resolveIdent]
 * @returns {string[]}
 */
function staticStringValuesFromExpr(node, resolveIdent = undefined) {
  const n = unwrapExpr(node);
  if (!n) return [];
  if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) {
    return [n.text];
  }
  if (ts.isIdentifier(n) && resolveIdent) {
    const resolved = resolveIdent(n.text);
    return resolved ?? [];
  }
  if (ts.isTemplateExpression(n)) {
    /** @type {string[]} */
    const parts = [n.head.text];
    for (const span of n.templateSpans) {
      const exprVals = staticStringValuesFromExpr(span.expression, resolveIdent);
      if (exprVals.length !== 1) return [];
      parts.push(exprVals[0]);
      parts.push(span.literal.text);
    }
    return [parts.join("")];
  }
  if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = staticStringValuesFromExpr(n.left, resolveIdent);
    const right = staticStringValuesFromExpr(n.right, resolveIdent);
    if (left.length === 1 && right.length === 1) return [left[0] + right[0]];
    return [];
  }
  return [];
}

/**
 * Terminal fixture-path consumers: the path (or a joined transform of it) must
 * flow into one of these callees. `path.join` alone is a *transformer*, not a
 * consumer — an assigned unused join never binds.
 */
const FIXTURE_PATH_TERMINAL_CONSUMERS = Object.freeze(
  new Set([
    "copyFixtureToTemp",
    "fixtureTemp",
    // Nested I/O consumers that may take path.join(...) as an argument.
    "fs.readFileSync",
    "fs.readFile",
    "fs.promises.readFile",
    "readFileSync",
    "readFile",
  ]),
);

/**
 * Direct callee name for CallExpression (`foo`, `path.join`, `fs.readFileSync`).
 * @param {import("typescript").CallExpression} call
 * @returns {string | null}
 */
function callCalleeName(call) {
  const expr = call.expression;
  if (ts.isIdentifier(expr)) return expr.text;
  if (
    ts.isPropertyAccessExpression(expr) &&
    ts.isIdentifier(expr.expression) &&
    ts.isIdentifier(expr.name)
  ) {
    return `${expr.expression.text}.${expr.name.text}`;
  }
  // fs.promises.readFile
  if (
    ts.isPropertyAccessExpression(expr) &&
    ts.isPropertyAccessExpression(expr.expression) &&
    ts.isIdentifier(expr.expression.expression) &&
    ts.isIdentifier(expr.expression.name) &&
    ts.isIdentifier(expr.name)
  ) {
    return `${expr.expression.expression.text}.${expr.expression.name.text}.${expr.name.text}`;
  }
  return null;
}

/**
 * True when a call is a *terminal* fixture-path consumer (not a mere transform).
 * @param {import("typescript").CallExpression} call
 */
function isFixturePathConsumerCall(call) {
  const name = callCalleeName(call);
  if (!name) return false;
  if (FIXTURE_PATH_TERMINAL_CONSUMERS.has(name)) return true;
  // Bare readFileSync without fs. prefix (local import alias)
  if (name === "readFileSync" || name === "readFile") return true;
  return false;
}

/**
 * True when expression is path.join(...) or an identifier bound to a path.join
 * call initializer in the same file (resolved by caller).
 * @param {import("typescript").Node | undefined} expr
 */
function isPathJoinCall(expr) {
  const n = unwrapExpr(expr);
  if (!n || !ts.isCallExpression(n)) return false;
  return callCalleeName(n) === "path.join";
}

/**
 * Collect string literal / const / object-property path values that flow into
 * fixture-consuming call arguments (not dead declarations or unused consts).
 * Resolves minimal same-file const / object-property / function-parameter flow;
 * ambiguity or unresolved identifiers fail closed (no raw text.includes).
 *
 * @param {import("typescript").SourceFile} sf
 * @returns {string[]}
 */
function collectFixturePathLiteralsFromConsumers(sf) {
  /** @type {Map<string, import("typescript").Expression>} */
  const constInits = new Map();
  /**
   * @param {import("typescript").Node} node
   */
  const collectConsts = (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      // Prefer const; also accept let/var for local test helpers.
      constInits.set(node.name.text, node.initializer);
    }
    // Expanded helper bodies arrive as Block statements; still walk.
    ts.forEachChild(node, collectConsts);
  };
  collectConsts(sf);

  /**
   * Resolve an expression to concrete path string candidates via const/object flow.
   * @param {import("typescript").Node | undefined} expr
   * @param {Set<string>} seen
   * @returns {string[]}
   */
  const resolvePathValues = (expr, seen = new Set()) => {
    const n = unwrapExpr(expr);
    if (!n) return [];

    /**
     * @param {string} name
     * @returns {string[] | null}
     */
    const resolveIdent = (name) => {
      if (seen.has(name)) return null;
      const init = constInits.get(name);
      if (!init) return null;
      seen.add(name);
      const vals = resolvePathValues(init, seen);
      seen.delete(name);
      return vals.length > 0 ? vals : null;
    };

    // Literal / template / concat first (with optional ident resolution for
    // `${CRASH_ROOT}/leaf` style FAMILY_FIXTURES entries).
    if (
      ts.isStringLiteral(n) ||
      ts.isNoSubstitutionTemplateLiteral(n) ||
      ts.isTemplateExpression(n) ||
      (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.PlusToken)
    ) {
      const statics = staticStringValuesFromExpr(n, resolveIdent);
      if (statics.length > 0) return statics;
    }

    if (ts.isIdentifier(n)) {
      if (seen.has(n.text)) return [];
      seen.add(n.text);
      const init = constInits.get(n.text);
      if (!init) {
        seen.delete(n.text);
        return [];
      }
      const vals = resolvePathValues(init, seen);
      seen.delete(n.text);
      return vals;
    }

    if (ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.expression)) {
      const objName = n.expression.text;
      const prop = n.name.text;
      const key = `${objName}.${prop}`;
      if (seen.has(key)) return [];
      seen.add(key);
      const init = constInits.get(objName);
      if (!init) {
        seen.delete(key);
        return [];
      }
      const obj = unwrapExpr(init);
      if (!obj || !ts.isObjectLiteralExpression(obj)) {
        seen.delete(key);
        return [];
      }
      for (const p of obj.properties) {
        if (ts.isPropertyAssignment(p)) {
          const pkey =
            ts.isIdentifier(p.name) || ts.isStringLiteral(p.name) || ts.isNoSubstitutionTemplateLiteral(p.name)
              ? p.name.text
              : null;
          if (pkey === prop) {
            const vals = resolvePathValues(p.initializer, seen);
            seen.delete(key);
            return vals;
          }
        }
      }
      seen.delete(key);
      return [];
    }

    if (ts.isElementAccessExpression(n) && ts.isIdentifier(n.expression)) {
      const objName = n.expression.text;
      const arg = unwrapExpr(n.argumentExpression);
      if (
        !arg ||
        !(ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg))
      ) {
        return [];
      }
      const prop = arg.text;
      const key = `${objName}[${prop}]`;
      if (seen.has(key)) return [];
      seen.add(key);
      const init = constInits.get(objName);
      if (!init) {
        seen.delete(key);
        return [];
      }
      const obj = unwrapExpr(init);
      if (!obj || !ts.isObjectLiteralExpression(obj)) {
        seen.delete(key);
        return [];
      }
      for (const p of obj.properties) {
        if (ts.isPropertyAssignment(p)) {
          const pkey =
            ts.isIdentifier(p.name) || ts.isStringLiteral(p.name) || ts.isNoSubstitutionTemplateLiteral(p.name)
              ? p.name.text
              : null;
          if (pkey === prop) {
            const vals = resolvePathValues(p.initializer, seen);
            seen.delete(key);
            return vals;
          }
        }
      }
      seen.delete(key);
      return [];
    }

    // path.join is a pure transform: resolve each argument and return them so a
    // nested join inside a terminal consumer can prove fixture identity. A bare
    // join assignment is never visited as a terminal consumer, so unused joins
    // still fail closed.
    if (ts.isCallExpression(n) && callCalleeName(n) === "path.join") {
      /** @type {string[]} */
      const joined = [];
      for (const arg of n.arguments) {
        for (const v of resolvePathValues(arg, seen)) joined.push(v);
      }
      return joined;
    }

    // Thin same-file wrapper: fixtureTemp(PROTECTED) expands to helper body
    // `return copyFixtureToTemp(rel, tmp)` where `rel` is a parameter. When the
    // expanded body is concatenated, parameter identifiers remain unresolved —
    // also accept call-site args of known consumers walked above. Fail closed.
    return [];
  };

  /** @type {string[]} */
  const out = [];
  /**
   * @param {import("typescript").Node} node
   */
  const visit = (node) => {
    if (ts.isCallExpression(node) && isFixturePathConsumerCall(node)) {
      for (const arg of node.arguments) {
        for (const v of resolvePathValues(arg)) out.push(v);
      }
    }
    // Template-literal path fragments inside consumer args are covered by
    // resolvePathValues → staticStringValuesFromExpr. Nested path.join inside a
    // terminal consumer is resolved above; standalone path.join is ignored.
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

/**
 * Match a collected path literal against the row's concrete fixture identity.
 * @param {string} lit
 * @param {string} normFixture
 */
function pathLiteralMatchesFixture(lit, normFixture) {
  const n = lit.replace(/\\/g, "/");
  const leaf = normFixture.split("/").filter(Boolean).slice(-2).join("/");
  const last = normFixture.split("/").filter(Boolean).pop() ?? normFixture;
  if (n === normFixture) return true;
  if (n.includes(normFixture)) return true;
  if (leaf.length > 0 && (n === leaf || n.endsWith(`/${leaf}`) || n.includes(leaf))) {
    return true;
  }
  // Bare last segment only when it appears as a path component, never alone as
  // an unrelated identifier.
  if (
    last.length >= 6 &&
    (n === last || n.endsWith(`/${last}`) || (n.includes(`/${last}`) && n.includes("fixtures/")))
  ) {
    return true;
  }
  // Template partials like `fixtures/plugin-cache/${fixture}` after expansion
  // of object maps already yield full paths via resolvePathValues.
  return false;
}

/**
 * True when expanded executable body (after same-file helper/const expansion)
 * binds the row's concrete fixture identity via a real path string that *flows
 * into a terminal fixture-consuming call* (`copyFixtureToTemp`, `fixtureTemp`,
 * or nested `path.join` inside `fs.readFileSync` / equivalent I/O). Dead or
 * unreferenced strings, unused `path.join` assignments, and bare transforms
 * never count. Generic helper names alone never count. Fail closed on parse
 * errors or unresolved flow — never raw `text.includes(path)`.
 * @param {string} body
 * @param {string | null | undefined} fixture
 * @param {string | null | undefined} publicSeam
 */
export function bodyBindsFixtureOrSeam(body, fixture, publicSeam) {
  // Comments must not supply fixture/seam tokens.
  const text = stripComments(body);
  if (fixture) {
    const sf = parseSource(body);
    if (!sf) return false;
    const literals = collectFixturePathLiteralsFromConsumers(sf);
    const norm = fixture.replace(/\\/g, "/");
    const matched = literals.some((lit) => pathLiteralMatchesFixture(lit, norm));
    if (!matched) return false;
  }
  if (publicSeam) {
    // Public seam is documentary; require at least one product-facing call shape.
    const seamHints = [
      /runCliRepair(?:Preview|Apply)|runCliRollback|runCliVerify|runCliDiagnose/,
      /runLifecycle|analyzePage|previewUpstream|assessImpact|validateCandidate/,
      /subscribeIssue|followupStatus|confirmUpstreamAction|platformStatus/,
      /previewRepair|gateCapsuleForActions|validateSupportReceipt/,
      /refreshOfficialEvidence|quarantineProse|pageCommandsToDslCandidates/,
      /parseFollowupRequestJson|validateCandidateFix/,
      /supersedeRecipe|measureWithRegisteredProfile/,
    ];
    if (!seamHints.some((re) => re.test(text))) {
      // Pure unit-style quarantine / DSL tests may only call library functions
      if (!/assert\./.test(text)) return false;
    }
  }
  return true;
}
