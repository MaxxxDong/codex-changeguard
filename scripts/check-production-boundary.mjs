/**
 * Independent production-boundary guard (Ticket 01).
 * Scans production TypeScript sources with the TypeScript compiler API
 * (devDependency only — never a production runtime dependency).
 *
 * Fails if the diagnosis path introduces:
 * - network APIs/modules (fetch, http/https/net/tls/dns/dgram/undici, WebSocket)
 * - child processes / arbitrary shell
 * - non-read-only filesystem capabilities on a proven `node:fs` namespace
 *   (read-only method allowlist; unknown methods fail closed)
 * - forbidden fs capability references (pass, bind, sequence, Reflect.apply,
 *   store in array/object, destructure/extract/object-rest) without requiring
 *   a later direct call
 * - dynamic `import(...)`, `require(...)`, or `node:module` / `createRequire`
 *   loader surfaces (static ESM imports only on the production graph)
 * - eval / Function capability acquisition or use / process.dlopen / process.binding
 *
 * open/openSync are allowed only as a direct call through a proven `node:fs`
 * namespace (or simple namespace alias) with statically proven read-only flags.
 * Mere references, extracts, binds, callbacks, or reflective invokes of open
 * are unproven and fail closed.
 *
 * Production module graph follows static ESM ImportDeclaration and relative
 * ExportDeclaration re-exports only.
 *
 * network_used:false in diagnosis output is NOT treated as proof.
 *
 * Self-test mode: `node scripts/check-production-boundary.mjs --self-test`
 * scans synthetic snippets (not production sources) and proves forbidden
 * examples fail and representative safe passages pass.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC_ROOT = path.join(repoRoot, "src");

/** Production entry graph: CLI + MCP + shared core (exclude harness/tests). */
const ENTRY_FILES = [
  path.join(SRC_ROOT, "cli", "main.ts"),
  path.join(SRC_ROOT, "mcp", "server.ts"),
  path.join(SRC_ROOT, "core", "diagnose.ts"),
  path.join(SRC_ROOT, "core", "index.ts"),
];

/**
 * Allowlist of Node builtins permitted on the production diagnosis graph.
 * Anything outside this set (and outside relative imports) is forbidden.
 */
const ALLOWED_NODE_BUILTINS = new Set([
  "crypto",
  "fs",
  "path",
  "url",
  "util",
  "buffer",
  "stream",
  "events",
  "os",
  "assert",
  "readline",
  "string_decoder",
  "timers",
  "tty",
  "zlib",
  "constants",
  // "module" intentionally absent: node:module / createRequire are forbidden loaders.
  "perf_hooks",
  "process",
  "v8",
]);

/** Explicitly forbidden even if they appear as Node builtins. */
const FORBIDDEN_MODULES = new Set([
  "http",
  "https",
  "http2",
  "net",
  "tls",
  "dns",
  "dgram",
  "undici",
  "child_process",
  "worker_threads",
  "cluster",
  "inspector",
  "async_hooks",
  "module",
]);

/**
 * Conservative read-only allowlist for proven `fs` namespace methods (sync +
 * callback forms that do not mutate path contents/metadata). Anything else on
 * a proven fs namespace fails closed, including unknown future Node APIs.
 * open/openSync are NOT allowlisted — they use conditional flag proof instead.
 */
const READONLY_FS_METHODS = new Set([
  "access",
  "accessSync",
  "close",
  "closeSync",
  "createReadStream",
  "exists",
  "existsSync",
  "fstat",
  "fstatSync",
  "lstat",
  "lstatSync",
  "opendir",
  "opendirSync",
  "read",
  "readSync",
  "readv",
  "readvSync",
  "readdir",
  "readdirSync",
  "readFile",
  "readFileSync",
  "readlink",
  "readlinkSync",
  "realpath",
  "realpathSync",
  "stat",
  "statSync",
  "statfs",
  "statfsSync",
]);

/**
 * Read-only allowlist for proven `fs.promises` methods. `open` is conditional
 * (same flag proof as openSync) and is not listed here.
 */
const READONLY_FS_PROMISES_METHODS = new Set([
  "access",
  "close",
  "lstat",
  "opendir",
  "read",
  "readdir",
  "readFile",
  "readlink",
  "realpath",
  "stat",
  "statfs",
]);

/** Namespace / meta properties on fs that are not method capabilities. */
const FS_NAMESPACE_META_PROPERTIES = new Set(["promises", "constants"]);

/** open / openSync / promises.open — allowed only with statically read-only flags. */
const CONDITIONAL_OPEN_METHODS = new Set(["open", "openSync"]);

/** Global names treated as forbidden code-execution capabilities (any value use). */
const FORBIDDEN_CODE_EXEC_GLOBALS = new Set(["eval", "Function"]);

/** Loader APIs forbidden even as named identifiers / imports. */
const FORBIDDEN_LOADER_APIS = new Set(["createRequire", "require"]);

/** String modes that open a path for reading only (Node.js). */
const READ_ONLY_STRING_MODES = new Set(["r", "rs", "sr"]);

/**
 * Flag property names that do not grant write/create/truncate capability on their own.
 * Combined only via bitwise OR of other allowlisted flags (or alone).
 */
const READ_ONLY_FLAG_NAMES = new Set([
  "O_RDONLY",
  "O_NOFOLLOW",
  "O_CLOEXEC",
  "O_NONBLOCK",
  "O_DIRECTORY",
  "O_NOATIME",
  "O_SYNC",
  "O_DSYNC",
  "O_RSYNC",
]);

/** Flag property names that enable write, create, truncate, or read-write. */
const WRITE_CAPABLE_FLAG_NAMES = new Set([
  "O_WRONLY",
  "O_RDWR",
  "O_APPEND",
  "O_CREAT",
  "O_TRUNC",
  "O_TMPFILE",
]);

const FORBIDDEN_GLOBALS = new Set(["fetch", "WebSocket", "XMLHttpRequest"]);

const FORBIDDEN_CHILD_METHODS = new Set([
  "spawn",
  "spawnSync",
  "exec",
  "execSync",
  "execFile",
  "execFileSync",
  "fork",
]);

const FORBIDDEN_PROCESS_METHODS = new Set(["dlopen", "binding"]);

function normalizeModuleSpec(spec) {
  if (typeof spec !== "string") return null;
  return spec.startsWith("node:") ? spec.slice("node:".length) : spec;
}

function isForbiddenModule(spec) {
  const bare = normalizeModuleSpec(spec);
  if (!bare) return true;
  if (FORBIDDEN_MODULES.has(bare)) return true;
  // Subpath like fs/promises is ok (mutations checked via alias resolution).
  if (bare === "fs" || bare.startsWith("fs/")) return false;
  // Relative / package path handled by caller.
  if (bare.startsWith(".") || bare.startsWith("/") || bare.includes(":")) {
    // Absolute or protocol-like non-node specs are not Node builtins we allow.
    if (bare.startsWith(".") || bare.startsWith("/")) return false;
    return true;
  }
  // Bare package name that is a forbidden builtin
  if (FORBIDDEN_MODULES.has(bare.split("/")[0])) return true;
  // Prefer allowlist for production Node builtins: unknown bare builtins fail closed.
  const root = bare.split("/")[0];
  if (ALLOWED_NODE_BUILTINS.has(root) || ALLOWED_NODE_BUILTINS.has(bare)) {
    return false;
  }
  // Third-party bare imports are not expected on Ticket 01 diagnosis path.
  // Treat as forbidden to keep the surface closed (no silent dependency).
  return true;
}

/**
 * Unwrap parentheses, type assertions, non-null assertions, and comma/sequence
 * expressions (rightmost value) for static checks. Used consistently for
 * member-chain and namespace resolution so `(fs as any)`, `fs!`, `(0, fs)`,
 * and nested combinations resolve the same way as a bare identifier.
 * @param {ts.Expression} expr
 * @returns {ts.Expression}
 */
function unwrapStaticExpr(expr) {
  let cur = expr;
  for (;;) {
    if (ts.isParenthesizedExpression(cur)) {
      cur = cur.expression;
      continue;
    }
    if (
      ts.isAsExpression(cur) ||
      ts.isNonNullExpression(cur) ||
      (ts.isTypeAssertionExpression && ts.isTypeAssertionExpression(cur))
    ) {
      cur = cur.expression;
      continue;
    }
    if (cur.kind === ts.SyntaxKind.TypeAssertionExpression && "expression" in cur) {
      cur = /** @type {ts.TypeAssertion} */ (cur).expression;
      continue;
    }
    // Comma / sequence: value is the rightmost operand.
    if (ts.isBinaryExpression(cur) && cur.operatorToken.kind === ts.SyntaxKind.CommaToken) {
      cur = cur.right;
      continue;
    }
    return cur;
  }
}

/**
 * Resolve a property access / element access chain into string segments.
 * Returns null when a segment is non-literal / non-ident (fail-closed check
 * happens at call sites for computed non-literal keys).
 *
 * Unwraps TS `as`, non-null, parentheses, and comma receivers consistently.
 * Also recognizes direct `require("fs")` / `require("node:fs")` (and
 * `fs/promises`) call expressions as synthetic roots so residual require
 * member chains remain visible even though `require(...)` itself is forbidden.
 *
 * @param {ts.Expression} expr
 * @returns {string[] | null}
 */
function resolveMemberChain(expr) {
  const cur = unwrapStaticExpr(expr);
  if (ts.isIdentifier(cur)) {
    return [cur.text];
  }
  if (ts.isPropertyAccessExpression(cur)) {
    const base = resolveMemberChain(cur.expression);
    if (!base) return null;
    return [...base, cur.name.text];
  }
  if (ts.isElementAccessExpression(cur)) {
    const base = resolveMemberChain(cur.expression);
    if (!base) return null;
    const arg = cur.argumentExpression;
    if (arg && ts.isStringLiteral(arg)) {
      return [...base, arg.text];
    }
    // Non-literal computed key — return special marker for fail-closed handling.
    return [...base, "\0computed"];
  }
  // require("fs").method / require("node:fs").promises.method (defense in depth)
  if (ts.isCallExpression(cur)) {
    const callee = unwrapStaticExpr(cur.expression);
    if (ts.isIdentifier(callee) && callee.text === "require") {
      const arg0 = cur.arguments[0];
      if (!arg0 || !ts.isStringLiteral(arg0)) {
        return ["\0nonliteral_require"];
      }
      const bare = normalizeModuleSpec(arg0.text);
      if (bare === "fs") return ["\0require_fs"];
      if (bare === "fs/promises") return ["\0require_fs_promises"];
      // Other literal requires are not fs namespace roots for method checks.
      return null;
    }
  }
  return null;
}

/**
 * Terminal property/element name of an expression, if statically known.
 * @param {ts.Expression} expr
 * @returns {string | null}
 */
function staticTerminalName(expr) {
  const cur = unwrapStaticExpr(expr);
  if (ts.isIdentifier(cur)) return cur.text;
  if (ts.isPropertyAccessExpression(cur)) return cur.name.text;
  if (ts.isElementAccessExpression(cur)) {
    const arg = cur.argumentExpression;
    if (arg && ts.isStringLiteral(arg)) return arg.text;
    return null;
  }
  return null;
}

/**
 * True when method name is an allowlisted read-only fs API for the namespace kind.
 * @param {string} method
 * @param {"fs" | "fs.promises"} [nsKind]
 * @returns {boolean}
 */
function isReadonlyFsMethod(method, nsKind = "fs") {
  if (nsKind === "fs.promises") return READONLY_FS_PROMISES_METHODS.has(method);
  return READONLY_FS_METHODS.has(method);
}

/**
 * True when name is a non-method meta property on the fs namespace.
 * @param {string} name
 * @returns {boolean}
 */
function isFsNamespaceMetaProperty(name) {
  return FS_NAMESPACE_META_PROPERTIES.has(name);
}

/**
 * Collect import-level provenance for Node `fs` namespaces and `fs.constants`.
 * Only named/default/namespace imports from `fs` / `node:fs` are recorded.
 * Names alone are not proof at a use site — see `isUnshadowedImportLocal`.
 * @param {ts.SourceFile} sf
 * @returns {{ fsConstantsLocals: Set<string>, fsNsAliases: Set<string> }}
 */
function collectFsFlagProvenance(sf) {
  /** @type {Set<string>} */
  const fsConstantsLocals = new Set();
  /** @type {Set<string>} */
  const fsNsAliases = new Set();
  for (const stmt of sf.statements) {
    if (!ts.isImportDeclaration(stmt) || !ts.isStringLiteral(stmt.moduleSpecifier)) {
      continue;
    }
    const bare = normalizeModuleSpec(stmt.moduleSpecifier.text);
    // constants live on the `fs` module (not `fs/promises`).
    if (bare !== "fs") continue;
    const clause = stmt.importClause;
    if (!clause) continue;
    if (clause.name) {
      fsNsAliases.add(clause.name.text);
    }
    if (!clause.namedBindings) continue;
    if (ts.isNamespaceImport(clause.namedBindings)) {
      fsNsAliases.add(clause.namedBindings.name.text);
    } else if (ts.isNamedImports(clause.namedBindings)) {
      for (const el of clause.namedBindings.elements) {
        const original = el.propertyName?.text ?? el.name.text;
        const local = el.name.text;
        if (original === "constants") {
          fsConstantsLocals.add(local);
        }
      }
    }
  }
  return { fsConstantsLocals, fsNsAliases };
}

/**
 * True when a BindingName (identifier or destructuring pattern) binds `name`.
 * @param {ts.BindingName} bindingName
 * @param {string} name
 * @returns {boolean}
 */
function bindingNameBinds(bindingName, name) {
  if (ts.isIdentifier(bindingName)) return bindingName.text === name;
  if (ts.isObjectBindingPattern(bindingName) || ts.isArrayBindingPattern(bindingName)) {
    for (const el of bindingName.elements) {
      if (ts.isOmittedExpression(el)) continue;
      if (ts.isBindingElement(el) && bindingNameBinds(el.name, name)) return true;
    }
  }
  return false;
}

/**
 * True when a variable declaration list binds `name`.
 * @param {ts.VariableDeclarationList} list
 * @param {string} name
 * @returns {boolean}
 */
function variableDeclarationListBinds(list, name) {
  for (const decl of list.declarations) {
    if (bindingNameBinds(decl.name, name)) return true;
  }
  return false;
}

/**
 * True when a statement introduces a lexical binding for `name` (not an import).
 * @param {ts.Statement} stmt
 * @param {string} name
 * @returns {boolean}
 */
function statementIntroducesLocalBinding(stmt, name) {
  if (ts.isVariableStatement(stmt)) {
    return variableDeclarationListBinds(stmt.declarationList, name);
  }
  if (ts.isFunctionDeclaration(stmt) && stmt.name && stmt.name.text === name) {
    return true;
  }
  if (ts.isClassDeclaration(stmt) && stmt.name && stmt.name.text === name) {
    return true;
  }
  return false;
}

/**
 * True when an ImportDeclaration binds local name `name`.
 * @param {ts.Statement} stmt
 * @param {string} name
 * @returns {boolean}
 */
function importDeclarationBinds(stmt, name) {
  if (!ts.isImportDeclaration(stmt) || !stmt.importClause) return false;
  const clause = stmt.importClause;
  if (clause.name && clause.name.text === name) return true;
  if (!clause.namedBindings) return false;
  if (ts.isNamespaceImport(clause.namedBindings)) {
    return clause.namedBindings.name.text === name;
  }
  if (ts.isNamedImports(clause.namedBindings)) {
    for (const el of clause.namedBindings.elements) {
      if (el.name.text === name) return true;
    }
  }
  return false;
}

/**
 * True when a `var` declaration of `name` appears in this function body (not in
 * a nested function). `var` is function-scoped, so it shadows imports for the
 * whole function even when declared in a nested block after the use site.
 * @param {ts.Node} fnNode
 * @param {string} name
 * @returns {boolean}
 */
function functionBodyHasVarBinding(fnNode, name) {
  const body = "body" in fnNode ? fnNode.body : undefined;
  if (!body) return false;
  let found = false;
  function walk(n) {
    if (found) return;
    if (
      n !== fnNode &&
      (ts.isFunctionDeclaration(n) ||
        ts.isFunctionExpression(n) ||
        ts.isArrowFunction(n) ||
        ts.isMethodDeclaration(n) ||
        ts.isConstructorDeclaration(n))
    ) {
      return;
    }
    if (ts.isVariableDeclarationList(n) && (n.flags & ts.NodeFlags.Let) === 0 && (n.flags & ts.NodeFlags.Const) === 0) {
      // Not let/const → var (or legacy).
      if (variableDeclarationListBinds(n, name)) {
        found = true;
        return;
      }
    }
    ts.forEachChild(n, walk);
  }
  walk(body);
  return found;
}

/**
 * True when a function-like node introduces a binding for `name` that is in
 * scope for uses in its body (parameters, function name, and function-scoped var).
 * @param {ts.Node} node
 * @param {string} name
 * @param {ts.Node} childFromUse — child on the path from the use site
 * @returns {boolean}
 */
function functionLikeShadowsName(node, name, childFromUse) {
  const isFn =
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node);
  if (!isFn) return false;

  // Function name is in scope inside the body (not on the name node itself).
  if (
    (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)) &&
    node.name &&
    node.name.text === name &&
    childFromUse !== node.name
  ) {
    return true;
  }

  const params = "parameters" in node ? node.parameters : undefined;
  if (params) {
    for (const p of params) {
      if (bindingNameBinds(p.name, name)) return true;
    }
  }

  if (functionBodyHasVarBinding(node, name)) return true;
  return false;
}

/**
 * True when an enclosing AST node introduces a nearer lexical binding for `name`
 * than the module import — parameters, catch bindings, function/class names,
 * block-local declarations, and for-loop variables.
 * @param {ts.Node} node
 * @param {string} name
 * @param {ts.Node} childFromUse
 * @returns {boolean}
 */
function enclosingNodeShadowsImport(node, name, childFromUse) {
  if (functionLikeShadowsName(node, name, childFromUse)) return true;

  if (ts.isCatchClause(node) && node.variableDeclaration) {
    if (bindingNameBinds(node.variableDeclaration.name, name)) return true;
  }

  if (
    (ts.isClassDeclaration(node) || ts.isClassExpression(node)) &&
    node.name &&
    node.name.text === name &&
    childFromUse !== node.name
  ) {
    return true;
  }

  // for (const name of/in …) / for (let name = …; …)
  if (ts.isForStatement(node) && node.initializer && ts.isVariableDeclarationList(node.initializer)) {
    if (variableDeclarationListBinds(node.initializer, name)) return true;
  }
  if (
    (ts.isForInStatement(node) || ts.isForOfStatement(node)) &&
    ts.isVariableDeclarationList(node.initializer)
  ) {
    if (variableDeclarationListBinds(node.initializer, name)) return true;
  }

  // Block / module body / case clause statement lists (lexical const/let/function/class).
  if (ts.isBlock(node) || ts.isModuleBlock(node)) {
    for (const stmt of node.statements) {
      if (statementIntroducesLocalBinding(stmt, name)) return true;
    }
  }
  if (ts.isCaseClause(node) || ts.isDefaultClause(node)) {
    for (const stmt of node.statements) {
      if (statementIntroducesLocalBinding(stmt, name)) return true;
    }
  }

  // Module scope: only non-import bindings shadow the import (rare / illegal collisions
  // still fail closed). Import bindings of the same name are the proven binding.
  if (ts.isSourceFile(node)) {
    for (const stmt of node.statements) {
      if (importDeclarationBinds(stmt, name)) continue;
      if (statementIntroducesLocalBinding(stmt, name)) return true;
    }
  }

  return false;
}

/**
 * Prove that an identifier at a use site is not lexically shadowed by any nearer
 * binding than the module scope. Used together with import-name sets: a name being
 * imported as `fs` / `constants` is necessary but not sufficient.
 * Fail closed for parameters, locals, catch bindings, function/class names, and
 * for-loop bindings that rebind the same identifier text.
 * @param {ts.Identifier} ident
 * @returns {boolean}
 */
function isUnshadowedImportLocal(ident) {
  const name = ident.text;
  let child = ident;
  let node = ident.parent;
  while (node) {
    if (enclosingNodeShadowsImport(node, name, child)) {
      return false;
    }
    if (ts.isSourceFile(node)) {
      return true;
    }
    child = node;
    node = node.parent;
  }
  return false;
}

/**
 * True when expr is statically Node's `fs` module namespace (import or require).
 * Import local names are accepted only when the identifier at the use site is
 * lexically unshadowed (shared provenance path).
 * @param {ts.Expression} expr
 * @param {Map<string, ts.Expression>} bindings
 * @param {{ fsConstantsLocals: Set<string>, fsNsAliases: Set<string> }} provenance
 * @param {Set<string>} visiting
 * @returns {boolean}
 */
function isProvenFsNamespace(expr, bindings, provenance, visiting = new Set()) {
  const cur = unwrapStaticExpr(expr);
  if (ts.isIdentifier(cur)) {
    // Import provenance requires lexical unshadowing at this exact use site.
    if (provenance.fsNsAliases.has(cur.text) && isUnshadowedImportLocal(cur)) {
      return true;
    }
    if (visiting.has(cur.text)) return false;
    const init = bindings.get(cur.text);
    if (!init) return false;
    visiting.add(cur.text);
    const ok = isProvenFsNamespace(init, bindings, provenance, visiting);
    visiting.delete(cur.text);
    return ok;
  }
  // require("fs") / require("node:fs")
  if (
    ts.isCallExpression(cur) &&
    ts.isIdentifier(cur.expression) &&
    cur.expression.text === "require"
  ) {
    const arg0 = cur.arguments[0];
    if (arg0 && ts.isStringLiteral(arg0) && normalizeModuleSpec(arg0.text) === "fs") {
      return true;
    }
  }
  return false;
}

/**
 * Resolve expression to a trusted `fs` / `fs.promises` namespace kind, or null.
 * Tracks unshadowed import/namespace bindings, require("fs"), simple local
 * aliases (`const f = fs; const g = f`), and `ns.promises` / `ns["promises"]`.
 * Parameters and other non-proven roots return null (no trusted provenance).
 *
 * @param {ts.Expression} expr
 * @param {Map<string, ts.Expression>} bindings
 * @param {{ fsConstantsLocals: Set<string>, fsNsAliases: Set<string> }} provenance
 * @param {Map<string, "fs" | "fs.promises" | "child_process">} nsAliases
 * @param {Set<string>} visiting
 * @returns {"fs" | "fs.promises" | null}
 */
function resolveTrustedFsNsKind(
  expr,
  bindings,
  provenance,
  nsAliases,
  visiting = new Set(),
) {
  const cur = unwrapStaticExpr(expr);
  if (ts.isIdentifier(cur)) {
    const importKind = nsAliases.get(cur.text);
    if (
      (importKind === "fs" || importKind === "fs.promises") &&
      isUnshadowedImportLocal(cur)
    ) {
      return importKind;
    }
    // Also accept default/namespace fs imports recorded only in flag provenance
    // when nsAliases missed an edge (should be rare); still require unshadowed.
    if (
      importKind !== "fs" &&
      importKind !== "fs.promises" &&
      provenance.fsNsAliases.has(cur.text) &&
      isUnshadowedImportLocal(cur)
    ) {
      return "fs";
    }
    if (visiting.has(cur.text)) return null;
    const init = bindings.get(cur.text);
    if (!init) return null;
    visiting.add(cur.text);
    const kind = resolveTrustedFsNsKind(init, bindings, provenance, nsAliases, visiting);
    visiting.delete(cur.text);
    return kind;
  }
  if (
    ts.isCallExpression(cur) &&
    ts.isIdentifier(cur.expression) &&
    cur.expression.text === "require"
  ) {
    const arg0 = cur.arguments[0];
    if (arg0 && ts.isStringLiteral(arg0)) {
      const bare = normalizeModuleSpec(arg0.text);
      if (bare === "fs") return "fs";
      if (bare === "fs/promises") return "fs.promises";
    }
    return null;
  }
  if (ts.isPropertyAccessExpression(cur) && cur.name.text === "promises") {
    const base = resolveTrustedFsNsKind(
      cur.expression,
      bindings,
      provenance,
      nsAliases,
      visiting,
    );
    return base === "fs" ? "fs.promises" : null;
  }
  if (ts.isElementAccessExpression(cur)) {
    const arg = cur.argumentExpression;
    if (arg && ts.isStringLiteral(arg) && arg.text === "promises") {
      const base = resolveTrustedFsNsKind(
        cur.expression,
        bindings,
        provenance,
        nsAliases,
        visiting,
      );
      return base === "fs" ? "fs.promises" : null;
    }
  }
  return null;
}

/**
 * Leftmost root of a property/element access chain (after unwrap).
 * @param {ts.Expression} expr
 * @returns {ts.Expression}
 */
function leftmostMemberRoot(expr) {
  let cur = unwrapStaticExpr(expr);
  for (;;) {
    if (ts.isPropertyAccessExpression(cur)) {
      cur = unwrapStaticExpr(cur.expression);
      continue;
    }
    if (ts.isElementAccessExpression(cur)) {
      cur = unwrapStaticExpr(cur.expression);
      continue;
    }
    return cur;
  }
}

/**
 * Collect simple const/let/var bindings visible at `node`, merging module scope
 * into nested callables when the local scope does not rebind a name.
 * @param {ts.Node} node
 * @param {ts.SourceFile} sf
 * @returns {Map<string, ts.Expression>}
 */
function bindingsForNode(node, sf) {
  const scope = enclosingCallableOrSourceFile(node);
  const bindings = collectSimpleBindings(scope);
  if (!ts.isSourceFile(scope)) {
    const moduleBindings = collectSimpleBindings(sf);
    for (const [k, v] of moduleBindings) {
      if (!bindings.has(k)) bindings.set(k, v);
    }
  }
  return bindings;
}

/**
 * Original property name for an object binding element, if statically known.
 * @param {ts.BindingElement} el
 * @returns {string | null}
 */
function bindingElementStaticPropertyName(el) {
  if (el.dotDotDotToken) return null;
  if (el.propertyName) {
    if (ts.isIdentifier(el.propertyName)) return el.propertyName.text;
    if (ts.isStringLiteral(el.propertyName) || ts.isNoSubstitutionTemplateLiteral(el.propertyName)) {
      return el.propertyName.text;
    }
    return null;
  }
  if (ts.isIdentifier(el.name)) return el.name.text;
  return null;
}

/**
 * Collect destructured fs method aliases under a scope root
 * (`const { writeFileSync } = fs`, `const { writeFileSync: write } = f`).
 * @param {ts.Node} scopeRoot
 * @param {Map<string, ts.Expression>} bindings
 * @param {{ fsConstantsLocals: Set<string>, fsNsAliases: Set<string> }} provenance
 * @param {Map<string, "fs" | "fs.promises" | "child_process">} nsAliases
 * @returns {Map<string, { original: string, nsKind: "fs" | "fs.promises" }>}
 */
function collectDestructuredFsMethodAliases(scopeRoot, bindings, provenance, nsAliases) {
  /** @type {Map<string, { original: string, nsKind: "fs" | "fs.promises" }>} */
  const map = new Map();
  function visit(node) {
    if (
      node !== scopeRoot &&
      (ts.isFunctionDeclaration(node) ||
        ts.isFunctionExpression(node) ||
        ts.isArrowFunction(node) ||
        ts.isMethodDeclaration(node) ||
        ts.isConstructorDeclaration(node))
    ) {
      return;
    }
    if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      ts.isObjectBindingPattern(node.name)
    ) {
      const nsKind = resolveTrustedFsNsKind(
        node.initializer,
        bindings,
        provenance,
        nsAliases,
      );
      if (nsKind === "fs" || nsKind === "fs.promises") {
        for (const el of node.name.elements) {
          if (ts.isOmittedExpression(el) || !ts.isBindingElement(el)) continue;
          if (!ts.isIdentifier(el.name)) continue;
          const original = bindingElementStaticPropertyName(el);
          if (!original) continue;
          // Track non-read-only / open extracts for call-site alias resolution.
          if (isFsCapabilityMethod(original, nsKind)) {
            map.set(el.name.text, { original, nsKind });
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(scopeRoot);
  return map;
}

/**
 * True when some binding of `name` is nearer than module scope (parameter,
 * catch, block-local, for-loop, nested function name, etc.). Module-level
 * const/let/function bindings are the target binding for local aliases and
 * are not treated as shadows here (unlike import-local checks).
 * @param {ts.Identifier} ident
 * @returns {boolean}
 */
function isShadowedRelativeToModuleBinding(ident) {
  const name = ident.text;
  let child = ident;
  let node = ident.parent;
  while (node) {
    if (ts.isSourceFile(node)) {
      return false;
    }
    if (functionLikeShadowsName(node, name, child)) {
      return true;
    }
    if (ts.isCatchClause(node) && node.variableDeclaration) {
      if (bindingNameBinds(node.variableDeclaration.name, name)) return true;
    }
    if (
      (ts.isClassDeclaration(node) || ts.isClassExpression(node)) &&
      node.name &&
      node.name.text === name &&
      child !== node.name
    ) {
      return true;
    }
    if (ts.isForStatement(node) && node.initializer && ts.isVariableDeclarationList(node.initializer)) {
      if (variableDeclarationListBinds(node.initializer, name)) return true;
    }
    if (
      (ts.isForInStatement(node) || ts.isForOfStatement(node)) &&
      ts.isVariableDeclarationList(node.initializer)
    ) {
      if (variableDeclarationListBinds(node.initializer, name)) return true;
    }
    if (ts.isBlock(node) || ts.isModuleBlock(node)) {
      for (const stmt of node.statements) {
        if (statementIntroducesLocalBinding(stmt, name)) return true;
      }
    }
    if (ts.isCaseClause(node) || ts.isDefaultClause(node)) {
      for (const stmt of node.statements) {
        if (statementIntroducesLocalBinding(stmt, name)) return true;
      }
    }
    child = node;
    node = node.parent;
  }
  return false;
}

/**
 * Resolve a bare identifier callee to a destructured (or simple property-copy)
 * fs method alias visible at the use site. Returns null when the name is a
 * simple local rebinding, a parameter/catch shadow, or otherwise unproven.
 * @param {ts.Identifier} ident
 * @param {ts.Node} callNode
 * @param {ts.SourceFile} sf
 * @param {Map<string, ts.Expression>} bindings
 * @param {{ fsConstantsLocals: Set<string>, fsNsAliases: Set<string> }} provenance
 * @param {Map<string, "fs" | "fs.promises" | "child_process">} nsAliases
 * @returns {{ original: string, nsKind: "fs" | "fs.promises" } | null}
 */
function resolveLocalFsMethodAlias(
  ident,
  callNode,
  sf,
  bindings,
  provenance,
  nsAliases,
) {
  const name = ident.text;

  // Simple `const write = fs.writeFileSync` / `const write = f.writeFileSync`.
  // A nearer simple binding always wins over outer destructuring.
  if (bindings.has(name)) {
    const init = unwrapStaticExpr(bindings.get(name));
    if (ts.isPropertyAccessExpression(init) || ts.isElementAccessExpression(init)) {
      const method = staticTerminalName(init);
      const base = propertyAccessBase(init);
      if (method && base && method !== "\0computed") {
        const nsKind = resolveTrustedFsNsKind(base, bindings, provenance, nsAliases);
        if (
          (nsKind === "fs" || nsKind === "fs.promises") &&
          isFsCapabilityMethod(method, nsKind)
        ) {
          return { original: method, nsKind };
        }
      }
    }
    // Identifier rebound to a non-method expression — not a method alias.
    return null;
  }

  // Nearest-scope destructuring: function body first, then module.
  const scope = enclosingCallableOrSourceFile(callNode);
  if (!ts.isSourceFile(scope)) {
    const localMap = collectDestructuredFsMethodAliases(
      scope,
      bindings,
      provenance,
      nsAliases,
    );
    if (localMap.has(name)) return localMap.get(name) ?? null;
  }

  // Parameter / catch / block / for shadows must not inherit module destructuring.
  if (isShadowedRelativeToModuleBinding(ident)) {
    return null;
  }

  const moduleBindings = collectSimpleBindings(sf);
  const moduleMap = collectDestructuredFsMethodAliases(
    sf,
    moduleBindings,
    provenance,
    nsAliases,
  );
  return moduleMap.get(name) ?? null;
}

/**
 * True when expr is statically Node's `fs.constants` object.
 * Accepts unshadowed `import { constants as c } from "node:fs"`, unshadowed
 * `fs.constants`, and simple aliases of those forms. Rejects object literals,
 * parameters, shadowed import locals, and unknown namespaces even when a later
 * property is named O_RDONLY.
 * @param {ts.Expression} expr
 * @param {Map<string, ts.Expression>} bindings
 * @param {{ fsConstantsLocals: Set<string>, fsNsAliases: Set<string> }} provenance
 * @param {Set<string>} visiting
 * @returns {boolean}
 */
function isProvenFsConstantsRoot(expr, bindings, provenance, visiting = new Set()) {
  const cur = unwrapStaticExpr(expr);
  if (ts.isIdentifier(cur)) {
    // Import provenance requires lexical unshadowing at this exact use site.
    if (provenance.fsConstantsLocals.has(cur.text) && isUnshadowedImportLocal(cur)) {
      return true;
    }
    if (visiting.has(cur.text)) return false;
    const init = bindings.get(cur.text);
    if (!init) return false;
    visiting.add(cur.text);
    const ok = isProvenFsConstantsRoot(init, bindings, provenance, visiting);
    visiting.delete(cur.text);
    return ok;
  }
  // fs.constants / require("fs").constants / ns["constants"]
  if (ts.isPropertyAccessExpression(cur) && cur.name.text === "constants") {
    return isProvenFsNamespace(cur.expression, bindings, provenance, visiting);
  }
  if (ts.isElementAccessExpression(cur)) {
    const arg = cur.argumentExpression;
    if (arg && ts.isStringLiteral(arg) && arg.text === "constants") {
      return isProvenFsNamespace(cur.expression, bindings, provenance, visiting);
    }
  }
  return false;
}

/**
 * Base expression of a property/element access, if any.
 * @param {ts.Expression} expr
 * @returns {ts.Expression | null}
 */
function propertyAccessBase(expr) {
  const cur = unwrapStaticExpr(expr);
  if (ts.isPropertyAccessExpression(cur)) return cur.expression;
  if (ts.isElementAccessExpression(cur)) return cur.expression;
  return null;
}

/**
 * True when `expr` is the immediate callee expression of a CallExpression
 * (direct call). Parenthesized / sequenced / bound / Reflect.apply forms are
 * not direct callees of the capability itself.
 * @param {ts.Expression} expr
 * @returns {boolean}
 */
function isDirectCallExpressionCallee(expr) {
  const parent = expr.parent;
  return Boolean(parent && ts.isCallExpression(parent) && parent.expression === expr);
}

/**
 * True when an identifier is used as a value-level capability reference
 * (alias, pass, sequence operand, etc.), not as a declaration name or type.
 * @param {ts.Identifier} id
 * @returns {boolean}
 */
function isForbiddenCapabilityIdentifierUse(id) {
  const p = id.parent;
  if (!p) return false;

  // Declaration / binding names are not value acquisitions of the global.
  if ("name" in p && /** @type {{ name?: ts.Node }} */ (p).name === id) {
    if (
      ts.isFunctionDeclaration(p) ||
      ts.isFunctionExpression(p) ||
      ts.isClassDeclaration(p) ||
      ts.isClassExpression(p) ||
      ts.isMethodDeclaration(p) ||
      ts.isPropertyDeclaration(p) ||
      ts.isParameter(p) ||
      ts.isBindingElement(p) ||
      ts.isVariableDeclaration(p) ||
      ts.isPropertyAssignment(p) ||
      ts.isShorthandPropertyAssignment(p) ||
      ts.isPropertySignature(p) ||
      ts.isMethodSignature(p) ||
      ts.isEnumMember(p) ||
      ts.isInterfaceDeclaration(p) ||
      ts.isTypeAliasDeclaration(p) ||
      ts.isNamespaceImport(p) ||
      ts.isImportClause(p)
    ) {
      return false;
    }
  }
  if (ts.isImportSpecifier(p) && (p.name === id || p.propertyName === id)) {
    // Named import of createRequire still acquires the loader capability.
    return FORBIDDEN_LOADER_APIS.has(id.text);
  }
  if (ts.isExportSpecifier(p) && (p.name === id || p.propertyName === id)) {
    return false;
  }

  // Skip pure type positions (const x: Function, type aliases, etc.).
  let cur = /** @type {ts.Node} */ (id);
  while (cur.parent) {
    const parent = cur.parent;
    if (typeof ts.isTypeNode === "function" && ts.isTypeNode(parent)) {
      return false;
    }
    if (ts.isTypeReferenceNode(parent) && parent.typeName === cur) {
      return false;
    }
    if (ts.isExpressionWithTypeArguments(parent) && parent.expression === cur) {
      const h = parent.parent;
      if (h && ts.isHeritageClause(h)) {
        if (h.token === ts.SyntaxKind.ImplementsKeyword) return false;
        if (h.parent && ts.isInterfaceDeclaration(h.parent)) return false;
      }
    }
    if (
      ts.isCallExpression(parent) ||
      ts.isNewExpression(parent) ||
      ts.isVariableDeclaration(parent) ||
      ts.isBinaryExpression(parent) ||
      ts.isPropertyAccessExpression(parent) ||
      ts.isElementAccessExpression(parent) ||
      ts.isParenthesizedExpression(parent) ||
      ts.isAsExpression(parent) ||
      ts.isNonNullExpression(parent) ||
      ts.isArrayLiteralExpression(parent) ||
      ts.isObjectLiteralExpression(parent) ||
      ts.isReturnStatement(parent) ||
      ts.isExpressionStatement(parent) ||
      ts.isSourceFile(parent) ||
      ts.isBlock(parent)
    ) {
      break;
    }
    cur = parent;
  }
  return true;
}

/**
 * True when method on a proven fs namespace is a capability that must be
 * policed: conditional open, or anything not on the read-only allowlist.
 * Meta properties (`promises`, `constants`) are not method capabilities.
 * @param {string} method
 * @param {"fs" | "fs.promises"} [nsKind]
 * @returns {boolean}
 */
function isFsCapabilityMethod(method, nsKind = "fs") {
  if (!method || method === "\0computed") return true;
  if (isFsNamespaceMetaProperty(method)) return false;
  if (CONDITIONAL_OPEN_METHODS.has(method)) return true;
  return !isReadonlyFsMethod(method, nsKind);
}

/**
 * Collect simple const/let/var bindings (name → initializer) under a scope root.
 * @param {ts.Node} scopeRoot
 * @returns {Map<string, ts.Expression>}
 */
function collectSimpleBindings(scopeRoot) {
  /** @type {Map<string, ts.Expression>} */
  const map = new Map();
  function visit(node) {
    // Do not descend into nested function bodies (their bindings are separate).
    if (
      node !== scopeRoot &&
      (ts.isFunctionDeclaration(node) ||
        ts.isFunctionExpression(node) ||
        ts.isArrowFunction(node) ||
        ts.isMethodDeclaration(node) ||
        ts.isConstructorDeclaration(node))
    ) {
      return;
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      map.set(node.name.text, node.initializer);
    }
    ts.forEachChild(node, visit);
  }
  visit(scopeRoot);
  return map;
}

/**
 * @param {ts.Node} node
 * @returns {ts.Node}
 */
function enclosingCallableOrSourceFile(node) {
  let cur = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isMethodDeclaration(cur)
    ) {
      return cur;
    }
    if (ts.isSourceFile(cur)) return cur;
    cur = cur.parent;
  }
  return node.getSourceFile();
}

/**
 * True when every return of a same-file named function is a read-only open-flags expression.
 * @param {string} name
 * @param {ts.SourceFile} sf
 * @param {{ fsConstantsLocals: Set<string>, fsNsAliases: Set<string> }} provenance
 * @param {Set<string>} visiting
 * @returns {boolean}
 */
function namedFunctionReturnsOnlyReadonlyFlags(name, sf, provenance, visiting) {
  if (visiting.has(name)) return false;
  visiting.add(name);
  /** @type {ts.FunctionDeclaration[]} */
  const decls = [];
  function find(node) {
    if (ts.isFunctionDeclaration(node) && node.name && node.name.text === name && node.body) {
      decls.push(node);
    }
    ts.forEachChild(node, find);
  }
  find(sf);
  if (decls.length === 0) {
    visiting.delete(name);
    return false;
  }
  for (const decl of decls) {
    const bindings = collectSimpleBindings(decl);
    // Merge module-level bindings so helpers can close over imports / consts.
    const moduleBindings = collectSimpleBindings(sf);
    for (const [k, v] of moduleBindings) {
      if (!bindings.has(k)) bindings.set(k, v);
    }
    /** @type {ts.Expression[]} */
    const returns = [];
    function walkReturns(node) {
      if (
        node !== decl &&
        (ts.isFunctionDeclaration(node) ||
          ts.isFunctionExpression(node) ||
          ts.isArrowFunction(node) ||
          ts.isMethodDeclaration(node))
      ) {
        return;
      }
      if (ts.isReturnStatement(node) && node.expression) {
        returns.push(node.expression);
      }
      ts.forEachChild(node, walkReturns);
    }
    walkReturns(decl);
    if (returns.length === 0) {
      visiting.delete(name);
      return false;
    }
    for (const ret of returns) {
      if (!isStaticallyReadonlyOpenFlags(ret, bindings, sf, provenance, visiting)) {
        visiting.delete(name);
        return false;
      }
    }
  }
  visiting.delete(name);
  return true;
}

/**
 * Statically prove that an open flags expression cannot grant write capability.
 * Fail closed on unknown shapes (identifiers without binding, numerics, objects, …).
 * Read-only flag properties are accepted only when their object root is proven
 * to be Node `fs.constants` (shared flag-provenance evaluator).
 * @param {ts.Expression | undefined} expr
 * @param {Map<string, ts.Expression>} bindings
 * @param {ts.SourceFile} sf
 * @param {{ fsConstantsLocals: Set<string>, fsNsAliases: Set<string> }} provenance
 * @param {Set<string>} visitingFns
 * @returns {boolean}
 */
function isStaticallyReadonlyOpenFlags(
  expr,
  bindings,
  sf,
  provenance,
  visitingFns = new Set(),
) {
  if (!expr) {
    // open(path) defaults to read-only "r".
    return true;
  }
  if (ts.isParenthesizedExpression(expr)) {
    return isStaticallyReadonlyOpenFlags(
      expr.expression,
      bindings,
      sf,
      provenance,
      visitingFns,
    );
  }
  // `expr as T` and legacy `<T>expr` both expose `.expression`.
  if (
    ts.isAsExpression(expr) ||
    ts.isNonNullExpression(expr) ||
    (ts.isTypeAssertionExpression && ts.isTypeAssertionExpression(expr))
  ) {
    return isStaticallyReadonlyOpenFlags(
      expr.expression,
      bindings,
      sf,
      provenance,
      visitingFns,
    );
  }
  if (expr.kind === ts.SyntaxKind.TypeAssertionExpression && "expression" in expr) {
    return isStaticallyReadonlyOpenFlags(
      /** @type {ts.TypeAssertion} */ (expr).expression,
      bindings,
      sf,
      provenance,
      visitingFns,
    );
  }
  if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
    return READ_ONLY_STRING_MODES.has(expr.text);
  }
  if (ts.isNumericLiteral(expr)) {
    // Numeric flags are not proven read-only (O_RDONLY is 0 on some platforms,
    // but any other value may enable write); fail closed.
    return false;
  }
  if (ts.isPrefixUnaryExpression(expr)) {
    return false;
  }
  if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.BarToken) {
    return (
      isStaticallyReadonlyOpenFlags(expr.left, bindings, sf, provenance, visitingFns) &&
      isStaticallyReadonlyOpenFlags(expr.right, bindings, sf, provenance, visitingFns)
    );
  }
  if (ts.isConditionalExpression(expr)) {
    return (
      isStaticallyReadonlyOpenFlags(expr.whenTrue, bindings, sf, provenance, visitingFns) &&
      isStaticallyReadonlyOpenFlags(expr.whenFalse, bindings, sf, provenance, visitingFns)
    );
  }
  if (ts.isIdentifier(expr)) {
    if (expr.text === "undefined") return true;
    const init = bindings.get(expr.text);
    if (!init) return false;
    return isStaticallyReadonlyOpenFlags(init, bindings, sf, provenance, visitingFns);
  }
  if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) {
    const term = staticTerminalName(expr);
    if (!term || term === "\0computed") return false;
    if (WRITE_CAPABLE_FLAG_NAMES.has(term)) return false;
    if (READ_ONLY_FLAG_NAMES.has(term)) {
      // Shared flag-provenance evaluator: terminal name alone is never enough.
      const base = propertyAccessBase(expr);
      if (!base) return false;
      return isProvenFsConstantsRoot(base, bindings, provenance);
    }
    return false;
  }
  if (ts.isCallExpression(expr) && ts.isIdentifier(expr.expression)) {
    // Same-file helper that only returns allowlisted read-only flag expressions
    // (production path-safety openReadNoFollowFlags pattern).
    return namedFunctionReturnsOnlyReadonlyFlags(
      expr.expression.text,
      sf,
      provenance,
      visitingFns,
    );
  }
  // Object-form options, spreads, await, etc. — fail closed.
  return false;
}

/**
 * @param {string} rel
 * @param {string} methodLabel
 * @param {ts.Expression | undefined} flagsExpr
 * @param {ts.Node} callNode
 * @param {ts.SourceFile} sf
 * @param {{ fsConstantsLocals: Set<string>, fsNsAliases: Set<string> }} provenance
 * @returns {string | null} violation message or null if allowed
 */
function checkOpenCallFlags(rel, methodLabel, flagsExpr, callNode, sf, provenance) {
  const scope = enclosingCallableOrSourceFile(callNode);
  const bindings = collectSimpleBindings(scope);
  // Merge module-level bindings for nested functions (helpers often close over imports).
  if (!ts.isSourceFile(scope)) {
    const moduleBindings = collectSimpleBindings(sf);
    for (const [k, v] of moduleBindings) {
      if (!bindings.has(k)) bindings.set(k, v);
    }
  }
  if (isStaticallyReadonlyOpenFlags(flagsExpr, bindings, sf, provenance)) {
    return null;
  }
  return `${rel}: fs open without statically provable read-only flags ('${methodLabel}')`;
}

/**
 * @param {string} file
 * @param {string} text
 * @param {string} rel
 * @returns {string[]}
 */
function scanSourceText(file, text, rel) {
  /** @type {string[]} */
  const violations = [];
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
  // Import-level provenance for open-flag property roots (fs.constants only).
  const flagProvenance = collectFsFlagProvenance(sf);

  /** Names bound to fs / fs.promises namespaces or default imports. */
  /** @type {Map<string, "fs" | "fs.promises" | "child_process">} */
  const nsAliases = new Map();
  /** Local name → original method for named fs imports. */
  /** @type {Map<string, string>} */
  const namedFsMethods = new Map();
  /** Local names for child_process named methods. */
  /** @type {Map<string, string>} */
  const namedChildMethods = new Map();
  /** Identifiers known to alias process (rare; process is global). */
  /** @type {Set<string>} */
  const processAliases = new Set(["process"]);

  /**
   * @param {ts.ImportClause | undefined} clause
   * @param {string} bare
   */
  function recordImportBindings(clause, bare) {
    if (!clause) return;
    if (bare === "fs" || bare === "fs/promises") {
      const kind = bare === "fs/promises" ? "fs.promises" : "fs";
      if (clause.name) {
        // default import: import fs from "node:fs"
        nsAliases.set(clause.name.text, kind);
      }
      if (clause.namedBindings) {
        if (ts.isNamespaceImport(clause.namedBindings)) {
          nsAliases.set(clause.namedBindings.name.text, kind);
        } else if (ts.isNamedImports(clause.namedBindings)) {
          for (const el of clause.namedBindings.elements) {
            const original = el.propertyName?.text ?? el.name.text;
            const local = el.name.text;
            if (kind === "fs" && original === "promises") {
              // import { promises as fsp } from "fs"
              nsAliases.set(local, "fs.promises");
            } else if (kind === "fs" && original === "constants") {
              // import { constants as c } — not a method; flag provenance owns it.
            } else if (CONDITIONAL_OPEN_METHODS.has(original)) {
              // Named open/openSync import is an unproven open capability extract.
              namedFsMethods.set(local, original);
              violations.push(
                `${rel}: forbidden unproven fs open import '${original}' as '${local}'`,
              );
            } else if (!isReadonlyFsMethod(original, kind)) {
              namedFsMethods.set(local, original);
              violations.push(
                `${rel}: forbidden non-read-only fs import '${original}' as '${local}'`,
              );
            } else {
              namedFsMethods.set(local, original);
            }
          }
        }
      }
    }
    if (bare === "child_process") {
      if (clause.name) {
        nsAliases.set(clause.name.text, "child_process");
      }
      if (clause.namedBindings) {
        if (ts.isNamespaceImport(clause.namedBindings)) {
          nsAliases.set(clause.namedBindings.name.text, "child_process");
        } else if (ts.isNamedImports(clause.namedBindings)) {
          for (const el of clause.namedBindings.elements) {
            const original = el.propertyName?.text ?? el.name.text;
            const local = el.name.text;
            namedChildMethods.set(local, original);
            if (FORBIDDEN_CHILD_METHODS.has(original)) {
              violations.push(
                `${rel}: forbidden child_process import '${original}' as '${local}'`,
              );
            }
          }
        }
      }
    }
  }

  function checkModuleSpec(spec, kind) {
    if (isForbiddenModule(spec)) {
      violations.push(`${rel}: forbidden ${kind} '${spec}'`);
    }
  }

  /**
   * Apply fs method policy for a resolved namespace kind and method name.
   * @param {"fs" | "fs.promises"} nsKind
   * @param {string} method
   * @param {string} displayRoot
   * @param {readonly ts.Expression[] | undefined} args
   * @param {ts.Node} callNode
   */
  function checkFsMethod(nsKind, method, displayRoot, args, callNode) {
    if (method === "\0computed") {
      violations.push(`${rel}: computed fs method call (fail-closed)`);
      return;
    }
    if (isFsNamespaceMetaProperty(method)) {
      // `fs.promises` / `fs.constants` as a bare value callee is not a method call.
      return;
    }
    if (CONDITIONAL_OPEN_METHODS.has(method)) {
      // open(path, flags?) / openSync(path, flags?) — second arg is flags/mode string.
      const flagsExpr = args && args.length >= 2 ? args[1] : undefined;
      const msg = checkOpenCallFlags(
        rel,
        `${displayRoot}.${method}`,
        flagsExpr,
        callNode,
        sf,
        flagProvenance,
      );
      if (msg) violations.push(msg);
      return;
    }
    if (!isReadonlyFsMethod(method, nsKind)) {
      violations.push(
        `${rel}: forbidden non-read-only fs method '${displayRoot}.${method}'`,
      );
    }
  }

  /**
   * Report a property/element access that resolves to a forbidden mutation or
   * open capability on a proven fs namespace, when it is not the direct callee
   * of a CallExpression (call policy is owned by checkCallOrNew / checkFsMethod).
   * @param {ts.PropertyAccessExpression | ts.ElementAccessExpression} access
   */
  function checkFsCapabilityReference(access) {
    if (isDirectCallExpressionCallee(access)) {
      return;
    }
    const refBindings = bindingsForNode(access, sf);
    const base = propertyAccessBase(access);
    if (!base) return;

    let method = staticTerminalName(access);
    if (method === null && ts.isElementAccessExpression(access)) {
      // Non-literal computed key on a proven fs namespace: fail closed.
      const nsKindComputed = resolveTrustedFsNsKind(
        base,
        refBindings,
        flagProvenance,
        nsAliases,
      );
      if (nsKindComputed === "fs" || nsKindComputed === "fs.promises") {
        violations.push(`${rel}: computed fs capability reference (fail-closed)`);
        return;
      }
      // require("fs")[dyn] via member chain root
      const chain = resolveMemberChain(access);
      if (
        chain &&
        chain.length >= 2 &&
        (chain[0] === "\0require_fs" || chain[0] === "\0require_fs_promises") &&
        chain[chain.length - 1] === "\0computed"
      ) {
        violations.push(`${rel}: computed fs capability reference (fail-closed)`);
      }
      return;
    }
    if (!method || method === "\0computed") {
      if (method === "\0computed") {
        const nsKindComputed = resolveTrustedFsNsKind(
          base,
          refBindings,
          flagProvenance,
          nsAliases,
        );
        if (nsKindComputed === "fs" || nsKindComputed === "fs.promises") {
          violations.push(`${rel}: computed fs capability reference (fail-closed)`);
        }
      }
      return;
    }

    let nsKind = resolveTrustedFsNsKind(base, refBindings, flagProvenance, nsAliases);
    if (nsKind !== "fs" && nsKind !== "fs.promises") {
      // require("fs").writeFileSync / require("node:fs").promises.writeFile
      const chain = resolveMemberChain(access);
      if (chain && chain.length >= 2) {
        if (chain[0] === "\0require_fs") {
          if (chain.length >= 3 && chain[1] === "promises") {
            nsKind = "fs.promises";
            method = chain[2];
          } else {
            nsKind = "fs";
            method = chain[1];
          }
        } else if (chain[0] === "\0require_fs_promises") {
          nsKind = "fs.promises";
          method = chain[1];
        } else if (chain[0] === "\0nonliteral_require") {
          violations.push(`${rel}: non-literal require capability reference (fail-closed)`);
          return;
        }
      }
    }
    if (nsKind !== "fs" && nsKind !== "fs.promises") {
      // Import-map fallback for unshadowed namespace roots only when expression
      // root maps to fs (mirrors call-site fail-closed capability policy).
      const chain = resolveMemberChain(access);
      if (chain && chain.length >= 2) {
        const mapped = nsAliases.get(chain[0]);
        if (mapped === "fs" || mapped === "fs.promises") {
          nsKind = mapped;
          if (nsKind === "fs" && chain.length >= 3 && chain[1] === "promises") {
            nsKind = "fs.promises";
            method = chain[2];
          } else if (!(nsKind === "fs" && chain[1] === "promises")) {
            method = chain[1];
          } else {
            return;
          }
        }
      }
    }
    if (nsKind !== "fs" && nsKind !== "fs.promises") {
      return;
    }
    if (!isFsCapabilityMethod(method, nsKind)) {
      return;
    }
    if (CONDITIONAL_OPEN_METHODS.has(method)) {
      violations.push(
        `${rel}: forbidden unproven fs open capability reference '${method}'`,
      );
    } else {
      violations.push(`${rel}: forbidden fs capability reference '${method}'`);
    }
  }

  /**
   * @param {ts.Expression} callee
   * @param {boolean} isNew
   * @param {readonly ts.Expression[] | undefined} args
   * @param {ts.Node} callNode
   */
  function checkCallOrNew(callee, isNew, args, callNode) {
    const callBindings = bindingsForNode(callNode, sf);
    // Unwrap as/non-null/paren/comma so (0, eval), (fs as any).m, etc. share policy.
    const bareCallee = unwrapStaticExpr(callee);

    // Direct identifier callees (eval, Function, fetch, named imports, local aliases).
    if (ts.isIdentifier(bareCallee)) {
      const name = bareCallee.text;
      if (FORBIDDEN_GLOBALS.has(name)) {
        violations.push(`${rel}: forbidden global '${name}'`);
      }
      if (FORBIDDEN_CODE_EXEC_GLOBALS.has(name)) {
        violations.push(
          name === "eval"
            ? `${rel}: forbidden eval()`
            : `${rel}: forbidden Function constructor`,
        );
      }
      if (FORBIDDEN_LOADER_APIS.has(name)) {
        violations.push(`${rel}: forbidden loader API '${name}'`);
      }
      if (namedFsMethods.has(name)) {
        const original = namedFsMethods.get(name);
        if (CONDITIONAL_OPEN_METHODS.has(original)) {
          // open/openSync may only be a direct call through a proven namespace;
          // a named import / local name is unproven even with read-only flags.
          violations.push(`${rel}: forbidden unproven fs open call '${name}'`);
        } else if (!isReadonlyFsMethod(original, "fs")) {
          violations.push(`${rel}: forbidden fs call '${name}'`);
        }
      } else {
        // Destructuring / property-copy aliases: const { writeFileSync } = fs;
        // const { writeFileSync: write } = fs; const write = fs.writeFileSync;
        const localAlias = resolveLocalFsMethodAlias(
          bareCallee,
          callNode,
          sf,
          callBindings,
          flagProvenance,
          nsAliases,
        );
        if (localAlias) {
          const { original, nsKind } = localAlias;
          if (CONDITIONAL_OPEN_METHODS.has(original)) {
            // Extracted / property-copied open is unproven; do not accept flags.
            violations.push(`${rel}: forbidden unproven fs open call '${name}'`);
          } else if (!isReadonlyFsMethod(original, nsKind)) {
            violations.push(`${rel}: forbidden fs call '${name}'`);
          }
        }
      }
      if (
        namedChildMethods.has(name) &&
        FORBIDDEN_CHILD_METHODS.has(namedChildMethods.get(name))
      ) {
        violations.push(`${rel}: forbidden child_process call '${name}'`);
      }
    }

    const chain = resolveMemberChain(callee);
    if (!chain || chain.length === 0) {
      return;
    }

    // Single-ident chain already handled above for Identifier callees.
    // eval via globalThis["eval"] / globalThis.eval
    if (
      (chain[0] === "globalThis" || chain[0] === "global" || chain[0] === "window") &&
      chain.length >= 2
    ) {
      const prop = chain[1];
      if (prop === "\0computed") {
        violations.push(`${rel}: computed globalThis property call (fail-closed)`);
        return;
      }
      if (
        FORBIDDEN_GLOBALS.has(prop) ||
        FORBIDDEN_CODE_EXEC_GLOBALS.has(prop) ||
        FORBIDDEN_LOADER_APIS.has(prop)
      ) {
        violations.push(`${rel}: forbidden ${chain[0]}.${prop}`);
      }
    }

    // process.dlopen / process.binding
    if (processAliases.has(chain[0]) && chain.length >= 2) {
      const method = chain[1];
      if (method === "\0computed") {
        violations.push(`${rel}: computed process property call (fail-closed)`);
      } else if (FORBIDDEN_PROCESS_METHODS.has(method)) {
        violations.push(`${rel}: forbidden process.${method}`);
      }
    }

    // Direct require("fs") / require("node:fs") member chains
    if (chain[0] === "\0nonliteral_require") {
      // Already reported at require() call; still fail closed on method chain.
      if (chain.length >= 2) {
        violations.push(`${rel}: non-literal require member call (fail-closed)`);
      }
      return;
    }
    if (chain[0] === "\0require_fs") {
      if (chain.length >= 3 && chain[1] === "promises") {
        checkFsMethod("fs.promises", chain[2], "require(...).promises", args, callNode);
      } else if (chain.length >= 2) {
        checkFsMethod("fs", chain[1], "require(...)", args, callNode);
      }
      return;
    }
    if (chain[0] === "\0require_fs_promises") {
      if (chain.length >= 2) {
        checkFsMethod("fs.promises", chain[1], "require(...)", args, callNode);
      }
      return;
    }

    // Namespace fs / fs.promises — import locals, simple aliases, chained aliases.
    // Prefer expression-level proven aliases (`const f = fs; f.writeFileSync`).
    // Fall back to import-map names without requiring unshadowed use: a parameter
    // that rebinds `fs` must not gain trusted *flag* provenance, but mutation /
    // conditional-open policy still applies fail-closed (open flags then reject).
    if (chain.length >= 2) {
      const rootExpr = leftmostMemberRoot(callee);
      let nsKind = resolveTrustedFsNsKind(
        rootExpr,
        callBindings,
        flagProvenance,
        nsAliases,
      );
      if (nsKind !== "fs" && nsKind !== "fs.promises") {
        const mapped = nsAliases.get(chain[0]);
        if (mapped === "fs" || mapped === "fs.promises") {
          nsKind = mapped;
        }
      }
      if (nsKind === "fs" || nsKind === "fs.promises") {
        const rootLabel = chain[0];
        if (nsKind === "fs" && chain.length >= 3 && chain[1] === "promises") {
          checkFsMethod(
            "fs.promises",
            chain[2],
            `${rootLabel}.promises`,
            args,
            callNode,
          );
        } else if (chain[1] === "promises" && chain.length === 2) {
          // e.g. fs.promises as a value callee — not a method call.
        } else if (!(nsKind === "fs" && chain[1] === "promises")) {
          checkFsMethod(nsKind, chain[1], rootLabel, args, callNode);
        }
      }
    }

    // child_process stays import-map based (no alias expansion in this ticket).
    const root = chain[0];
    const ns = nsAliases.get(root);
    if (ns === "child_process" && chain.length >= 2) {
      const method = chain[1];
      if (method === "\0computed" || FORBIDDEN_CHILD_METHODS.has(method)) {
        violations.push(
          `${rel}: forbidden child_process '${method === "\0computed" ? "[computed]" : method}'`,
        );
      }
    }

    // new WebSocket(...) already covered if Identifier WebSocket; NewExpression with member
    if (isNew && chain.length === 1 && FORBIDDEN_GLOBALS.has(chain[0])) {
      violations.push(`${rel}: forbidden new ${chain[0]}(...)`);
    }
  }

  function visit(node) {
    // import ... from 'mod'
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const spec = node.moduleSpecifier.text;
      if (!(spec.startsWith(".") || spec.startsWith("/"))) {
        checkModuleSpec(spec, "module import");
      }
      const bare = normalizeModuleSpec(spec);
      if (bare) recordImportBindings(node.importClause, bare);
    }

    // export ... from 'mod'
    if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      const spec = node.moduleSpecifier.text;
      if (!(spec.startsWith(".") || spec.startsWith("/"))) {
        checkModuleSpec(spec, "module re-export");
      }
    }

    // require('mod') / import('mod') — CallExpression
    // Ticket 01 production loaders are static ESM only: every dynamic import and
    // every require is a violation (including relative specs).
    if (ts.isCallExpression(node)) {
      const expr = node.expression;
      const bareExpr = unwrapStaticExpr(expr);
      const arg0 = node.arguments[0];

      // import(...) dynamic — always forbidden
      if (expr.kind === ts.SyntaxKind.ImportKeyword) {
        if (!arg0 || !ts.isStringLiteral(arg0)) {
          violations.push(`${rel}: forbidden non-literal dynamic import`);
        } else {
          violations.push(`${rel}: forbidden dynamic import '${arg0.text}'`);
        }
      }

      // require(...) — always forbidden (static ESM only)
      if (ts.isIdentifier(bareExpr) && bareExpr.text === "require") {
        if (!arg0 || !ts.isStringLiteral(arg0)) {
          violations.push(`${rel}: forbidden non-literal require`);
        } else {
          violations.push(`${rel}: forbidden require('${arg0.text}')`);
        }
      }

      checkCallOrNew(expr, false, node.arguments, node);
    }

    // new WebSocket(...), new Function(...)
    if (ts.isNewExpression(node) && node.expression) {
      const bareNew = unwrapStaticExpr(node.expression);
      if (ts.isIdentifier(bareNew)) {
        if (bareNew.text === "Function") {
          violations.push(`${rel}: forbidden new Function(...)`);
        }
        if (FORBIDDEN_GLOBALS.has(bareNew.text)) {
          violations.push(`${rel}: forbidden new ${bareNew.text}(...)`);
        }
      }
      checkCallOrNew(node.expression, true, node.arguments, node);
    }

    // Destructure / object-pattern extract of non-read-only or open capability
    // from a proven fs namespace fails immediately (do not wait for a later call).
    // Object rest (`const { ...bag } = fs`) extracts the full capability surface.
    if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      ts.isObjectBindingPattern(node.name)
    ) {
      const bindBindings = bindingsForNode(node, sf);
      const nsKind = resolveTrustedFsNsKind(
        node.initializer,
        bindBindings,
        flagProvenance,
        nsAliases,
      );
      if (nsKind === "fs" || nsKind === "fs.promises") {
        for (const el of node.name.elements) {
          if (ts.isOmittedExpression(el) || !ts.isBindingElement(el)) continue;
          if (el.dotDotDotToken) {
            violations.push(`${rel}: forbidden fs object-rest capability extract`);
            continue;
          }
          const original = bindingElementStaticPropertyName(el);
          if (!original) continue;
          if (CONDITIONAL_OPEN_METHODS.has(original)) {
            violations.push(
              `${rel}: forbidden unproven fs open capability extract '${original}'`,
            );
          } else if (isFsCapabilityMethod(original, nsKind)) {
            violations.push(`${rel}: forbidden fs capability extract '${original}'`);
          }
        }
      }
    }

    // Property / element capability references on proven fs namespaces:
    // consume(fs.writeFileSync), Reflect.apply(fs.openSync, …), (0, fs.m)(),
    // fs.openSync.bind(fs), array/object storage, etc. Direct call callees are
    // owned by checkCallOrNew (non-read-only always forbidden; open only with
    // proven read-only flags through a proven namespace).
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      checkFsCapabilityReference(node);
    }

    // eval / Function / createRequire as value capabilities (alias, pass, sequence).
    // Conservative: any value-position identifier with these names is forbidden.
    if (ts.isIdentifier(node)) {
      const name = node.text;
      if (FORBIDDEN_CODE_EXEC_GLOBALS.has(name) || FORBIDDEN_LOADER_APIS.has(name)) {
        if (isForbiddenCapabilityIdentifierUse(node)) {
          // Direct call / new already reported a specific message; still OK to
          // mark acquisition forms (const e = eval; (0, eval); foo(eval)).
          if (!isDirectCallExpressionCallee(node) && !(node.parent && ts.isNewExpression(node.parent) && node.parent.expression === node)) {
            violations.push(`${rel}: forbidden capability reference '${name}'`);
          }
        }
      }
    }

    ts.forEachChild(node, visit);
  }

  sf.forEachChild(visit);
  return violations;
}

/**
 * @param {string[]} files
 * @returns {{ ok: boolean, violations: string[] }}
 */
export function scanFiles(files) {
  /** @type {string[]} */
  const violations = [];
  for (const file of files) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.isAbsolute(file) ? path.relative(repoRoot, file) || file : file;
    violations.push(...scanSourceText(file, text, rel));
  }
  return { ok: violations.length === 0, violations };
}

/**
 * Scan a synthetic source string (for self-tests / external callers).
 * @param {string} text
 * @param {string} [label]
 */
export function scanSourceSnippet(text, label = "snippet.ts") {
  return scanSourceText(label, text, label);
}

/**
 * Collect static ESM production graph files reachable from entry points.
 * Follows relative ImportDeclaration and relative ExportDeclaration re-exports
 * only (no dynamic import / require edges — those are rejected at scan time).
 *
 * @param {string[]} entryFiles
 * @param {{ root?: string, skipPathSubstrings?: string[] }} [opts]
 * @returns {string[]}
 */
function collectStaticEsmGraph(entryFiles, opts = {}) {
  const root = opts.root ?? SRC_ROOT;
  const skipPathSubstrings = opts.skipPathSubstrings ?? [
    `${path.sep}harness${path.sep}`,
  ];
  /** @type {Set<string>} */
  const files = new Set();
  /** @type {string[]} */
  const queue = [...entryFiles];

  while (queue.length) {
    const file = queue.pop();
    if (!file || files.has(file)) continue;
    if (!file.startsWith(root)) continue;
    if (skipPathSubstrings.some((s) => file.includes(s))) continue;
    if (file.endsWith(`${path.sep}mcp${path.sep}client.ts`)) continue;
    if (!fs.existsSync(file)) {
      throw new Error(`Missing production entry: ${file}`);
    }
    files.add(file);

    const text = fs.readFileSync(file, "utf8");
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
    sf.forEachChild(function visit(node) {
      if (
        ts.isImportDeclaration(node) &&
        node.moduleSpecifier &&
        ts.isStringLiteral(node.moduleSpecifier)
      ) {
        const spec = node.moduleSpecifier.text;
        if (spec.startsWith(".") || spec.startsWith("/")) {
          const resolved = resolveRelative(file, spec);
          if (resolved) queue.push(resolved);
        }
      }
      // Relative re-exports are part of the static ESM graph (hidden mutators
      // must not escape scan by export-from alone).
      if (
        ts.isExportDeclaration(node) &&
        node.moduleSpecifier &&
        ts.isStringLiteral(node.moduleSpecifier)
      ) {
        const spec = node.moduleSpecifier.text;
        if (spec.startsWith(".") || spec.startsWith("/")) {
          const resolved = resolveRelative(file, spec);
          if (resolved) queue.push(resolved);
        }
      }
      ts.forEachChild(node, visit);
    });
  }
  return [...files].sort();
}

function collectProductionFiles() {
  return collectStaticEsmGraph(ENTRY_FILES, { root: SRC_ROOT });
}

function resolveRelative(fromFile, spec) {
  const base = path.resolve(path.dirname(fromFile), spec);
  const candidates = [
    base,
    `${base}.ts`,
    `${base}.js`,
    path.join(base, "index.ts"),
    path.join(base, "index.js"),
  ];
  if (spec.endsWith(".js")) {
    candidates.unshift(base.replace(/\.js$/, ".ts"));
  }
  for (const c of candidates) {
    if (fs.existsSync(c) && fs.statSync(c).isFile()) return c;
  }
  return null;
}

/** Self-test cases: each forbidden snippet must produce >=1 violation; safe must produce 0. */
function runSelfTests() {
  /** @type {{ name: string, source: string, expectViolation: boolean }[]} */
  const cases = [
    {
      name: "default fs import + writeFileSync",
      expectViolation: true,
      source: `import fs from "node:fs";\nfs.writeFileSync("x", "y");\n`,
    },
    {
      name: "fs.promises.writeFile via namespace",
      expectViolation: true,
      source: `import fs from "node:fs";\nawait fs.promises.writeFile("x", "y");\n`,
    },
    {
      name: "named fs promises alias writeFile",
      expectViolation: true,
      source: `import { promises as fsp } from "node:fs";\nawait fsp.writeFile("x", "y");\n`,
    },
    {
      name: "openSync write mode + writeSync",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst fd = fs.openSync("x", "w");\nfs.writeSync(fd, "y");\n`,
    },
    {
      name: "require(fs).writeFileSync member chain",
      expectViolation: true,
      source: `require("fs").writeFileSync("x", "y");\n`,
    },
    {
      name: "require(node:fs).promises.writeFile member chain",
      expectViolation: true,
      source: `require("node:fs").promises.writeFile("x", "y");\n`,
    },
    {
      name: "createWriteStream",
      expectViolation: true,
      source: `import fs from "node:fs";\nfs.createWriteStream("x");\n`,
    },
    {
      name: "truncateSync",
      expectViolation: true,
      source: `import fs from "node:fs";\nfs.truncateSync("x", 0);\n`,
    },
    {
      name: "ftruncateSync",
      expectViolation: true,
      source: `import fs from "node:fs";\nfs.ftruncateSync(1, 0);\n`,
    },
    {
      name: "openSync unknown/nonliteral flags",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst mode = "w";\nfs.openSync("x", mode);\n`,
    },
    {
      name: "openSync numeric flags fail-closed",
      expectViolation: true,
      source: `import fs from "node:fs";\nfs.openSync("x", 1);\n`,
    },
    {
      name: "openSync O_WRONLY flag",
      expectViolation: true,
      source: `import fs from "node:fs";\nimport { constants as c } from "node:fs";\nfs.openSync("x", c.O_WRONLY);\n`,
    },
    {
      name: "openSync fake object O_RDONLY bypass",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst fake = { O_RDONLY: 1 };\nfs.openSync("x", fake.O_RDONLY);\n`,
    },
    {
      name: "openSync unknown parameter O_RDONLY bypass",
      expectViolation: true,
      source: `import fs from "node:fs";\nfunction unsafe(fake: unknown) {\n  fs.openSync("x", (fake as any).O_RDONLY);\n}\n`,
    },
    {
      name: "openSync object-literal O_RDONLY mapped to write-capable value",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst alias = { O_RDONLY: 1 };\nfs.openSync("x", alias.O_RDONLY);\n`,
    },
    {
      name: "openSync parameter shadows imported constants alias",
      expectViolation: true,
      source: `import fs, { constants as c } from "node:fs";\nfunction unsafe(c: any) {\n  fs.openSync("x", c.O_RDONLY);\n}\n`,
    },
    {
      name: "openSync parameter shadows imported fs namespace for constants",
      expectViolation: true,
      source: `import fs from "node:fs";\nfunction unsafe(fs: any) {\n  fs.openSync("x", fs.constants.O_RDONLY);\n}\n`,
    },
    {
      name: "openSync local nested shadow of imported constants alias",
      expectViolation: true,
      source: `import fs, { constants as c } from "node:fs";\nfunction outer() {\n  const c = { O_RDONLY: 1 };\n  fs.openSync("x", c.O_RDONLY);\n}\n`,
    },
    {
      name: "fs namespace simple alias writeFileSync",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst f = fs;\nf.writeFileSync("x", "y");\n`,
    },
    {
      name: "fs destructured writeFileSync call",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst { writeFileSync } = fs;\nwriteFileSync("x", "y");\n`,
    },
    {
      name: "fs namespace simple alias openSync write mode",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst f = fs;\nf.openSync("x", "w");\n`,
    },
    {
      name: "fs namespace chained alias writeFileSync",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst f = fs;\nconst g = f;\ng.writeFileSync("x", "y");\n`,
    },
    {
      name: "fs destructured renamed writeFileSync",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst { writeFileSync: write } = fs;\nwrite("x", "y");\n`,
    },
    {
      name: "fs destructured openSync write mode",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst { openSync } = fs;\nopenSync("x", "w");\n`,
    },
    {
      name: "fs alias from alias then destructure writeFileSync",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst f = fs;\nconst { writeFileSync } = f;\nwriteFileSync("x", "y");\n`,
    },
    {
      name: "fs namespace alias re-shadowed does not grant mutation provenance",
      expectViolation: false,
      source: `import fs from "node:fs";\nconst f = fs;\nfunction outer() {\n  const f = { writeFileSync(_a: string, _b: string) {} };\n  f.writeFileSync("x", "y");\n}\n`,
    },
    {
      name: "fs destructured alias re-shadowed by parameter still extracts capability",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst { writeFileSync } = fs;\nfunction outer(writeFileSync: (a: string, b: string) => void) {\n  writeFileSync("x", "y");\n}\n`,
    },
    {
      name: "parameter-only writeFileSync name without fs extract is not a capability",
      expectViolation: false,
      source: `function outer(writeFileSync: (a: string, b: string) => void) {\n  writeFileSync("x", "y");\n}\n`,
    },
    {
      name: "safe openSync via fs namespace alias O_RDONLY",
      expectViolation: false,
      source: `import fs from "node:fs";\nconst f = fs;\nconst fd = f.openSync("x", f.constants.O_RDONLY);\nf.closeSync(fd);\n`,
    },
    {
      name: "destructured openSync even with string mode r is unproven",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst { openSync, closeSync } = fs;\nconst fd = openSync("x", "r");\ncloseSync(fd);\n`,
    },
    {
      name: "capability reference writeFileSync passed as value",
      expectViolation: true,
      source: `import fs from "node:fs";\nfunction consume(_fn: unknown) {}\nconsume(fs.writeFileSync);\n`,
    },
    {
      name: "Reflect.apply writeFileSync",
      expectViolation: true,
      source: `import fs from "node:fs";\nReflect.apply(fs.writeFileSync, fs, ["x", "y"]);\n`,
    },
    {
      name: "comma sequence writeFileSync call",
      expectViolation: true,
      source: `import fs from "node:fs";\n(0, fs.writeFileSync)("x", "y");\n`,
    },
    {
      name: "openSync.bind then call write mode",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst o = fs.openSync.bind(fs);\no("x", "w");\n`,
    },
    {
      name: "Reflect.apply openSync write mode",
      expectViolation: true,
      source: `import fs from "node:fs";\nReflect.apply(fs.openSync, fs, ["x", "w"]);\n`,
    },
    {
      name: "destructured writeFileSync passed as callback",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst { writeFileSync } = fs;\nsetTimeout(writeFileSync as any, 0);\n`,
    },
    {
      name: "writeFileSync stored in array",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst bag = [fs.writeFileSync];\nvoid bag;\n`,
    },
    {
      name: "writeFileSync stored in object",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst bag = { w: fs.writeFileSync };\nvoid bag;\n`,
    },
    {
      name: "openSync capability reference only",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst o = fs.openSync;\nvoid o;\n`,
    },
    {
      name: "named openSync import is unproven",
      expectViolation: true,
      source: `import { openSync } from "node:fs";\nvoid openSync;\n`,
    },
    {
      name: "safe closeSync and readFileSync references",
      expectViolation: false,
      source: `import fs from "node:fs";\nconst r = fs.readFileSync;\nconst c = fs.closeSync;\nvoid r; void c;\n`,
    },
    {
      name: "safe openSync via fs namespace alias string mode r",
      expectViolation: false,
      source: `import fs from "node:fs";\nconst f = fs;\nconst fd = f.openSync("x", "r");\nf.closeSync(fd);\n`,
    },
    {
      name: "literal dynamic import node:net",
      expectViolation: true,
      source: `const m = await import("node:net");\n`,
    },
    {
      name: "non-literal dynamic import",
      expectViolation: true,
      source: `const s = "node:fs";\nawait import(s);\n`,
    },
    {
      name: "non-literal require",
      expectViolation: true,
      source: `const s = "fs";\nrequire(s);\n`,
    },
    {
      name: "new WebSocket",
      expectViolation: true,
      source: `const w = new WebSocket("wss://example");\n`,
    },
    {
      name: "computed globalThis fetch",
      expectViolation: true,
      source: `globalThis["fetch"]("https://example");\n`,
    },
    {
      name: "globalThis.fetch property",
      expectViolation: true,
      source: `globalThis.fetch("https://example");\n`,
    },
    {
      name: "eval call",
      expectViolation: true,
      source: `eval("1+1");\n`,
    },
    {
      name: "new Function",
      expectViolation: true,
      source: `const f = new Function("return 1");\n`,
    },
    {
      name: "Function constructor call",
      expectViolation: true,
      source: `const f = Function("return 1");\n`,
    },
    {
      name: "process.dlopen",
      expectViolation: true,
      source: `process.dlopen({} as any, "x.node");\n`,
    },
    {
      name: "process.binding",
      expectViolation: true,
      source: `process.binding("fs");\n`,
    },
    {
      name: "child_process spawn",
      expectViolation: true,
      source: `import { spawn } from "node:child_process";\nspawn("ls");\n`,
    },
    {
      name: "http import",
      expectViolation: true,
      source: `import http from "node:http";\nvoid http;\n`,
    },
    {
      name: "safe crypto import",
      expectViolation: false,
      source: `import crypto from "node:crypto";\nexport const h = crypto.createHash("sha256");\n`,
    },
    {
      name: "safe fs read-only",
      expectViolation: false,
      source: `import fs from "node:fs";\nconst s = fs.readFileSync("x");\nconst st = fs.lstatSync("x");\nvoid s; void st;\n`,
    },
    {
      name: "safe openSync string mode r",
      expectViolation: false,
      source: `import fs from "node:fs";\nconst fd = fs.openSync("x", "r");\nfs.closeSync(fd);\n`,
    },
    {
      name: "safe openSync O_RDONLY only",
      expectViolation: false,
      source: `import fs from "node:fs";\nimport { constants as fsConstants } from "node:fs";\nconst fd = fs.openSync("x", fsConstants.O_RDONLY);\nfs.closeSync(fd);\n`,
    },
    {
      name: "safe openSync fs.constants.O_RDONLY direct",
      expectViolation: false,
      source: `import fs from "node:fs";\nconst fd = fs.openSync("x", fs.constants.O_RDONLY);\nfs.closeSync(fd);\n`,
    },
    {
      name: "safe openSync fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW",
      expectViolation: false,
      source: `import fs from "node:fs";\nimport { constants as fsConstants } from "node:fs";\nconst fd = fs.openSync("x", fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);\nfs.closeSync(fd);\n`,
    },
    {
      name: "safe openSync O_RDONLY | O_NOFOLLOW production helper form",
      expectViolation: false,
      source: `import fs from "node:fs";
import { constants as fsConstants } from "node:fs";
function openReadNoFollowFlags(): number {
  const base = fsConstants.O_RDONLY;
  const nofollow =
    "O_NOFOLLOW" in fsConstants
      ? (fsConstants as NodeJS.Dict<number>).O_NOFOLLOW
      : undefined;
  if (typeof nofollow === "number") {
    return base | nofollow;
  }
  return base;
}
const flags = openReadNoFollowFlags();
const fd = fs.openSync("x", flags);
fs.closeSync(fd);
`,
    },
    {
      name: "safe path + url",
      expectViolation: false,
      source: `import path from "node:path";\nimport { fileURLToPath } from "node:url";\nexport const r = path.join(fileURLToPath(import.meta.url), "..");\n`,
    },
    {
      name: "safe relative import only",
      expectViolation: false,
      source: `import { x } from "./local.js";\nexport const y = x;\n`,
    },
    // --- R13 structural closure: receiver wrappers ---
    {
      name: "fs as any writeFileSync receiver",
      expectViolation: true,
      source: `import fs from "node:fs";\n(fs as any).writeFileSync("x", "y");\n`,
    },
    {
      name: "fs non-null writeFileSync receiver",
      expectViolation: true,
      source: `import fs from "node:fs";\nfs!.writeFileSync("x", "y");\n`,
    },
    {
      name: "comma sequence fs receiver writeFileSync",
      expectViolation: true,
      source: `import fs from "node:fs";\n(0, fs).writeFileSync("x", "y");\n`,
    },
    {
      name: "fs as any openSync write mode",
      expectViolation: true,
      source: `import fs from "node:fs";\n(fs as any).openSync("x", "w");\n`,
    },
    {
      name: "safe direct openSync after as-cast on unrelated value",
      expectViolation: false,
      source: `import fs from "node:fs";\nconst fd = fs.openSync("x", "r");\nfs.closeSync(fd);\n`,
    },
    // --- R13: alternate / dynamic loaders fail closed ---
    {
      name: "createRequire from node:module",
      expectViolation: true,
      source: `import { createRequire } from "node:module";\nconst r = createRequire(import.meta.url);\nr("fs").writeFileSync("x", "y");\n`,
    },
    {
      name: "createRequire alias then fs load",
      expectViolation: true,
      source: `import { createRequire } from "node:module";\nconst r = createRequire(import.meta.url);\nconst f = r("fs"); f.writeFileSync("x", "y");\n`,
    },
    {
      name: "dynamic import node:fs namespace writeFileSync",
      expectViolation: true,
      source: `const mod = await import("node:fs");\nmod.writeFileSync("x", "y");\n`,
    },
    {
      name: "dynamic import named writeFileSync",
      expectViolation: true,
      source: `const { writeFileSync } = await import("node:fs");\nwriteFileSync("x", "y");\n`,
    },
    {
      name: "relative dynamic import forbidden",
      expectViolation: true,
      source: `await import("./hidden-mutator.js");\n`,
    },
    {
      name: "relative require forbidden",
      expectViolation: true,
      source: `require("./hidden-mutator.js");\n`,
    },
    {
      name: "node:module bare import forbidden",
      expectViolation: true,
      source: `import module from "node:module";\nvoid module;\n`,
    },
    // --- R13: incomplete mutation blacklist → allowlist fail-closed ---
    {
      name: "mkdtempSync not on read-only allowlist",
      expectViolation: true,
      source: `import fs from "node:fs";\nfs.mkdtempSync("/tmp/cg-");\n`,
    },
    {
      name: "lchownSync not on read-only allowlist",
      expectViolation: true,
      source: `import fs from "node:fs";\nfs.lchownSync("x", 0, 0);\n`,
    },
    {
      name: "lchmodSync not on read-only allowlist",
      expectViolation: true,
      source: `import fs from "node:fs";\nfs.lchmodSync("x", 0o644);\n`,
    },
    {
      name: "unknown future fs API fail-closed",
      expectViolation: true,
      source: `import fs from "node:fs";\n(fs as any).totallyNewMutationApi("x");\n`,
    },
    {
      name: "safe Ticket 01 read-only fs surface",
      expectViolation: false,
      source: `import fs from "node:fs";\nfs.lstatSync("x");\nfs.realpathSync("x");\nfs.readFileSync("x");\nconst fd = fs.openSync("x", "r");\nfs.fstatSync(fd);\nfs.closeSync(fd);\n`,
    },
    {
      name: "safe existsSync read-only",
      expectViolation: false,
      source: `import fs from "node:fs";\nconst ok = fs.existsSync("x");\nvoid ok;\n`,
    },
    // --- R13: object rest extracts full fs capability ---
    {
      name: "object rest from fs namespace",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst { ...bag } = fs;\nbag.writeFileSync("x", "y");\n`,
    },
    {
      name: "object rest from fs alias",
      expectViolation: true,
      source: `import fs from "node:fs";\nconst f = fs;\nconst { ...bag } = f;\nvoid bag;\n`,
    },
    // --- R13: indirect eval / Function capability ---
    {
      name: "comma sequence eval call",
      expectViolation: true,
      source: `(0, eval)("1+1");\n`,
    },
    {
      name: "eval alias then call",
      expectViolation: true,
      source: `const e = eval;\ne("1+1");\n`,
    },
    {
      name: "comma sequence Function constructor",
      expectViolation: true,
      source: `(0, Function)("return 1");\n`,
    },
    {
      name: "Function alias acquisition",
      expectViolation: true,
      source: `const F = Function;\nvoid F;\n`,
    },
    {
      name: "safe Function type annotation only",
      expectViolation: false,
      source: `const f: Function = (() => 1) as unknown as Function;\nvoid f;\n`,
    },
  ];

  /** @type {string[]} */
  const failures = [];
  for (const c of cases) {
    const v = scanSourceSnippet(c.source, `self-test:${c.name}`);
    const has = v.length > 0;
    if (c.expectViolation && !has) {
      failures.push(`EXPECTED violation missing: ${c.name}`);
    }
    if (!c.expectViolation && has) {
      failures.push(`UNEXPECTED violation in safe case ${c.name}: ${v.join("; ")}`);
    }
  }

  // Also scan a temp file path form to prove file-based scanner works.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cg-boundary-"));
  const badFile = path.join(tmp, "bad.ts");
  fs.writeFileSync(badFile, `import net from "node:net";\nvoid net;\n`, "utf8");
  const fileScan = scanFiles([badFile]);
  if (fileScan.ok) {
    failures.push("temp file scan of node:net should fail");
  }

  // Graph-closure self-test: relative re-export must reach a hidden mutator.
  const graphRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-boundary-graph-"));
  const entryPath = path.join(graphRoot, "entry.ts");
  const bridgePath = path.join(graphRoot, "bridge.ts");
  const hiddenPath = path.join(graphRoot, "hidden-mutator.ts");
  fs.writeFileSync(
    entryPath,
    `export { mutate } from "./bridge.js";\n`,
    "utf8",
  );
  fs.writeFileSync(
    bridgePath,
    `export { mutate } from "./hidden-mutator.js";\n`,
    "utf8",
  );
  fs.writeFileSync(
    hiddenPath,
    `import fs from "node:fs";\nexport function mutate() {\n  fs.writeFileSync("x", "y");\n}\n`,
    "utf8",
  );
  const graphFiles = collectStaticEsmGraph([entryPath], {
    root: graphRoot,
    skipPathSubstrings: [],
  });
  const graphRel = graphFiles.map((f) => path.relative(graphRoot, f)).sort();
  if (!graphRel.includes("hidden-mutator.ts")) {
    failures.push(
      `graph re-export did not reach hidden-mutator.ts (got: ${graphRel.join(", ")})`,
    );
  } else {
    const graphScan = scanFiles(graphFiles);
    if (graphScan.ok) {
      failures.push("graph re-export hidden mutator should produce violations");
    }
  }

  // Opposite control: re-export of read-only-only module is clean.
  const cleanRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-boundary-graph-clean-"));
  const cleanEntry = path.join(cleanRoot, "entry.ts");
  const cleanLeaf = path.join(cleanRoot, "readonly.ts");
  fs.writeFileSync(cleanEntry, `export { read } from "./readonly.js";\n`, "utf8");
  fs.writeFileSync(
    cleanLeaf,
    `import fs from "node:fs";\nexport function read() {\n  return fs.readFileSync("x");\n}\n`,
    "utf8",
  );
  const cleanFiles = collectStaticEsmGraph([cleanEntry], {
    root: cleanRoot,
    skipPathSubstrings: [],
  });
  const cleanScan = scanFiles(cleanFiles);
  if (!cleanScan.ok) {
    failures.push(
      `graph re-export read-only control should pass: ${cleanScan.violations.join("; ")}`,
    );
  }

  return {
    ok: failures.length === 0,
    cases: cases.length,
    failures,
  };
}

function main() {
  const selfTest = process.argv.includes("--self-test");
  if (selfTest) {
    const result = runSelfTests();
    console.log(
      JSON.stringify(
        {
          ok: result.ok,
          mode: "self-test",
          cases: result.cases,
          failures: result.failures,
          note: "Boundary guard self-tests against synthetic snippets.",
        },
        null,
        2,
      ),
    );
    if (!result.ok) process.exit(1);
    return;
  }

  // Production scan always runs self-tests first so the guard remains credible.
  const self = runSelfTests();
  if (!self.ok) {
    console.log(
      JSON.stringify(
        {
          ok: false,
          mode: "self-test-before-production",
          failures: self.failures,
        },
        null,
        2,
      ),
    );
    process.exit(1);
  }

  const files = collectProductionFiles();
  const result = scanFiles(files);
  const report = {
    ok: result.ok,
    scanned_files: files.map((f) => path.relative(repoRoot, f)),
    violations: result.violations,
    self_test_ok: true,
    note: "Independent AST boundary evidence; does not rely on network_used:false alone.",
  };
  console.log(JSON.stringify(report, null, 2));
  if (!result.ok) {
    process.exit(1);
  }
}

// Allow import of scan helpers without auto-running (when used as module).
const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  main();
}
