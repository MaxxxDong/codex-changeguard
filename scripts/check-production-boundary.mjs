/**
 * Independent production-boundary guard (Ticket 01).
 * Scans production TypeScript sources with the TypeScript compiler API
 * (devDependency only — never a production runtime dependency).
 *
 * Fails if the diagnosis path introduces:
 * - network APIs/modules (fetch, http/https/net/tls/dns/dgram/undici, WebSocket)
 * - child processes / arbitrary shell
 * - filesystem mutation APIs (write/append/rm/mkdir/rename/copy/chmod/…)
 * - eval / Function / process.dlopen / process.binding bypass surfaces
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
  "module",
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
]);

const FORBIDDEN_FS_METHODS = new Set([
  "writeFile",
  "writeFileSync",
  "appendFile",
  "appendFileSync",
  "rm",
  "rmSync",
  "rmdir",
  "rmdirSync",
  "mkdir",
  "mkdirSync",
  "rename",
  "renameSync",
  "copyFile",
  "copyFileSync",
  "cp",
  "cpSync",
  "unlink",
  "unlinkSync",
  "chmod",
  "chmodSync",
  "chown",
  "chownSync",
  "truncate",
  "truncateSync",
  "createWriteStream",
  "openAsBlob",
  "link",
  "linkSync",
  "symlink",
  "symlinkSync",
  "fchmod",
  "fchmodSync",
  "fchown",
  "fchownSync",
  "ftruncate",
  "ftruncateSync",
  "futimes",
  "futimesSync",
  "lutimes",
  "lutimesSync",
  "utimes",
  "utimesSync",
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
 * Resolve a property access / element access chain into string segments.
 * Returns null when a segment is non-literal / non-ident (fail-closed check
 * happens at call sites for computed non-literal keys).
 * @param {ts.Expression} expr
 * @returns {string[] | null}
 */
function resolveMemberChain(expr) {
  if (ts.isIdentifier(expr)) {
    return [expr.text];
  }
  if (ts.isPropertyAccessExpression(expr)) {
    const base = resolveMemberChain(expr.expression);
    if (!base) return null;
    return [...base, expr.name.text];
  }
  if (ts.isElementAccessExpression(expr)) {
    const base = resolveMemberChain(expr.expression);
    if (!base) return null;
    const arg = expr.argumentExpression;
    if (arg && ts.isStringLiteral(arg)) {
      return [...base, arg.text];
    }
    // Non-literal computed key — return special marker for fail-closed handling.
    return [...base, "\0computed"];
  }
  if (ts.isParenthesizedExpression(expr)) {
    return resolveMemberChain(expr.expression);
  }
  return null;
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
            } else if (FORBIDDEN_FS_METHODS.has(original)) {
              namedFsMethods.set(local, original);
              violations.push(`${rel}: forbidden fs import '${original}' as '${local}'`);
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
   * @param {ts.Expression} callee
   * @param {readonly ts.NodeArray<ts.Expression>} _args
   */
  function checkCallOrNew(callee, isNew) {
    // Direct identifier callees (eval, Function, fetch, named imports).
    if (ts.isIdentifier(callee)) {
      const name = callee.text;
      if (FORBIDDEN_GLOBALS.has(name)) {
        violations.push(`${rel}: forbidden global '${name}'`);
      }
      if (name === "eval") {
        violations.push(`${rel}: forbidden eval()`);
      }
      if (name === "Function") {
        violations.push(`${rel}: forbidden Function constructor`);
      }
      if (namedFsMethods.has(name) && FORBIDDEN_FS_METHODS.has(namedFsMethods.get(name))) {
        violations.push(`${rel}: forbidden fs call '${name}'`);
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
      if (FORBIDDEN_GLOBALS.has(prop) || prop === "eval" || prop === "Function") {
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

    // Namespace fs / fs.promises / child_process
    const root = chain[0];
    const ns = nsAliases.get(root);
    if (ns === "fs" || ns === "fs.promises") {
      // fs.writeFile / fs.promises.writeFile / fsp.writeFile
      if (ns === "fs" && chain.length >= 3 && chain[1] === "promises") {
        const method = chain[2];
        if (method === "\0computed" || FORBIDDEN_FS_METHODS.has(method)) {
          violations.push(
            `${rel}: forbidden fs.promises mutation '${method === "\0computed" ? "[computed]" : method}'`,
          );
        }
      } else if (chain.length >= 2) {
        const method = chain[1];
        if (method === "\0computed") {
          violations.push(`${rel}: computed fs method call (fail-closed)`);
        } else if (FORBIDDEN_FS_METHODS.has(method)) {
          violations.push(`${rel}: forbidden fs mutation '${root}.${method}'`);
        }
      }
    }
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
    if (ts.isCallExpression(node)) {
      const expr = node.expression;
      const arg0 = node.arguments[0];

      // import(...) dynamic
      if (expr.kind === ts.SyntaxKind.ImportKeyword) {
        if (!arg0 || !ts.isStringLiteral(arg0)) {
          violations.push(`${rel}: non-literal dynamic import`);
        } else {
          const spec = arg0.text;
          if (!(spec.startsWith(".") || spec.startsWith("/"))) {
            checkModuleSpec(spec, "dynamic import");
          }
        }
      }

      // require(...)
      if (ts.isIdentifier(expr) && expr.text === "require") {
        if (!arg0 || !ts.isStringLiteral(arg0)) {
          violations.push(`${rel}: non-literal require`);
        } else {
          const spec = arg0.text;
          if (!(spec.startsWith(".") || spec.startsWith("/"))) {
            checkModuleSpec(spec, "require");
          }
        }
      }

      checkCallOrNew(expr, false);
    }

    // new WebSocket(...), new Function(...)
    if (ts.isNewExpression(node) && node.expression) {
      if (ts.isIdentifier(node.expression)) {
        if (node.expression.text === "Function") {
          violations.push(`${rel}: forbidden new Function(...)`);
        }
        if (FORBIDDEN_GLOBALS.has(node.expression.text)) {
          violations.push(`${rel}: forbidden new ${node.expression.text}(...)`);
        }
      }
      checkCallOrNew(node.expression, true);
    }

    // Tagged template Function`...` rare — skip; eval identifier alone not enough.

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

function collectProductionFiles() {
  /** @type {Set<string>} */
  const files = new Set();
  /** @type {string[]} */
  const queue = [...ENTRY_FILES];

  while (queue.length) {
    const file = queue.pop();
    if (!file || files.has(file)) continue;
    if (!file.startsWith(SRC_ROOT)) continue;
    if (file.includes(`${path.sep}harness${path.sep}`)) continue;
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
      ts.forEachChild(node, visit);
    });
  }
  return [...files].sort();
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
      name: "safe path + url",
      expectViolation: false,
      source: `import path from "node:path";\nimport { fileURLToPath } from "node:url";\nexport const r = path.join(fileURLToPath(import.meta.url), "..");\n`,
    },
    {
      name: "safe relative import only",
      expectViolation: false,
      source: `import { x } from "./local.js";\nexport const y = x;\n`,
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
