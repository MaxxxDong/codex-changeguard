/**
 * Independent production-boundary guard (Ticket 01).
 * Scans production TypeScript sources with the TypeScript compiler API
 * (devDependency only — never a production runtime dependency).
 *
 * Fails if the diagnosis path introduces:
 * - network APIs/modules (fetch, http/https/net/tls/dns/dgram/undici, WebSocket)
 * - child processes / arbitrary shell
 * - filesystem mutation APIs (write/append/rm/mkdir/rename/copy/chmod/…)
 *
 * network_used:false in diagnosis output is NOT treated as proof.
 */
import fs from "node:fs";
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
  "node:http",
  "node:https",
  "node:http2",
  "node:net",
  "node:tls",
  "node:dns",
  "node:dgram",
  "node:undici",
  "node:child_process",
  "node:worker_threads",
  "node:cluster",
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
]);

const FORBIDDEN_GLOBALS = new Set(["fetch", "WebSocket"]);

const FORBIDDEN_CHILD_METHODS = new Set([
  "spawn",
  "spawnSync",
  "exec",
  "execSync",
  "execFile",
  "execFileSync",
  "fork",
]);

function collectProductionFiles() {
  /** @type {Set<string>} */
  const files = new Set();
  /** @type {string[]} */
  const queue = [...ENTRY_FILES];

  while (queue.length) {
    const file = queue.pop();
    if (!file || files.has(file)) continue;
    if (!file.startsWith(SRC_ROOT)) continue;
    // Exclude harness and test client from production boundary of diagnosis path.
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
      if (
        ts.isCallExpression(node) &&
        ts.isIdentifier(node.expression) &&
        (node.expression.text === "require" || node.expression.text === "import")
      ) {
        // dynamic — checked separately
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
  // Strip .js extension used in NodeNext imports → .ts source
  if (spec.endsWith(".js")) {
    candidates.unshift(base.replace(/\.js$/, ".ts"));
  }
  for (const c of candidates) {
    if (fs.existsSync(c) && fs.statSync(c).isFile()) return c;
  }
  return null;
}

function moduleNameOf(spec) {
  if (spec.startsWith("node:")) return spec;
  // bare package / builtin
  return spec;
}

/**
 * @param {string[]} files
 * @returns {{ ok: boolean, violations: string[] }}
 */
function scanFiles(files) {
  /** @type {string[]} */
  const violations = [];

  for (const file of files) {
    const text = fs.readFileSync(file, "utf8");
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
    const rel = path.relative(repoRoot, file);

    /** @type {Set<string>} */
    const importedFsNames = new Set();
    /** @type {string | null} */
    let fsNamespace = null;
    /** @type {string | null} */
    let childNamespace = null;

    sf.forEachChild(function visit(node) {
      // import ... from 'mod'
      if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
        const spec = moduleNameOf(node.moduleSpecifier.text);
        if (FORBIDDEN_MODULES.has(spec) || FORBIDDEN_MODULES.has(spec.replace(/^node:/, ""))) {
          violations.push(`${rel}: forbidden module import '${spec}'`);
        }
        const bare = spec.replace(/^node:/, "");
        if (bare === "fs" || bare === "fs/promises") {
          if (node.importClause?.namedBindings && ts.isNamespaceImport(node.importClause.namedBindings)) {
            fsNamespace = node.importClause.namedBindings.name.text;
          }
          if (node.importClause?.namedBindings && ts.isNamedImports(node.importClause.namedBindings)) {
            for (const el of node.importClause.namedBindings.elements) {
              importedFsNames.add(el.name.text);
              if (FORBIDDEN_FS_METHODS.has(el.propertyName?.text ?? el.name.text)) {
                violations.push(
                  `${rel}: forbidden fs import '${el.propertyName?.text ?? el.name.text}'`,
                );
              }
            }
          }
        }
        if (bare === "child_process") {
          if (node.importClause?.namedBindings && ts.isNamespaceImport(node.importClause.namedBindings)) {
            childNamespace = node.importClause.namedBindings.name.text;
          }
        }
      }

      // require('mod') / import('mod')
      if (ts.isCallExpression(node)) {
        const arg0 = node.arguments[0];
        if (
          arg0 &&
          ts.isStringLiteral(arg0) &&
          (ts.isIdentifier(node.expression) &&
            (node.expression.text === "require" || node.expression.text === "import"))
        ) {
          const spec = moduleNameOf(arg0.text);
          if (FORBIDDEN_MODULES.has(spec) || FORBIDDEN_MODULES.has(spec.replace(/^node:/, ""))) {
            violations.push(`${rel}: forbidden dynamic import/require '${spec}'`);
          }
        }
        // import(non-literal) is also forbidden as arbitrary dynamic load surface
        if (
          node.expression.kind === ts.SyntaxKind.ImportKeyword ||
          (ts.isIdentifier(node.expression) && node.expression.text === "import")
        ) {
          if (!arg0 || !ts.isStringLiteral(arg0)) {
            // allow only if not present — treat non-literal as violation
            if (arg0 && !ts.isStringLiteral(arg0)) {
              violations.push(`${rel}: non-literal dynamic import`);
            }
          }
        }
      }

      // fs mutation: fs.writeFileSync / namespace.method
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const obj = node.expression.expression;
        const method = node.expression.name.text;
        if (ts.isIdentifier(obj)) {
          if (fsNamespace && obj.text === fsNamespace && FORBIDDEN_FS_METHODS.has(method)) {
            violations.push(`${rel}: forbidden fs mutation '${fsNamespace}.${method}'`);
          }
          if (childNamespace && obj.text === childNamespace && FORBIDDEN_CHILD_METHODS.has(method)) {
            violations.push(`${rel}: forbidden child_process '${childNamespace}.${method}'`);
          }
          // process.stdout is fine; process.binding / process.dlopen not used
        }
        // fs.promises.writeFile etc. — covered via namespace if imported as fs
      }

      // Direct call of imported forbidden fs method
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
        if (importedFsNames.has(node.expression.text) && FORBIDDEN_FS_METHODS.has(node.expression.text)) {
          violations.push(`${rel}: forbidden fs call '${node.expression.text}'`);
        }
        if (FORBIDDEN_GLOBALS.has(node.expression.text)) {
          violations.push(`${rel}: forbidden global '${node.expression.text}'`);
        }
      }

      // Identifier reference to fetch / WebSocket as callee already handled;
      // also flag `globalThis.fetch(...)`
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        ts.isIdentifier(node.expression.expression) &&
        (node.expression.expression.text === "globalThis" ||
          node.expression.expression.text === "global") &&
        FORBIDDEN_GLOBALS.has(node.expression.name.text)
      ) {
        violations.push(
          `${rel}: forbidden globalThis.${node.expression.name.text}`,
        );
      }

      ts.forEachChild(node, visit);
    });
  }

  return { ok: violations.length === 0, violations };
}

function main() {
  const files = collectProductionFiles();
  const result = scanFiles(files);
  const report = {
    ok: result.ok,
    scanned_files: files.map((f) => path.relative(repoRoot, f)),
    violations: result.violations,
    note: "Independent AST boundary evidence; does not rely on network_used:false alone.",
  };
  console.log(JSON.stringify(report, null, 2));
  if (!result.ok) {
    process.exit(1);
  }
}

main();
