/**
 * Package threat audit (Ticket 16).
 *
 * Inspects the *built* package tree under release/codex-changeguard-plugin.
 * Refuses: daemon loops, hidden network/telemetry, dynamic dependency install,
 * arbitrary shell/loader, OpenAI binary redistribution, secrets/private material,
 * forbidden paths, top-level surface drift, package symlinks.
 *
 * Avoids word-search false positives in public Markdown docs; audits
 * executable/package surfaces by capability + exact allowlists.
 * Normal bounded timers (setTimeout once) are not daemons; setInterval /
 * persistent loop capability is.
 *
 * Plant self-tests operate on an isolated temporary copy of the package tree
 * and never write poison into the canonical release/ tree.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const PACKAGE_TOP_LEVEL_ALLOWLIST = Object.freeze([
  ".codex-plugin",
  ".mcp.json",
  "README.md",
  "bin",
  "dist",
  "docs",
  "fixtures",
  "hooks",
  "package.json",
  "schemas",
  "skills",
]);

export const PACKAGE_FORBIDDEN_PATHS = Object.freeze([
  "AGENTS.md",
  "HANDOFF.md",
  "docs/agents",
  ".scratch",
  "src",
  "scripts",
  "node_modules",
]);

/** Executable-ish extensions under the package (capability scan). */
const EXEC_EXT = new Set([".js", ".mjs", ".cjs", ".json"]);

/** Docs extensions — skip capability word search except exact secret patterns. */
const DOC_EXT = new Set([".md"]);

/**
 * Exact shipped surfaces that may import child_process.
 * Prefix exemption for dist/harness/ is intentionally NOT used.
 * Spawned executables are restricted to CHILD_PROCESS_EXECUTABLE_ALLOWLIST.
 * Shell-interpreter execution is still rejected even on these files.
 */
const CHILD_PROCESS_ALLOWLIST = Object.freeze([
  "dist/harness/scenario.js",
  "dist/harness/macos-scenario.js",
  "dist/mcp/client.js",
]);

/**
 * Fixed executable allowlist for spawn/execFile first-argument string literals
 * on child_process surfaces currently shipped by the harness/MCP package.
 * process.execPath is also accepted (Node binary for in-process CLI/MCP).
 * Shell interpreters and arbitrary binaries are rejected.
 */
const CHILD_PROCESS_EXECUTABLE_ALLOWLIST = Object.freeze([
  "node",
  "npm",
  "git",
]);

/** Network module names (bare and node: prefixed). */
const NETWORK_MODULES =
  "http|https|http2|net|tls|dns|dgram|undici|websocket|ws";

/**
 * @param {string} repoRoot
 * @param {{
 *   packageDir?: string,
 *   plant?: { rel: string, content: string } | null,
 *   readFileUtf8?: (abs: string) => string,
 * }} [opts]
 */
export function checkPackageAudit(repoRoot, opts = {}) {
  const canonicalPackageDir =
    opts.packageDir ?? path.join(repoRoot, "release", "codex-changeguard-plugin");
  /** @type {string[]} */
  const errors = [];
  /** Optional read override for fail-closed unreadable self-tests only. */
  const readFileUtf8 =
    opts.readFileUtf8 ?? ((abs) => fs.readFileSync(abs, "utf8"));

  if (!fs.existsSync(canonicalPackageDir) || !fs.statSync(canonicalPackageDir).isDirectory()) {
    return {
      ok: false,
      reason_code: "GATE_PACKAGE_AUDIT",
      errors: ["package_missing"],
      detail: "package_audit_failed",
    };
  }

  // Plant negatives always use an isolated temp copy — never poison release/.
  let packageDir = canonicalPackageDir;
  /** @type {string | null} */
  let tempRoot = null;
  if (opts.plant && opts.plant.rel) {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "cg-t16-pkg-audit-"));
    const isolated = path.join(tempRoot, "codex-changeguard-plugin");
    const copyResult = copyTreeStrict(canonicalPackageDir, isolated);
    if (!copyResult.ok) {
      cleanupTemp(tempRoot);
      return {
        ok: false,
        reason_code: "GATE_PACKAGE_AUDIT",
        errors: copyResult.errors,
        detail: "package_audit_failed",
      };
    }
    packageDir = isolated;
    const plantedPath = path.join(packageDir, opts.plant.rel);
    // Path-safety: plant must stay inside the isolated package dir
    const resolvedPlant = path.resolve(plantedPath);
    const resolvedPkg = path.resolve(packageDir);
    if (!resolvedPlant.startsWith(resolvedPkg + path.sep) && resolvedPlant !== resolvedPkg) {
      cleanupTemp(tempRoot);
      return {
        ok: false,
        reason_code: "GATE_PACKAGE_AUDIT",
        errors: ["plant_path_escape"],
        detail: "package_audit_failed",
      };
    }
    fs.mkdirSync(path.dirname(plantedPath), { recursive: true });
    fs.writeFileSync(plantedPath, opts.plant.content, "utf8");
  }

  try {
    const top = fs.readdirSync(packageDir).sort();
    const allowed = new Set(PACKAGE_TOP_LEVEL_ALLOWLIST);
    for (const name of top) {
      if (!allowed.has(name)) {
        errors.push(`top_level_unexpected:${name}`);
      }
      if (name.startsWith(".grok") || name.includes("grok-worker") || name.includes("grok-disposable")) {
        errors.push(`clone_path:${name}`);
      }
    }
    for (const name of PACKAGE_TOP_LEVEL_ALLOWLIST) {
      if (!top.includes(name)) {
        // fixtures/docs may exist; require core surface
        if (["bin", "dist", "package.json", ".mcp.json", "schemas"].includes(name) && !top.includes(name)) {
          errors.push(`top_level_missing:${name}`);
        }
      }
    }
    // exact set equality for top-level
    if (JSON.stringify(top) !== JSON.stringify([...PACKAGE_TOP_LEVEL_ALLOWLIST].sort())) {
      errors.push("top_level_drift");
    }

    walk(packageDir, "", (rel, abs, ent) => {
      // Symlinks in the package tree are refused (not silently skipped).
      if (ent.isSymbolicLink()) {
        errors.push(`package_symlink:${rel}`);
        return;
      }
      for (const forbidden of PACKAGE_FORBIDDEN_PATHS) {
        if (rel === forbidden || rel.startsWith(`${forbidden}/`)) {
          errors.push(`forbidden_path:${rel}`);
        }
      }
      if (ent.isFile()) {
        auditFile(rel, abs, errors, readFileUtf8);
      }
    });

    if (fs.existsSync(path.join(packageDir, "node_modules"))) {
      errors.push("node_modules_present");
    }

    // package.json scripts must not install deps dynamically
    const pkgJsonPath = path.join(packageDir, "package.json");
    if (fs.existsSync(pkgJsonPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8"));
      const scripts = pkg.scripts ?? {};
      for (const [k, v] of Object.entries(scripts)) {
        const s = String(v);
        if (isDynamicInstallText(s)) {
          errors.push(`dynamic_install_script:${k}`);
        }
      }
      if (pkg.dependencies && Object.keys(pkg.dependencies).length > 0) {
        // production package should be self-contained JS without runtime deps
        errors.push("runtime_dependencies_present");
      }
    }

    // .mcp.json — node only, no shell
    const mcpPath = path.join(packageDir, ".mcp.json");
    if (fs.existsSync(mcpPath)) {
      const mcp = JSON.parse(fs.readFileSync(mcpPath, "utf8"));
      const servers = mcp.mcpServers ?? mcp.servers ?? {};
      for (const [name, cfg] of Object.entries(servers)) {
        const command = String(cfg.command ?? "");
        if (command && command !== "node" && !command.endsWith("/node")) {
          // allow process.execPath patterns only if clearly node
          if (!/node(\.exe)?$/i.test(command)) {
            errors.push(`mcp_non_node_command:${name}`);
          }
        }
        const args = cfg.args ?? [];
        const joined = JSON.stringify(args);
        if (/\bsh\b|\bbash\b|\bcmd\.exe\b|\bpowershell\b/i.test(joined)) {
          errors.push(`mcp_shell_args:${name}`);
        }
      }
    }
  } finally {
    if (tempRoot) {
      cleanupTemp(tempRoot);
    }
  }

  if (errors.length > 0) {
    return {
      ok: false,
      reason_code: "GATE_PACKAGE_AUDIT",
      errors,
      detail: "package_audit_failed",
    };
  }
  return {
    ok: true,
    reason_code: null,
    errors: [],
    detail: "package_audit_ok",
  };
}

/**
 * @param {string} rel
 * @param {string} abs
 * @param {string[]} errors
 * @param {(abs: string) => string} [readFileUtf8]
 */
function auditFile(rel, abs, errors, readFileUtf8 = (p) => fs.readFileSync(p, "utf8")) {
  const ext = path.extname(rel).toLowerCase();
  const base = path.basename(rel).toLowerCase();

  // Secret / private material by filename
  if (
    base.endsWith(".pem") ||
    base.endsWith(".key") ||
    base.endsWith(".p12") ||
    base.endsWith(".pfx") ||
    base === ".env" ||
    base.endsWith(".env") ||
    base.includes("id_rsa") ||
    base.endsWith(".codex-auth")
  ) {
    errors.push(`secret_filename:${rel}`);
  }

  // OpenAI product binary redistribution heuristics (not fixture stub scripts)
  if (
    (ext === "" || ext === ".exe" || ext === ".dll" || ext === ".dylib" || ext === ".so") &&
    !rel.startsWith("fixtures/") &&
    !rel.startsWith("docs/")
  ) {
    const st = fs.statSync(abs);
    if (st.size > 64 * 1024 && isProbablyBinary(abs)) {
      errors.push(`binary_blob:${rel}`);
    }
  }
  // Explicit OpenAI desktop/cli binary names outside fixtures (basename or path segment)
  if (!rel.startsWith("fixtures/")) {
    const baseExact = path.basename(rel);
    if (
      /^(Codex\.exe|codex\.exe|codex-cli(\.exe)?|Codex)$/i.test(baseExact) ||
      /(?:^|\/)Codex\.app(?:\/|$)/i.test(rel)
    ) {
      errors.push(`openai_binary:${rel}`);
    }
  }

  // Skip large binaries for text scan
  const st = fs.statSync(abs);
  if (st.size > 2 * 1024 * 1024) {
    errors.push(`oversized_file:${rel}`);
    return;
  }

  if (DOC_EXT.has(ext)) {
    // Docs: only flag obvious embedded private key blocks / env dumps — not words like "network"
    let text;
    try {
      text = readFileUtf8(abs);
    } catch {
      errors.push(`unreadable_package_file:${rel}`);
      return;
    }
    if (/-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/.test(text)) {
      errors.push(`secret_material_doc:${rel}`);
    }
    if (/cg-t16-planted-secret|AKIA[0-9A-Z]{16}/.test(text)) {
      errors.push(`planted_secret_doc:${rel}`);
    }
    return;
  }

  if (!EXEC_EXT.has(ext) && ext !== ".ts") {
    // non-exec fixtures (json already in EXEC_EXT) — still scan json for secrets
    if (ext === ".sh" || ext === ".ps1" || ext === ".bat") {
      if (!rel.startsWith("fixtures/")) {
        errors.push(`shell_script:${rel}`);
      }
    }
    return;
  }

  let text;
  try {
    text = readFileUtf8(abs);
  } catch {
    // Fail closed: unreadable package files cannot be silently skipped.
    errors.push(`unreadable_package_file:${rel}`);
    return;
  }

  // JSON fixtures under fixtures/ may contain synthetic incident text for
  // redaction/doctor tests; skip capability + live-credential word search.
  // Still flag PEM private keys and explicit package-plant markers.
  if (rel.startsWith("fixtures/") && ext === ".json") {
    if (/-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/.test(text)) {
      errors.push(`secret_material:${rel}`);
    }
    if (/cg-t16-planted-package-secret/.test(text)) {
      errors.push(`planted_secret:${rel}`);
    }
    return;
  }

  // Capability scans on executable JS surfaces (dist/, bin/) and package JSON
  const isExecJs =
    ext === ".js" || ext === ".mjs" || ext === ".cjs" || rel === "bin/changeguard.js";
  const isPackageJsonSurface = ext === ".json" && !rel.startsWith("fixtures/");

  if (isExecJs) {
    // Daemon: setInterval is persistent loop capability; setTimeout alone is not.
    if (/\bsetInterval\s*\(/.test(text)) {
      errors.push(`daemon_setInterval:${rel}`);
    }
    // while(true) with network or sleep patterns in same file (coarse)
    if (/while\s*\(\s*true\s*\)/.test(text) && /\b(fetch|http\.|https\.|net\.|setTimeout)\b/.test(text)) {
      errors.push(`daemon_loop:${rel}`);
    }

    // Hidden network modules — bare and node: prefixed
    if (
      new RegExp(
        String.raw`\bfrom\s+["'](?:node:)?(?:${NETWORK_MODULES})["']`,
      ).test(text) ||
      new RegExp(
        String.raw`\brequire\s*\(\s*["'](?:node:)?(?:${NETWORK_MODULES})["']\s*\)`,
      ).test(text) ||
      new RegExp(
        String.raw`\bimport\s*\(\s*["'](?:node:)?(?:${NETWORK_MODULES})["']\s*\)`,
      ).test(text)
    ) {
      errors.push(`network_module:${rel}`);
    }

    // Global / browser network capabilities (not method names on transport objects)
    if (hasGlobalNetworkCapability(text)) {
      errors.push(`network_global:${rel}`);
    }

    // Telemetry hosts / analytics (capability URLs in code, not docs)
    if (
      /https?:\/\/(?:www\.)?(?:google-analytics|segment\.io|api\.segment|sentry\.io|telemetry\.)/i.test(
        text,
      ) ||
      /\btelemetry\.(track|emit|capture)\s*\(/.test(text)
    ) {
      errors.push(`telemetry:${rel}`);
    }

    // Dynamic dependency install in executable code
    if (isDynamicInstallText(text)) {
      errors.push(`dynamic_install:${rel}`);
    }

    // Arbitrary shell capability via child_process import (bare + node:).
    const hasChildProcessImport =
      /\bfrom\s+["'](?:node:)?child_process["']/.test(text) ||
      /\brequire\s*\(\s*["'](?:node:)?child_process["']\s*\)/.test(text) ||
      /\bimport\s*\(\s*["'](?:node:)?child_process["']\s*\)/.test(text);

    if (hasChildProcessImport) {
      if (!isAllowlistedChildProcessSurface(rel)) {
        errors.push(`shell_child_process:${rel}`);
      } else {
        // Allowlisted surfaces: still reject non-allowlisted executables / shells.
        if (hasArbitraryShellInvocation(text)) {
          errors.push(`arbitrary_shell:${rel}`);
        }
        // process.execPath is the preferred Node spawn target; string "node" also ok.
        // Reject spawn of clearly arbitrary tools (curl, python, etc.) already
        // handled by hasArbitraryShellInvocation allowlist.
      }
    } else if (hasArbitraryShellInvocation(text)) {
      // Shell-interpreter / non-allowlisted exec forms without import still fail.
      errors.push(`arbitrary_shell:${rel}`);
    }

    // Dynamic loaders
    if (
      /\bcreateRequire\s*\(/.test(text) ||
      /\bFunction\s*\(\s*["']return/.test(text) ||
      (/\beval\s*\(/.test(text) && !rel.includes("test"))
    ) {
      if (rel.startsWith("dist/") || rel.startsWith("bin/")) {
        errors.push(`dynamic_loader:${rel}`);
      }
    }

    // Planted secret marker
    if (/cg-t16-planted-package-secret/.test(text)) {
      errors.push(`planted_secret:${rel}`);
    }
    if (/-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/.test(text)) {
      errors.push(`secret_material:${rel}`);
    }

    // High-confidence embedded credentials (not redaction regex source)
    if (hasEmbeddedCredential(text, rel)) {
      errors.push(`embedded_credential:${rel}`);
    }
  }

  // package.json and other non-fixture JSON: install scripts + secrets
  if (isPackageJsonSurface) {
    if (isDynamicInstallText(text)) {
      errors.push(`dynamic_install:${rel}`);
    }
    if (/cg-t16-planted-package-secret/.test(text)) {
      errors.push(`planted_secret:${rel}`);
    }
    if (hasEmbeddedCredential(text, rel)) {
      errors.push(`embedded_credential:${rel}`);
    }
    if (/-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/.test(text)) {
      errors.push(`secret_material:${rel}`);
    }
  }
}

/**
 * Detect global network API capability without flagging transport method names
 * like `transport.fetch(request)`, `this.fetch(...)`, or object-method
 * shorthand `fetch(request) { ... }` on OfficialTransport.
 * Bare global `fetch(...)` *calls* are refused — including variable /
 * computed first arguments (not only URL string literals).
 * @param {string} text
 */
function hasGlobalNetworkCapability(text) {
  // globalThis / window / self bound network APIs
  if (
    /\b(?:globalThis|window|self)\s*\.\s*(?:fetch|WebSocket|XMLHttpRequest|EventSource)\b/.test(
      text,
    )
  ) {
    return true;
  }
  // new WebSocket / new XMLHttpRequest / new EventSource
  if (/\bnew\s+(?:WebSocket|XMLHttpRequest|EventSource)\s*\(/.test(text)) {
    return true;
  }
  // Bare global fetch(...) *calls* (any argument form). Method shorthand
  // definitions `fetch(req) {` / `async fetch(req) {` are not calls.
  if (hasBareGlobalFetchCall(text)) {
    return true;
  }
  // Bare WebSocket / XMLHttpRequest / EventSource identifier used as constructor-like call
  if (/\bWebSocket\s*\(/.test(text)) {
    return true;
  }
  if (/\bXMLHttpRequest\s*\(/.test(text)) {
    return true;
  }
  if (/\bEventSource\s*\(/.test(text)) {
    return true;
  }
  return false;
}

/**
 * True when source contains a bare global `fetch(...)` *call* (not a method
 * definition and not a member call like `obj.fetch(...)`).
 * @param {string} text
 */
function hasBareGlobalFetchCall(text) {
  const re = /(?<![\w$.])\bfetch\s*\(/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const openIdx = m.index + m[0].length - 1; // '('
    const closeIdx = skipBalancedParens(text, openIdx);
    if (closeIdx < 0) continue;
    let j = closeIdx + 1;
    while (j < text.length && /\s/.test(text[j])) j++;
    // Optional TS return type on method: ): Promise<Response> {
    if (text[j] === ":") {
      // method-with-return-type definition — skip
      continue;
    }
    if (text[j] === "{") {
      // Object/class method shorthand definition, not a call.
      continue;
    }
    // Otherwise treat as a call (`;`, `,`, `)`, newline expression, etc.)
    return true;
  }
  return false;
}

/**
 * @param {string} text
 * @param {number} openIdx index of '('
 */
function skipBalancedParens(text, openIdx) {
  let depth = 0;
  let i = openIdx;
  let mode = "code";
  while (i < text.length) {
    const c = text[i];
    const n = text[i + 1];
    if (mode === "code") {
      if (c === "/" && n === "/") {
        mode = "line";
        i += 2;
        continue;
      }
      if (c === "/" && n === "*") {
        mode = "block";
        i += 2;
        continue;
      }
      if (c === "'") {
        mode = "s";
        i++;
        continue;
      }
      if (c === '"') {
        mode = "d";
        i++;
        continue;
      }
      if (c === "`") {
        mode = "t";
        i++;
        continue;
      }
      if (c === "(") {
        depth++;
        i++;
        continue;
      }
      if (c === ")") {
        depth--;
        if (depth === 0) return i;
        i++;
        continue;
      }
      i++;
      continue;
    }
    if (mode === "line") {
      if (c === "\n") mode = "code";
      i++;
      continue;
    }
    if (mode === "block") {
      if (c === "*" && n === "/") {
        mode = "code";
        i += 2;
        continue;
      }
      i++;
      continue;
    }
    if (mode === "s" || mode === "d") {
      if (c === "\\") {
        i += 2;
        continue;
      }
      if ((mode === "s" && c === "'") || (mode === "d" && c === '"')) mode = "code";
      i++;
      continue;
    }
    if (mode === "t") {
      if (c === "\\") {
        i += 2;
        continue;
      }
      if (c === "`") mode = "code";
      i++;
      continue;
    }
    i++;
  }
  return -1;
}

/**
 * Dynamic package-manager install capability in executable code or scripts.
 * @param {string} text
 */
function isDynamicInstallText(text) {
  return (
    /\bnpm\s+i(?:nstall)?\b/i.test(text) ||
    /\bnpm\s+i\s+\S+/i.test(text) ||
    /\bpnpm\s+(?:i|install|add)\b/i.test(text) ||
    /\byarn\s+(?:add|install)\b/i.test(text) ||
    /\bbun\s+(?:add|install)\b/i.test(text)
  );
}

/**
 * spawn/exec/execFile forms that invoke a shell interpreter or non-allowlisted
 * executable. Also catches spawn("sh", ...) and shell: true.
 * @param {string} text
 */
function hasArbitraryShellInvocation(text) {
  // execSync/spawnSync/execFileSync/spawn/exec/execFile with shell interpreter first arg
  if (
    /\b(?:spawn|spawnSync|exec|execSync|execFile|execFileSync)\s*\(\s*["'`](?:sh|bash|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)["'`]/i.test(
      text,
    )
  ) {
    return true;
  }
  // shell: true option (arbitrary shell capability)
  if (/\bshell\s*:\s*true\b/.test(text)) {
    return true;
  }
  // exec/execSync with string command that embeds shell -c patterns
  if (
    /\b(?:exec|execSync)\s*\(\s*["'`][^"'`]*(?:\bsh\b|\bbash\b)\s+-c\b/i.test(text)
  ) {
    return true;
  }
  // String-literal first arg to spawn/execFile family must be allowlisted.
  // process.execPath is always accepted (dynamic Node path).
  const spawnLit =
    /\b(?:spawn|spawnSync|execFile|execFileSync)\s*\(\s*["'`]([^"'`]+)["'`]/gi;
  let m;
  while ((m = spawnLit.exec(text)) !== null) {
    const exe = m[1];
    if (!isAllowlistedChildProcessExecutable(exe)) {
      return true;
    }
  }
  // exec/execSync string form — only allow exact allowlisted bare commands
  // (still reject shell metacharacters / multi-word shell lines)
  const execLit = /\b(?:exec|execSync)\s*\(\s*["'`]([^"'`]+)["'`]/gi;
  while ((m = execLit.exec(text)) !== null) {
    const cmd = m[1].trim();
    const first = cmd.split(/\s+/)[0] ?? "";
    if (!isAllowlistedChildProcessExecutable(first)) {
      return true;
    }
    if (/[;&|<>$`]/.test(cmd)) {
      return true;
    }
  }
  return false;
}

/**
 * @param {string} exe
 */
function isAllowlistedChildProcessExecutable(exe) {
  if (!exe) return false;
  // process.execPath appears as identifier, not string — string forms below
  const base = path.basename(exe).toLowerCase().replace(/\.exe$/i, "");
  if (CHILD_PROCESS_EXECUTABLE_ALLOWLIST.includes(base)) return true;
  // Absolute path ending in allowlisted name
  if (CHILD_PROCESS_EXECUTABLE_ALLOWLIST.some((a) => base === a)) return true;
  return false;
}

/**
 * High-confidence embedded credentials in executable/JSON surfaces.
 * Avoids flagging redaction regex *source* that mentions `sk-` as a pattern
 * fragment (character classes, quantifiers) without a concrete live token body.
 * @param {string} text
 * @param {string} rel
 */
function hasEmbeddedCredential(text, rel) {
  // Redaction / pattern-source files: only flag concrete quoted plant tokens,
  // not regex character-class descriptions of credential shapes.
  const isPatternSource =
    rel.includes("redact") ||
    /CREDENTIAL_SHAPES|redactText|\/\\b\(\?:sk/.test(text);

  // OpenAI project keys and long sk-/pk- live-looking tokens (concrete bodies)
  if (/\bsk-proj-[A-Za-z0-9_-]{16,}\b/.test(text)) return true;
  if (/\bsk-live-[A-Za-z0-9_-]{16,}\b/.test(text)) return true;
  // Require a concrete token body of 24+ alnum after sk- (not `{8,}` quantifiers)
  if (/\bsk-[A-Za-z0-9]{24,}\b/.test(text)) return true;
  if (/\bpk-(?:live|test)-[A-Za-z0-9]{16,}\b/.test(text)) return true;
  // AWS access key id shape (concrete AKIA + 16 uppercase/digit)
  if (/\bAKIA[0-9A-Z]{16}\b/.test(text)) return true;
  // Slack tokens with long body
  if (/\bxox[baprs]-[A-Za-z0-9-]{20,}\b/.test(text)) return true;
  // High-confidence GitHub PAT shapes (same family as privacy/redaction):
  // classic ghp_… and fine-grained github_pat_…. Require concrete long bodies
  // so redaction-source character classes / quantifiers do not false-positive.
  if (/\bghp_[A-Za-z0-9]{20,}\b/.test(text)) return true;
  if (/\bgithub_pat_[A-Za-z0-9_]{20,}\b/.test(text)) return true;
  // Other high-confidence GitHub token prefixes (app/user/server/refresh).
  if (/\b(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/.test(text)) return true;

  if (isPatternSource) return false;

  // Quoted assignment of long secret material in non-redaction code
  if (
    /(?:api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["'`][A-Za-z0-9_\-]{20,}["'`]/i.test(
      text,
    )
  ) {
    return true;
  }
  return false;
}

/**
 * Surfaces that may import child_process inside the shipped package tree.
 * Exact known shipped files only — not a dist/harness/ prefix exemption.
 * Shell interpreter execution is still rejected on these files.
 * @param {string} rel
 */
function isAllowlistedChildProcessSurface(rel) {
  return CHILD_PROCESS_ALLOWLIST.includes(rel);
}

function isProbablyBinary(abs) {
  const fd = fs.openSync(abs, "r");
  try {
    const buf = Buffer.alloc(32);
    const n = fs.readSync(fd, buf, 0, 32, 0);
    for (let i = 0; i < n; i++) {
      if (buf[i] === 0) return true;
    }
    return false;
  } finally {
    fs.closeSync(fd);
  }
}

function walk(dir, relBase, onEntry) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = relBase ? `${relBase}/${ent.name}` : ent.name;
    const abs = path.join(dir, ent.name);
    onEntry(rel, abs, ent);
    // Do not follow symlinks into further walk
    if (ent.isDirectory() && !ent.isSymbolicLink()) walk(abs, rel, onEntry);
  }
}

/**
 * Copy package tree for plant isolation. Symlinks fail closed (never skip).
 * @param {string} src
 * @param {string} dest
 * @returns {{ ok: true } | { ok: false, errors: string[] }}
 */
function copyTreeStrict(src, dest) {
  /** @type {string[]} */
  const errors = [];
  fs.mkdirSync(dest, { recursive: true });
  for (const ent of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, ent.name);
    const d = path.join(dest, ent.name);
    if (ent.isSymbolicLink()) {
      errors.push(`package_symlink:${ent.name}`);
      continue;
    }
    if (ent.isDirectory()) {
      const sub = copyTreeStrict(s, d);
      if (!sub.ok) errors.push(...sub.errors);
    } else if (ent.isFile()) {
      fs.copyFileSync(s, d);
    }
  }
  if (errors.length > 0) return { ok: false, errors };
  return { ok: true };
}

/**
 * @param {string} tempRoot
 */
function cleanupTemp(tempRoot) {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    /* best-effort cleanup */
  }
}
