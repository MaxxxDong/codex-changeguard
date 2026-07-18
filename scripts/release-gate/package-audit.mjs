/**
 * Package threat audit (Ticket 16).
 *
 * Inspects the *built* package tree under release/codex-changeguard-plugin.
 * Refuses: daemon loops, hidden network/telemetry, dynamic dependency install,
 * arbitrary shell/loader, OpenAI binary redistribution, secrets/private material,
 * forbidden paths, top-level surface drift.
 *
 * Avoids word-search false positives in public Markdown docs; audits
 * executable/package surfaces by capability + exact allowlists.
 * Normal bounded timers (setTimeout once) are not daemons; setInterval /
 * persistent loop capability is.
 */

import fs from "node:fs";
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
 * @param {string} repoRoot
 * @param {{ packageDir?: string, plant?: { rel: string, content: string } | null }} [opts]
 */
export function checkPackageAudit(repoRoot, opts = {}) {
  const packageDir =
    opts.packageDir ?? path.join(repoRoot, "release", "codex-changeguard-plugin");
  /** @type {string[]} */
  const errors = [];

  if (!fs.existsSync(packageDir) || !fs.statSync(packageDir).isDirectory()) {
    return {
      ok: false,
      reason_code: "GATE_PACKAGE_AUDIT",
      errors: ["package_missing"],
      detail: "package_audit_failed",
    };
  }

  // Optional plant for negative tests
  let plantedPath = null;
  if (opts.plant && opts.plant.rel) {
    plantedPath = path.join(packageDir, opts.plant.rel);
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

    /** @type {string[]} */
    const allRels = [];
    walk(packageDir, "", (rel, abs, ent) => {
      allRels.push(rel);
      for (const forbidden of PACKAGE_FORBIDDEN_PATHS) {
        if (rel === forbidden || rel.startsWith(`${forbidden}/`)) {
          errors.push(`forbidden_path:${rel}`);
        }
      }
      if (ent.isFile()) {
        auditFile(rel, abs, errors);
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
        if (/\bnpm\s+i(nstall)?\b/i.test(s) || /\bpnpm\s+i\b/i.test(s) || /\byarn\s+add\b/i.test(s)) {
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
    if (plantedPath && fs.existsSync(plantedPath)) {
      try {
        fs.unlinkSync(plantedPath);
      } catch {
        /* ignore cleanup */
      }
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
 */
function auditFile(rel, abs, errors) {
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
  // Explicit OpenAI desktop/cli binary names outside fixtures
  if (
    !rel.startsWith("fixtures/") &&
    /(?:^|\/)(?:Codex|codex-cli|Codex\.app)(?:\/|$)/i.test(rel) &&
    (ext === ".exe" || ext === ".dll" || ext === ".dylib" || base === "codex")
  ) {
    errors.push(`openai_binary:${rel}`);
  }

  // Skip large binaries for text scan
  const st = fs.statSync(abs);
  if (st.size > 2 * 1024 * 1024) {
    errors.push(`oversized_file:${rel}`);
    return;
  }

  if (DOC_EXT.has(ext)) {
    // Docs: only flag obvious embedded private key blocks / env dumps — not words like "network"
    const text = fs.readFileSync(abs, "utf8");
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
    text = fs.readFileSync(abs, "utf8");
  } catch {
    return;
  }

  // JSON fixtures under fixtures/ may contain synthetic incident text; skip capability
  // scan for pure fixture data except planted secret markers / real private keys
  if (rel.startsWith("fixtures/") && ext === ".json") {
    if (/-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/.test(text)) {
      errors.push(`secret_material:${rel}`);
    }
    if (/cg-t16-planted-package-secret/.test(text)) {
      errors.push(`planted_secret:${rel}`);
    }
    return;
  }

  // Capability scans on executable JS surfaces (dist/, bin/)
  if (ext === ".js" || ext === ".mjs" || ext === ".cjs" || rel === "bin/changeguard.js") {
    // Daemon: setInterval is persistent loop capability
    if (/\bsetInterval\s*\(/.test(text)) {
      errors.push(`daemon_setInterval:${rel}`);
    }
    // while(true) with network or sleep patterns in same file (coarse)
    if (/while\s*\(\s*true\s*\)/.test(text) && /\b(fetch|http\.|https\.|net\.|setTimeout)\b/.test(text)) {
      errors.push(`daemon_loop:${rel}`);
    }

    // Hidden network modules / globals
    if (
      /\bfrom\s+["']node:(http|https|http2|net|tls|dns|dgram|undici)["']/.test(text) ||
      /\brequire\s*\(\s*["']node:(http|https|http2|net|tls|dns|dgram|undici)["']\s*\)/.test(text) ||
      /\brequire\s*\(\s*["'](http|https|http2|net|tls|dns|dgram|undici)["']\s*\)/.test(text)
    ) {
      errors.push(`network_module:${rel}`);
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

    // Dynamic dependency install
    if (
      /\bnpm\s+install\b/.test(text) ||
      /\bchild_process\b/.test(text) && /\bnpm\b/.test(text) && /\binstall\b/.test(text)
    ) {
      // child_process may appear in scripts outside package; production dist must not
      if (rel.startsWith("dist/") || rel.startsWith("bin/")) {
        if (/\bnpm\s+install\b/.test(text)) {
          errors.push(`dynamic_install:${rel}`);
        }
      }
    }

    // Arbitrary shell
    if (
      /\bfrom\s+["']node:child_process["']/.test(text) ||
      /\brequire\s*\(\s*["']node:child_process["']\s*\)/.test(text) ||
      /\brequire\s*\(\s*["']child_process["']\s*\)/.test(text)
    ) {
      // Production dist must not import child_process
      if (rel.startsWith("dist/")) {
        errors.push(`shell_child_process:${rel}`);
      }
    }
    if (/\b(?:execSync|spawnSync|execFileSync)\s*\(\s*["'`](?:sh|bash|cmd|powershell)/.test(text)) {
      errors.push(`arbitrary_shell:${rel}`);
    }

    // Dynamic loaders
    if (
      /\bcreateRequire\s*\(/.test(text) ||
      /\bFunction\s*\(\s*["']return/.test(text) ||
      (/\beval\s*\(/.test(text) && !rel.includes("test"))
    ) {
      if (rel.startsWith("dist/")) {
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
  }
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
    if (ent.isDirectory()) walk(abs, rel, onEntry);
  }
}
